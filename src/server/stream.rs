use bytes::{Bytes, BytesMut};
use futures::Stream;
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::shaper::{self, DecodedFrame, EncodingType, FrameCipher};

pin_project! {
    pub struct FrameDecoder<S> {
        #[pin]
        inner: S,
        buf: BytesMut,
        scratch: BytesMut,
        json_scratch: Vec<u8>,
        cipher: Option<Arc<dyn FrameCipher>>,
        encoding: EncodingType,
        max_buf_size: usize,
        eos: bool,
    }
}

impl<S> FrameDecoder<S>
where
    S: Stream<Item = io::Result<Bytes>>,
{
    pub fn new(
        inner: S,
        cipher: Option<Arc<dyn FrameCipher>>,
        encoding: EncodingType,
        max_buf_size: usize,
    ) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(max_buf_size),
            scratch: BytesMut::new(),
            json_scratch: Vec::new(),
            cipher,
            encoding,
            max_buf_size,
            eos: false,
        }
    }
}

impl<S> Stream for FrameDecoder<S>
where
    S: Stream<Item = io::Result<Bytes>>,
{
    type Item = io::Result<(u64, Bytes)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            let cipher_ref: Option<&dyn FrameCipher> =
                this.cipher.as_ref().map(|c| c.as_ref() as &dyn FrameCipher);
            match shaper::decode_frame(
                this.buf,
                this.scratch,
                this.json_scratch,
                cipher_ref,
                *this.encoding,
            ) {
                Ok(Some(frame)) => {
                    let (seq, data) = match frame {
                        DecodedFrame::InScratch { seq, start, end } => {
                            let plain = this.scratch.split().freeze();
                            (seq, plain.slice(start..end))
                        }
                        DecodedFrame::Owned { seq, data } => (seq, data),
                    };
                    return Poll::Ready(Some(Ok((seq, data))));
                }
                Ok(None) => {}
                Err(e) => {
                    return Poll::Ready(Some(Err(e)));
                }
            }

            if *this.eos {
                return if this.buf.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trailing data after last frame",
                    ))))
                };
            }

            if this.buf.len() > *this.max_buf_size {
                return Poll::Ready(Some(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame buffer exceeded maximum size",
                ))));
            }

            match this.inner.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    this.buf.extend_from_slice(&chunk);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    *this.eos = true;
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shaper;
    use bytes::Bytes;
    use futures::{StreamExt, stream};

    fn make_frame(data: &[u8], seq: u64) -> Bytes {
        let frame =
            shaper::encode_frame(data, seq, None, 16384, [0, 0], shaper::EncodingType::Binary)
                .unwrap();
        Bytes::from(frame)
    }

    #[tokio::test]
    async fn single_frame_decoded() {
        let frame = make_frame(b"hello", 0);
        let byte_stream = stream::iter(vec![Ok(frame)]);
        let mut decoder =
            FrameDecoder::new(byte_stream, None, shaper::EncodingType::Binary, 18_781);
        let (seq, data) = decoder.next().await.unwrap().unwrap();
        assert_eq!(seq, 0);
        assert_eq!(&data[..], b"hello");
        assert!(decoder.next().await.is_none());
    }

    #[tokio::test]
    async fn partial_then_complete() {
        let frame = make_frame(b"world", 1);
        let split_at = frame.len() / 2;
        let bytes: Vec<io::Result<Bytes>> =
            vec![Ok(frame.slice(0..split_at)), Ok(frame.slice(split_at..))];
        let byte_stream = stream::iter(bytes);
        let mut decoder =
            FrameDecoder::new(byte_stream, None, shaper::EncodingType::Binary, 18_781);
        let (seq, data) = decoder.next().await.unwrap().unwrap();
        assert_eq!(seq, 1);
        assert_eq!(&data[..], b"world");
        assert!(decoder.next().await.is_none());
    }

    #[tokio::test]
    async fn multiple_frames_in_one_chunk() {
        let f0 = make_frame(b"first", 0);
        let f1 = make_frame(b"second", 1);
        let mut combined = BytesMut::new();
        combined.extend_from_slice(&f0);
        combined.extend_from_slice(&f1);
        let byte_stream = stream::iter(vec![Ok(combined.freeze())]);
        let mut decoder =
            FrameDecoder::new(byte_stream, None, shaper::EncodingType::Binary, 18_781);

        let (seq0, d0) = decoder.next().await.unwrap().unwrap();
        assert_eq!(seq0, 0);
        assert_eq!(&d0[..], b"first");

        let (seq1, d1) = decoder.next().await.unwrap().unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(&d1[..], b"second");

        assert!(decoder.next().await.is_none());
    }

    #[tokio::test]
    async fn trailing_data_errors() {
        let byte_stream = stream::iter(vec![Ok(Bytes::from_static(b"abcde"))]);
        let mut decoder =
            FrameDecoder::new(byte_stream, None, shaper::EncodingType::Binary, 18_781);
        let result = decoder.next().await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn empty_stream_yields_none() {
        let byte_stream = stream::iter(vec![]);
        let mut decoder: FrameDecoder<_> =
            FrameDecoder::new(byte_stream, None, shaper::EncodingType::Binary, 18_781);
        assert!(decoder.next().await.is_none());
    }

    #[tokio::test]
    async fn decode_error_propagates() {
        use bytes::BufMut;
        let mut buf = BytesMut::new();
        buf.put_u16(50_000u16);
        buf.resize(2 + 50_000, 0u8);
        let byte_stream = stream::iter(vec![Ok(buf.freeze())]);
        let mut decoder =
            FrameDecoder::new(byte_stream, None, shaper::EncodingType::Binary, 18_781);
        let result = decoder.next().await.unwrap();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn max_buf_size_enforced() {
        use bytes::BufMut;
        let mut chunk = BytesMut::with_capacity(2 + 200);
        chunk.put_u16(1000u16);
        chunk.resize(2 + 200, 0u8);
        let byte_stream = stream::iter(vec![
            Ok(chunk.clone().freeze()),
            Ok(chunk.clone().freeze()),
            Ok(chunk.clone().freeze()),
        ]);
        let mut decoder = FrameDecoder::new(byte_stream, None, shaper::EncodingType::Binary, 512);
        let result = decoder.next().await.unwrap();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("buffer exceeded"), "got: {err_msg}");
    }

    #[tokio::test]
    async fn encrypted_frames_decoded_with_scratch() {
        use crate::crypto::AesFrameCipher;
        use zeroize::Zeroizing;

        let mut key = Zeroizing::new([0u8; 32]);
        rand::Rng::fill_bytes(&mut rand::rng(), &mut *key);
        let cipher = Arc::new(AesFrameCipher::new(&key));

        let frame = shaper::encode_frame(
            b"encrypted hello",
            0,
            Some(cipher.as_ref() as &dyn shaper::FrameCipher),
            16384,
            [0, 0],
            shaper::EncodingType::Binary,
        )
        .unwrap();
        let byte_stream = stream::iter(vec![Ok(Bytes::from(frame))]);
        let mut decoder = FrameDecoder::new(
            byte_stream,
            Some(cipher),
            shaper::EncodingType::Binary,
            18_781,
        );
        let (seq, data) = decoder.next().await.unwrap().unwrap();
        assert_eq!(seq, 0);
        assert_eq!(&data[..], b"encrypted hello");
    }
}
