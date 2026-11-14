use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;

use anyhow::{Result, bail};
use bytes::Bytes;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use super::sys::{self, Ptr};

const READ_CHUNK: usize = 64 * 1024;

static NEXT_KEY: AtomicUsize = AtomicUsize::new(1);

pub(crate) fn next_key() -> usize {
    NEXT_KEY.fetch_add(1, Ordering::Relaxed)
}

pub(crate) enum Event {
    Status(u16),
    Data(Bytes),
    End,
    Fail(String),
}

pub(crate) struct Spec {
    pub(crate) url: String,
    pub(crate) method: &'static str,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Option<Bytes>,
}

enum Command {
    Open {
        key: usize,
        events: UnboundedSender<Event>,
        spec: Spec,
    },
    Resume(usize),
    Close(usize),
    Run(Ptr),
    Stop,
}

struct Slot {
    request: Ptr,
    events: UnboundedSender<Event>,
    upload: Option<(Ptr, Ptr)>,
    reading: bool,
    closed: bool,
}

impl Slot {
    fn fill(&mut self) {
        if self.reading || self.closed {
            return;
        }
        let api = sys::api();
        let buffer = api.buffer_create();
        if buffer.is_null() {
            return;
        }
        api.buffer_alloc(buffer, READ_CHUNK as u64);
        if api.buffer_size(buffer) < READ_CHUNK as u64 {
            api.buffer_destroy(buffer);
            return;
        }
        if api.request_read(self.request, buffer) == sys::RESULT_SUCCESS {
            self.reading = true;
        } else {
            api.buffer_destroy(buffer);
        }
    }
}

struct Upload {
    shared: Arc<Shared>,
    body: Bytes,
    position: usize,
    closed: AtomicBool,
}

struct Chunk {
    buffer: Ptr,
    length: usize,
}

impl AsRef<[u8]> for Chunk {
    fn as_ref(&self) -> &[u8] {
        let data = sys::api().buffer_data(self.buffer).cast::<u8>();
        unsafe { std::slice::from_raw_parts(data, self.length) }
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        sys::api().buffer_destroy(self.buffer);
    }
}

pub(crate) struct Shared {
    commands: UnboundedSender<Command>,
    slots: Mutex<HashMap<usize, Slot>>,
    garbage: Mutex<Vec<(Ptr, Ptr)>>,
}

pub(crate) struct Executor {
    shared: Arc<Shared>,
    object: Ptr,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Executor {
    pub(crate) fn new(engine: Ptr, callback: Ptr) -> Result<Arc<Self>> {
        let api = sys::api();
        let (commands, inbox) = unbounded_channel();
        let shared = Arc::new(Shared {
            commands,
            slots: Mutex::new(HashMap::new()),
            garbage: Mutex::new(Vec::new()),
        });
        let object = api.executor_create(Some(execute));
        if object.is_null() {
            bail!("cronet: executor create failed");
        }
        api.executor_set_context(object, Arc::as_ptr(&shared).cast_mut().cast());
        api.callback_set_context(callback, Arc::as_ptr(&shared).cast_mut().cast());

        let worker = Worker {
            engine,
            callback,
            executor: object,
            shared: Arc::clone(&shared),
        };
        let thread = match std::thread::Builder::new()
            .name("cronet".to_owned())
            .spawn(move || worker.run(inbox))
        {
            Ok(thread) => thread,
            Err(error) => {
                api.executor_destroy(object);
                return Err(error.into());
            }
        };
        Ok(Arc::new(Self {
            shared,
            object,
            thread: Mutex::new(Some(thread)),
        }))
    }

    pub(crate) fn open(&self, key: usize, events: UnboundedSender<Event>, spec: Spec) {
        let _ = self
            .shared
            .commands
            .send(Command::Open { key, events, spec });
    }

    pub(crate) fn resume(&self, key: usize) {
        let _ = self.shared.commands.send(Command::Resume(key));
    }

    pub(crate) fn close(&self, key: usize) {
        let _ = self.shared.commands.send(Command::Close(key));
    }

    pub(crate) fn shutdown(&self) {
        if let Some(thread) = self
            .thread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            let _ = self.shared.commands.send(Command::Stop);
            let _ = thread.join();
        }
    }

    #[cfg(test)]
    pub(crate) fn watch(&self) -> std::sync::Weak<Shared> {
        Arc::downgrade(&self.shared)
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        self.shutdown();
        sys::api().executor_destroy(self.object);
    }
}

struct Worker {
    engine: Ptr,
    callback: Ptr,
    executor: Ptr,
    shared: Arc<Shared>,
}

impl Worker {
    fn run(self, mut inbox: UnboundedReceiver<Command>) {
        while let Some(command) = inbox.blocking_recv() {
            match command {
                Command::Run(runnable) => {
                    let api = sys::api();
                    api.runnable_run(runnable);
                    api.runnable_destroy(runnable);
                }
                Command::Open { key, events, spec } => self.open(key, events, spec),
                Command::Resume(key) => self.resume(key),
                Command::Close(key) => self.close(key),
                Command::Stop => break,
            }
            self.collect();
        }
    }

    fn open(&self, key: usize, events: UnboundedSender<Event>, spec: Spec) {
        let api = sys::api();
        let Ok(url) = CString::new(spec.url) else {
            let _ = events.send(Event::Fail("cronet: invalid url".to_owned()));
            return;
        };
        let method = CString::new(spec.method).unwrap_or_default();

        let params = api.params_create();
        if params.is_null() {
            let _ = events.send(Event::Fail("cronet: params create failed".to_owned()));
            return;
        }

        api.params_method(params, method.as_ptr());
        api.params_no_cache(params, true);
        for (name, value) in &spec.headers {
            let (Ok(name), Ok(value)) = (CString::new(name.as_str()), CString::new(value.as_str()))
            else {
                continue;
            };
            let header = api.header_create();
            if header.is_null() {
                continue;
            }
            api.header_name(header, name.as_ptr());
            api.header_value(header, value.as_ptr());
            api.params_header_add(params, header);
            api.header_destroy(header);
        }

        let mut upload = None;
        if let Some(body) = spec.body.filter(|body| !body.is_empty()) {
            let owned = Box::into_raw(Box::new(Upload {
                shared: Arc::clone(&self.shared),
                body,
                position: 0,
                closed: AtomicBool::new(false),
            }));
            let provider = api.upload_create(
                Some(upload_length),
                Some(upload_read),
                Some(upload_rewind),
                Some(upload_close),
            );
            if provider.is_null() {
                unsafe { drop(Box::from_raw(owned)) };
                api.params_destroy(params);
                let _ = events.send(Event::Fail(
                    "cronet: upload provider create failed".to_owned(),
                ));
                return;
            }
            let data = Ptr::new(owned.cast());
            api.upload_set_context(provider, owned.cast());
            api.params_upload(params, provider);
            api.params_upload_executor(params, self.executor);
            upload = Some((provider, data));
        }

        let request = api.request_create();
        if request.is_null() {
            api.params_destroy(params);
            if let Some((provider, data)) = upload {
                reclaim(&self.shared, provider, data);
            }
            let _ = events.send(Event::Fail("cronet: request create failed".to_owned()));
            return;
        }

        api.request_set_context(request, key as *mut _);
        self.shared
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                key,
                Slot {
                    request,
                    events,
                    upload,
                    reading: false,
                    closed: false,
                },
            );

        let result = api.request_init(
            request,
            self.engine,
            url.as_ptr(),
            params,
            self.callback,
            self.executor,
        );
        api.params_destroy(params);

        if result != sys::RESULT_SUCCESS {
            let upload = finish(
                &self.shared,
                key,
                Event::Fail(format!("cronet: init failed ({result})")),
            );
            if let Some((provider, data)) = upload {
                reclaim(&self.shared, provider, data);
            }
            return;
        }

        let result = api.request_start(request);
        if result != sys::RESULT_SUCCESS {
            let upload = finish(
                &self.shared,
                key,
                Event::Fail(format!("cronet: start failed ({result})")),
            );
            if let Some((provider, data)) = upload {
                reclaim(&self.shared, provider, data);
            }
        }
    }

    fn resume(&self, key: usize) {
        if let Some(slot) = self
            .shared
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&key)
        {
            slot.fill();
        }
    }

    fn close(&self, key: usize) {
        if let Some(slot) = self
            .shared
            .slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&key)
        {
            slot.closed = true;
            sys::api().request_cancel(slot.request);
        }
    }

    fn collect(&self) {
        let api = sys::api();
        let mut garbage = self
            .shared
            .garbage
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for (provider, upload) in garbage.drain(..) {
            api.upload_destroy(provider);
            unsafe { drop(Box::from_raw(upload.raw().cast::<Upload>())) };
        }
    }
}

fn reclaim(shared: &Shared, provider: Ptr, data: Ptr) {
    let upload = unsafe { &*data.raw().cast::<Upload>() };
    if upload.closed.swap(true, Ordering::AcqRel) {
        return;
    }
    shared
        .garbage
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((provider, data));
}

fn finish(shared: &Shared, key: usize, event: Event) -> Option<(Ptr, Ptr)> {
    let slot = shared
        .slots
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(&key)?;
    sys::api().request_destroy(slot.request);
    let _ = slot.events.send(event);
    slot.upload
}

fn shared_of(callback: Ptr) -> Option<&'static Shared> {
    let raw = sys::api().callback_get_context(callback);
    (!raw.is_null()).then(|| unsafe { &*raw.cast::<Shared>() })
}

fn key_of(request: Ptr) -> usize {
    sys::api().request_get_context(request) as usize
}

pub(crate) unsafe extern "C" fn on_redirect(
    _callback: Ptr,
    request: Ptr,
    _info: Ptr,
    _location: sys::CronetString,
) {
    sys::api().request_follow_redirect(request);
}

pub(crate) unsafe extern "C" fn on_response_started(callback: Ptr, request: Ptr, info: Ptr) {
    let Some(shared) = shared_of(callback) else {
        return;
    };
    let status = sys::api().response_status(info);
    let key = key_of(request);
    let mut slots = shared.slots.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(slot) = slots.get_mut(&key) {
        slot.fill();
        let _ = slot
            .events
            .send(Event::Status(status.clamp(0, u16::MAX as i32) as u16));
    }
}

pub(crate) unsafe extern "C" fn on_read_completed(
    callback: Ptr,
    request: Ptr,
    _info: Ptr,
    buffer: Ptr,
    bytes: u64,
) {
    let api = sys::api();
    let chunk = if bytes > 0 {
        let length = (bytes as usize).min(api.buffer_size(buffer) as usize);
        Some(Bytes::from_owner(Chunk { buffer, length }))
    } else {
        api.buffer_destroy(buffer);
        None
    };

    let Some(shared) = shared_of(callback) else {
        return;
    };
    let key = key_of(request);
    let mut slots = shared.slots.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(slot) = slots.get_mut(&key) {
        slot.reading = false;
        if let Some(chunk) = chunk {
            let _ = slot.events.send(Event::Data(chunk));
        }
    }
}

pub(crate) unsafe extern "C" fn on_succeeded(callback: Ptr, request: Ptr, _info: Ptr) {
    if let Some(shared) = shared_of(callback) {
        let _ = finish(shared, key_of(request), Event::End);
    }
}

pub(crate) unsafe extern "C" fn on_canceled(callback: Ptr, request: Ptr, _info: Ptr) {
    if let Some(shared) = shared_of(callback) {
        let _ = finish(shared, key_of(request), Event::End);
    }
}

pub(crate) unsafe extern "C" fn on_failed(callback: Ptr, request: Ptr, _info: Ptr, error: Ptr) {
    let Some(shared) = shared_of(callback) else {
        return;
    };
    let message = if error.is_null() {
        None
    } else {
        let raw = sys::api().error_message(error);
        (!raw.is_null()).then(|| {
            unsafe { CStr::from_ptr(raw) }
                .to_string_lossy()
                .into_owned()
        })
    };
    let message = message.unwrap_or_else(|| "cronet: request failed".to_owned());
    let _ = finish(shared, key_of(request), Event::Fail(message));
}

unsafe extern "C" fn execute(object: Ptr, runnable: Ptr) {
    let api = sys::api();
    let context = api.executor_get_context(object);
    if context.is_null() {
        api.runnable_destroy(runnable);
        return;
    }
    let shared = unsafe { &*context.cast::<Shared>() };
    if shared.commands.send(Command::Run(runnable)).is_err() {
        api.runnable_destroy(runnable);
    }
}

fn upload_of(provider: Ptr) -> Option<&'static mut Upload> {
    let raw = sys::api().upload_get_context(provider);
    (!raw.is_null()).then(|| unsafe { &mut *raw.cast::<Upload>() })
}

unsafe extern "C" fn upload_length(provider: Ptr) -> i64 {
    upload_of(provider).map_or(0, |upload| upload.body.len() as i64)
}

unsafe extern "C" fn upload_read(provider: Ptr, sink: Ptr, buffer: Ptr) {
    let api = sys::api();
    let Some(upload) = upload_of(provider) else {
        api.sink_read_error(sink, c"cronet: upload lost".as_ptr());
        return;
    };
    let capacity = api.buffer_size(buffer) as usize;
    let pending = &upload.body[upload.position..];
    let length = capacity.min(pending.len());
    if length > 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(
                pending.as_ptr(),
                api.buffer_data(buffer).cast::<u8>(),
                length,
            );
        }
        upload.position += length;
    }
    api.sink_read_ok(sink, length as u64, false);
}

unsafe extern "C" fn upload_rewind(provider: Ptr, sink: Ptr) {
    if let Some(upload) = upload_of(provider) {
        upload.position = 0;
    }
    sys::api().sink_rewind_ok(sink);
}

unsafe extern "C" fn upload_close(provider: Ptr) {
    let raw = sys::api().upload_get_context(provider);
    if raw.is_null() {
        return;
    }
    let upload = unsafe { &*raw.cast::<Upload>() };
    if upload.closed.swap(true, Ordering::AcqRel) {
        return;
    }
    upload
        .shared
        .garbage
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((provider, Ptr::new(raw)));
}
