#[cfg(not(cronet_static))]
use std::ffi::{CString, OsString};
use std::ffi::{c_char, c_void};
use std::sync::OnceLock;

#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ptr(usize);

impl Ptr {
    pub(crate) fn new(raw: *mut c_void) -> Self {
        Self(raw as usize)
    }

    pub(crate) fn raw(self) -> *mut c_void {
        self.0 as *mut c_void
    }

    pub(crate) fn is_null(self) -> bool {
        self.0 == 0
    }
}

pub(crate) const RESULT_SUCCESS: i32 = 0;
pub(crate) const HTTP_CACHE_DISABLED: i32 = 0;

pub(crate) type CronetString = *const c_char;

pub(crate) type OnRedirectReceived = unsafe extern "C" fn(Ptr, Ptr, Ptr, CronetString);
pub(crate) type OnResponseStarted = unsafe extern "C" fn(Ptr, Ptr, Ptr);
pub(crate) type OnReadCompleted = unsafe extern "C" fn(Ptr, Ptr, Ptr, Ptr, u64);
pub(crate) type OnSucceeded = unsafe extern "C" fn(Ptr, Ptr, Ptr);
pub(crate) type OnFailed = unsafe extern "C" fn(Ptr, Ptr, Ptr, Ptr);
pub(crate) type OnCanceled = unsafe extern "C" fn(Ptr, Ptr, Ptr);
pub(crate) type OnExecute = unsafe extern "C" fn(Ptr, Ptr);
pub(crate) type UploadLength = unsafe extern "C" fn(Ptr) -> i64;
pub(crate) type UploadRead = unsafe extern "C" fn(Ptr, Ptr, Ptr);
pub(crate) type UploadRewind = unsafe extern "C" fn(Ptr, Ptr);
pub(crate) type UploadClose = unsafe extern "C" fn(Ptr);

macro_rules! api {
    ($($field:ident: $symbol:ident($($arg:ident: $arg_ty:ty),* $(,)?) $(-> $ret:ty)?;)*) => {
        #[cfg(cronet_static)]
        #[allow(non_snake_case)]
        mod symbols {
            use super::*;

            unsafe extern "C" {
                $(pub(super) fn $symbol($($arg: $arg_ty),*) $(-> $ret)?;)*
            }
        }

        pub(crate) struct Api {
            $($field: unsafe extern "C" fn($($arg_ty),*) $(-> $ret)?,)*
        }

        impl Api {
            #[cfg(cronet_static)]
            fn bind() -> Result<Self, String> {
                Ok(Self {
                    $($field: symbols::$symbol
                        as unsafe extern "C" fn($($arg_ty),*) $(-> $ret)?,)*
                })
            }

            #[cfg(not(cronet_static))]
            fn bind() -> Result<Self, String> {
                let library = Library::open()?;
                Ok(Self { $($field: unsafe { library.symbol(stringify!($symbol))? },)* })
            }

            $(
                #[inline]
                pub(crate) fn $field(&self $(, $arg: $arg_ty)*) $(-> $ret)? {
                    unsafe { (self.$field)($($arg),*) }
                }
            )*
        }
    };
}

api! {
    engine_create: Cronet_Engine_Create() -> Ptr;
    engine_destroy: Cronet_Engine_Destroy(engine: Ptr);
    engine_start: Cronet_Engine_StartWithParams(engine: Ptr, params: Ptr) -> i32;
    engine_shutdown: Cronet_Engine_Shutdown(engine: Ptr) -> i32;
    engine_version: Cronet_Engine_GetVersionString(engine: Ptr) -> CronetString;
    engine_params_create: Cronet_EngineParams_Create() -> Ptr;
    engine_params_destroy: Cronet_EngineParams_Destroy(params: Ptr);
    engine_params_user_agent: Cronet_EngineParams_user_agent_set(params: Ptr, agent: CronetString);
    engine_params_quic: Cronet_EngineParams_enable_quic_set(params: Ptr, enable: bool);
    engine_params_http2: Cronet_EngineParams_enable_http2_set(params: Ptr, enable: bool);
    engine_params_brotli: Cronet_EngineParams_enable_brotli_set(params: Ptr, enable: bool);
    engine_params_cache_mode: Cronet_EngineParams_http_cache_mode_set(params: Ptr, mode: i32);
    engine_params_experimental: Cronet_EngineParams_experimental_options_set(
        params: Ptr,
        options: CronetString,
    );
    request_create: Cronet_UrlRequest_Create() -> Ptr;
    request_destroy: Cronet_UrlRequest_Destroy(request: Ptr);
    request_set_context: Cronet_UrlRequest_SetClientContext(request: Ptr, context: *mut c_void);
    request_get_context: Cronet_UrlRequest_GetClientContext(request: Ptr) -> *mut c_void;
    request_init: Cronet_UrlRequest_InitWithParams(
        request: Ptr,
        engine: Ptr,
        url: CronetString,
        params: Ptr,
        callback: Ptr,
        executor: Ptr,
    ) -> i32;
    request_start: Cronet_UrlRequest_Start(request: Ptr) -> i32;
    request_follow_redirect: Cronet_UrlRequest_FollowRedirect(request: Ptr) -> i32;
    request_read: Cronet_UrlRequest_Read(request: Ptr, buffer: Ptr) -> i32;
    request_cancel: Cronet_UrlRequest_Cancel(request: Ptr);
    params_create: Cronet_UrlRequestParams_Create() -> Ptr;
    params_destroy: Cronet_UrlRequestParams_Destroy(params: Ptr);
    params_method: Cronet_UrlRequestParams_http_method_set(params: Ptr, method: CronetString);
    params_header_add: Cronet_UrlRequestParams_request_headers_add(params: Ptr, header: Ptr);
    params_no_cache: Cronet_UrlRequestParams_disable_cache_set(params: Ptr, disable: bool);
    params_upload: Cronet_UrlRequestParams_upload_data_provider_set(params: Ptr, provider: Ptr);
    params_upload_executor: Cronet_UrlRequestParams_upload_data_provider_executor_set(
        params: Ptr,
        executor: Ptr,
    );
    callback_create: Cronet_UrlRequestCallback_CreateWith(
        redirect: Option<OnRedirectReceived>,
        started: Option<OnResponseStarted>,
        read: Option<OnReadCompleted>,
        succeeded: Option<OnSucceeded>,
        failed: Option<OnFailed>,
        canceled: Option<OnCanceled>,
    ) -> Ptr;
    callback_destroy: Cronet_UrlRequestCallback_Destroy(callback: Ptr);
    callback_set_context: Cronet_UrlRequestCallback_SetClientContext(
        callback: Ptr,
        context: *mut c_void,
    );
    callback_get_context: Cronet_UrlRequestCallback_GetClientContext(callback: Ptr) -> *mut c_void;
    response_status: Cronet_UrlResponseInfo_http_status_code_get(info: Ptr) -> i32;
    error_message: Cronet_Error_message_get(error: Ptr) -> CronetString;
    buffer_create: Cronet_Buffer_Create() -> Ptr;
    buffer_destroy: Cronet_Buffer_Destroy(buffer: Ptr);
    buffer_alloc: Cronet_Buffer_InitWithAlloc(buffer: Ptr, size: u64);
    buffer_data: Cronet_Buffer_GetData(buffer: Ptr) -> *mut c_void;
    buffer_size: Cronet_Buffer_GetSize(buffer: Ptr) -> u64;
    upload_create: Cronet_UploadDataProvider_CreateWith(
        length: Option<UploadLength>,
        read: Option<UploadRead>,
        rewind: Option<UploadRewind>,
        close: Option<UploadClose>,
    ) -> Ptr;
    upload_destroy: Cronet_UploadDataProvider_Destroy(provider: Ptr);
    upload_set_context: Cronet_UploadDataProvider_SetClientContext(
        provider: Ptr,
        context: *mut c_void,
    );
    upload_get_context: Cronet_UploadDataProvider_GetClientContext(provider: Ptr) -> *mut c_void;
    sink_read_ok: Cronet_UploadDataSink_OnReadSucceeded(sink: Ptr, bytes: u64, last: bool);
    sink_read_error: Cronet_UploadDataSink_OnReadError(sink: Ptr, message: CronetString);
    sink_rewind_ok: Cronet_UploadDataSink_OnRewindSucceeded(sink: Ptr);
    executor_create: Cronet_Executor_CreateWith(execute: Option<OnExecute>) -> Ptr;
    executor_destroy: Cronet_Executor_Destroy(executor: Ptr);
    executor_set_context: Cronet_Executor_SetClientContext(executor: Ptr, context: *mut c_void);
    executor_get_context: Cronet_Executor_GetClientContext(executor: Ptr) -> *mut c_void;
    runnable_run: Cronet_Runnable_Run(runnable: Ptr);
    runnable_destroy: Cronet_Runnable_Destroy(runnable: Ptr);
    header_create: Cronet_HttpHeader_Create() -> Ptr;
    header_destroy: Cronet_HttpHeader_Destroy(header: Ptr);
    header_name: Cronet_HttpHeader_name_set(header: Ptr, name: CronetString);
    header_value: Cronet_HttpHeader_value_set(header: Ptr, value: CronetString);
}

static API: OnceLock<Result<Api, String>> = OnceLock::new();

pub(crate) fn load() -> Result<(), String> {
    match API.get_or_init(Api::bind) {
        Ok(_) => Ok(()),
        Err(error) => Err(error.clone()),
    }
}

pub(crate) fn api() -> &'static Api {
    match API.get_or_init(Api::bind) {
        Ok(api) => api,
        Err(error) => panic!("libcronet unavailable: {error}"),
    }
}

#[cfg(not(cronet_static))]
struct Library {
    handle: *mut c_void,
}

#[cfg(not(cronet_static))]
impl Library {
    fn open() -> Result<Self, String> {
        let mut tried = Vec::new();
        for candidate in candidates() {
            let Some(handle) = platform::open(candidate.as_os_str()) else {
                tried.push(candidate.to_string_lossy().into_owned());
                continue;
            };
            return Ok(Self { handle });
        }
        Err(format!("libcronet not found, tried: {}", tried.join(", ")))
    }

    unsafe fn symbol<T: Copy>(&self, name: &str) -> Result<T, String> {
        let name = CString::new(name).map_err(|_| "invalid symbol name".to_owned())?;
        let raw = platform::symbol(self.handle, &name)
            .ok_or_else(|| format!("missing symbol {}", name.to_string_lossy()))?;
        Ok(unsafe { std::mem::transmute_copy(&raw) })
    }
}

#[cfg(not(cronet_static))]
const LIBRARY_NAMES: &[&str] = if cfg!(windows) {
    &["libcronet.dll", "cronet.dll"]
} else if cfg!(target_os = "macos") {
    &["libcronet.dylib"]
} else {
    &["libcronet.so", "libcronet.so.1"]
};

#[cfg(not(cronet_static))]
fn candidates() -> Vec<OsString> {
    let mut paths = Vec::new();
    if let Some(explicit) = std::env::var_os("CRONET_LIB") {
        paths.push(explicit);
    }
    if let Ok(executable) = std::env::current_exe()
        && let Some(directory) = executable.parent()
    {
        paths.extend(
            LIBRARY_NAMES
                .iter()
                .map(|name| directory.join(name).into_os_string()),
        );
    }
    paths.extend(LIBRARY_NAMES.iter().map(OsString::from));
    paths
}

#[cfg(all(windows, not(cronet_static)))]
mod platform {
    use std::ffi::{CStr, OsStr, c_char, c_void};
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryW(name: *const u16) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    }

    pub(super) fn open(path: &OsStr) -> Option<*mut c_void> {
        let wide: Vec<u16> = path.encode_wide().chain([0]).collect();
        let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
        (!handle.is_null()).then_some(handle)
    }

    pub(super) fn symbol(handle: *mut c_void, name: &CStr) -> Option<*mut c_void> {
        let address = unsafe { GetProcAddress(handle, name.as_ptr()) };
        (!address.is_null()).then_some(address)
    }
}

#[cfg(all(unix, not(cronet_static)))]
mod platform {
    use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;

    const RTLD_NOW: c_int = 2;
    #[cfg(target_os = "macos")]
    const RTLD_LOCAL: c_int = 4;
    #[cfg(not(target_os = "macos"))]
    const RTLD_LOCAL: c_int = 0;

    #[cfg_attr(all(target_os = "linux", target_env = "gnu"), link(name = "dl"))]
    unsafe extern "C" {
        fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
        fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    }

    pub(super) fn open(path: &OsStr) -> Option<*mut c_void> {
        let path = std::ffi::CString::new(path.as_bytes()).ok()?;
        let handle = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        (!handle.is_null()).then_some(handle)
    }

    pub(super) fn symbol(handle: *mut c_void, name: &CStr) -> Option<*mut c_void> {
        let address = unsafe { dlsym(handle, name.as_ptr()) };
        (!address.is_null()).then_some(address)
    }
}
