// Do we really need `unsafe` on FFI functions? I don't think :)
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::{
    cell::RefCell,
    ffi::{c_char, c_int, c_void, CStr},
    fmt::Display,
    ptr::null,
    slice,
    sync::Arc,
};

use bpf_loader_lib::{
    export_event::{EventHandler, ExportFormatType},
    meta::{arg_parser::UnpresentVariableAction, ComposedObject, EunomiaObjectMeta},
    skeleton::builder::BpfSkeletonBuilder,
};
use helper::{convert_args, load_null_ptr_to_option_string, load_object};
use wrapper::{HandleWrapper, SkeletonWrapper};

mod helper;
mod wrapper;
thread_local! {
    static ERROR_MESSAGE: RefCell<String> = RefCell::new(String::default());
}
fn set_error_message(t: impl Display) {
    ERROR_MESSAGE.with(|v| v.replace(t.to_string()));
}

#[macro_export]
macro_rules! my_bail_custom {
    ($msg: expr, $ret: expr) => {{
        set_error_message($msg);
        return $ret;
    }};
}

macro_rules! my_bail {
    ($msg: expr) => {{
        $crate::my_bail_custom!($msg, std::ptr::null_mut());
    }};
}

#[no_mangle]
/// create a new eunomia bpf program from a json file
pub extern "C" fn open_eunomia_skel_from_json(
    json_data: *const c_char,
    bpf_object_buffer: *const c_void,
    object_size: usize,
    btf_archive_path: *const c_char,
) -> *mut SkeletonWrapper {
    let object_buffer =
        unsafe { std::slice::from_raw_parts(bpf_object_buffer as *const u8, object_size) };
    let btf_archive_path = match load_null_ptr_to_option_string(btf_archive_path) {
        Ok(v) => v,
        Err(e) => my_bail!(e),
    };
    let meta = match load_object::<EunomiaObjectMeta>(json_data) {
        Err(e) => my_bail!(e),
        Ok(v) => v,
    };
    let skel = match BpfSkeletonBuilder::from_object_meta_and_object_buffer(
        &meta,
        object_buffer,
        btf_archive_path,
    )
    .build()
    {
        Err(e) => my_bail!(format!("Failed to build: {}", e)),
        Ok(s) => s,
    };
    let ret = Box::leak(Box::new(SkeletonWrapper::PreLoad(skel)));
    ret as *mut SkeletonWrapper
}

#[no_mangle]
/// create a new eunomia bpf program from a json file
pub extern "C" fn open_eunomia_skel_from_json_package(
    json_data: *const c_char,
) -> *mut SkeletonWrapper {
    open_eunomia_skel_from_json_package_with_btf(json_data, null())
}

#[no_mangle]
/// create a new eunomia bpf program from a json with btf archive
pub extern "C" fn open_eunomia_skel_from_json_package_with_btf(
    json_data: *const c_char,
    btf_archive_path: *const c_char,
) -> *mut SkeletonWrapper {
    let package = match load_object::<ComposedObject>(json_data) {
        Err(e) => my_bail!(e),
        Ok(v) => v,
    };
    let btf_archive_path = match load_null_ptr_to_option_string(btf_archive_path) {
        Ok(v) => v,
        Err(e) => my_bail!(e),
    };

    let skel = match BpfSkeletonBuilder::from_json_package(&package, btf_archive_path).build() {
        Err(e) => my_bail!(format!("Failed to build: {}", e)),
        Ok(s) => s,
    };
    let ret = Box::leak(Box::new(SkeletonWrapper::PreLoad(skel)));
    ret as *mut SkeletonWrapper
}

#[no_mangle]
/// create a new eunomia bpf program from a json with args
pub extern "C" fn open_eunomia_skel_from_json_package_with_args(
    json_data: *const c_char,
    args: *const *const c_char,
    argc: c_int,
    btf_archive_path: *const c_char,
) -> *const SkeletonWrapper {
    let args = match unsafe { convert_args(slice::from_raw_parts(args, argc as usize)) } {
        Err(e) => my_bail!(e),
        Ok(v) => v,
    };
    let mut package = match load_object::<ComposedObject>(json_data) {
        Err(e) => my_bail!(e),
        Ok(v) => v,
    };
    let parser = match package.meta.build_argument_parser() {
        Ok(v) => v,
        Err(e) => my_bail!(format!(
            "Failed to build command parser for the skeleton: {}",
            e
        )),
    };
    let matches = match parser.try_get_matches_from(args) {
        Ok(v) => v,
        Err(e) => my_bail!(e),
    };
    if let Err(e) = package.meta.parse_arguments_and_fill_skeleton_variables(
        &matches,
        UnpresentVariableAction::FillWithZero,
    ) {
        my_bail!(format!("Failed to parse arguments: {}", e))
    }
    let btf_archive_path = match load_null_ptr_to_option_string(btf_archive_path) {
        Ok(v) => v,
        Err(e) => my_bail!(e),
    };
    let skel = match BpfSkeletonBuilder::from_json_package(&package, btf_archive_path).build() {
        Err(e) => my_bail!(format!("Failed to build: {}", e)),
        Ok(s) => s,
    };
    let ret = Box::leak(Box::new(SkeletonWrapper::PreLoad(skel)));
    ret as *mut SkeletonWrapper
}

#[no_mangle]
/// @brief start running the ebpf program
/// @details load and attach the ebpf program to the kernel to run the ebpf
/// program if the ebpf program has maps to export to user space, you need to
/// call the wait and export.
pub extern "C" fn load_and_attach_eunomia_skel(prog: *mut SkeletonWrapper) -> c_int {
    let wrapper = unsafe { &mut *(prog as *mut SkeletonWrapper) };
    let skel = match std::mem::replace(wrapper, SkeletonWrapper::None) {
        SkeletonWrapper::PreLoad(skel) => skel,
        SkeletonWrapper::Loaded(_) => my_bail_custom!(format!("Skeleton is already loaded"), -1),
        SkeletonWrapper::None => return -1,
    };
    let loaded = match skel.load_and_attach() {
        Ok(v) => v,
        Err(e) => my_bail_custom!(format!("Failed to load or attach: {}", e), -1),
    };
    *wrapper = SkeletonWrapper::Loaded(loaded);
    0
}

#[no_mangle]
/// @brief wait for the program to exit and receive data from export maps and
/// send to handlers
/// @details if the program has a ring buffer or perf event to export data
/// to user space, the program will help load the map info and poll the
/// events automatically.
pub extern "C" fn wait_and_poll_events_to_handler(
    prog: *mut SkeletonWrapper,
    ty: c_int,
    handler: extern "C" fn(*const c_void, *const c_char, usize),
    ctx: *const c_void,
) -> c_int {
    let ty = match ty {
        0 => ExportFormatType::PlainText,
        1 => ExportFormatType::Json,
        2 => ExportFormatType::RawEvent,
        s => my_bail_custom!(format!("Invalid export format type: {}", s), -1),
    };
    let prog = match unsafe { &*prog } {
        SkeletonWrapper::Loaded(prog) => prog,
        _ => my_bail_custom!("Expected a loaded skeleton", -1),
    };
    struct LocalEventHandler {
        callback: extern "C" fn(*const c_void, *const c_char, usize),
        ctx: *const c_void,
    }
    impl EventHandler for LocalEventHandler {
        fn handle_event(
            &self,
            _context: Option<std::sync::Arc<dyn std::any::Any>>,
            data: bpf_loader_lib::export_event::ReceivedEventData,
        ) {
            let bytes = data.trivally_to_plain_bytes();
            (self.callback)(self.ctx, bytes.as_ptr() as *const c_char, bytes.len());
        }
    }
    if let Err(e) = prog.wait_and_poll_to_handler(
        ty,
        Some(Arc::new(LocalEventHandler {
            callback: handler,
            ctx,
        })),
        None,
    ) {
        my_bail_custom!(e, -1);
    }
    0
}

#[no_mangle]
/// @brief stop, detach, and free the memory
/// @warning this function will free the memory of the program
/// it's not reenter-able, and you should not use the program after this
/// function.
pub extern "C" fn destroy_eunomia_skel(prog: *mut SkeletonWrapper) {
    drop(unsafe { Box::from_raw(prog) });
}
#[no_mangle]
/// @brief get fd of ebpf program or map by name
pub extern "C" fn get_bpf_fd(prog: *mut SkeletonWrapper, name: *const c_char) -> c_int {
    let prog = match unsafe { &*prog } {
        SkeletonWrapper::Loaded(prog) => prog,
        _ => my_bail_custom!("Expected a loaded skeleton", -1),
    };
    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(v) => v,
        Err(e) => my_bail_custom!(format!("Invalid name bytes: {}", e), -1),
    };
    prog.get_map_fd(name)
        .or_else(|| prog.get_prog_fd(name))
        .unwrap_or(-1)
}
#[no_mangle]
/// @brief stop, detach, but not clean the memory
pub extern "C" fn stop_ebpf_program(prog: *mut SkeletonWrapper) {
    let prog = match unsafe { &*prog } {
        SkeletonWrapper::Loaded(prog) => prog,
        _ => return,
    };
    prog.create_poll_handle().terminate();
}
#[no_mangle]
/// @brief free the memory of the program
pub extern "C" fn free_bpf_skel(prog: *mut SkeletonWrapper) {
    destroy_eunomia_skel(prog);
}
#[no_mangle]
/// @brief merge json config and args and return the new config
pub extern "C" fn parse_args_to_json_config(
    json_data: *const c_char,
    args: *const *const c_char,
    argc: c_int,
    out_buffer: *mut c_char,
    out_buffer_size: usize,
) -> c_int {
    let mut skel = match load_object::<EunomiaObjectMeta>(json_data) {
        Err(e) => my_bail_custom!(e, -1),
        Ok(v) => v,
    };
    let args_vec = match unsafe { convert_args(slice::from_raw_parts(args, argc as usize)) } {
        Err(e) => my_bail_custom!(e, -1),
        Ok(v) => v,
    };
    let parser = match skel.build_argument_parser() {
        Ok(v) => v,
        Err(e) => my_bail_custom!(
            format!("Failed to build command parser for the skeleton: {}", e),
            -1
        ),
    };
    let matches = match parser.try_get_matches_from(args_vec) {
        Ok(v) => v,
        Err(e) => my_bail_custom!(e, -2),
    };
    if let Err(e) = skel.parse_arguments_and_fill_skeleton_variables(
        &matches,
        UnpresentVariableAction::FillWithZero,
    ) {
        my_bail_custom!(format!("Failed to parse arguments: {}", e), -1)
    }
    let out_json_str = match serde_json::to_string(&skel) {
        Ok(v) => v,
        Err(e) => my_bail_custom!(format!("Failed to serialize new skel to json: {}", e), -1),
    };
    let out_json_str = out_json_str.as_bytes();
    let out_slice = unsafe { slice::from_raw_parts_mut(out_buffer, out_buffer_size) };
    let mut i = 0;
    while i < out_json_str.len() && i + 1 < out_slice.len() {
        out_slice[i] = out_json_str[i] as c_char;
        i += 1;
    }
    out_slice[i] = 0;
    0
}

#[no_mangle]
/// @brief create a polling handle from a ready-to-poll eunomia
pub extern "C" fn handle_create(prog: *mut SkeletonWrapper) -> *mut HandleWrapper {
    let prog = match unsafe { &*prog } {
        SkeletonWrapper::Loaded(prog) => prog,
        _ => my_bail!("Expected a loaded skeleton"),
    };
    let ptr = Box::leak(Box::new(HandleWrapper {
        handle: prog.create_poll_handle(),
    }));
    ptr as *mut HandleWrapper
}
#[no_mangle]
/// @brief pause or resume the poller
pub extern "C" fn handle_set_pause_state(handle: *mut HandleWrapper, state: u8) {
    let handle = unsafe { &*handle };
    handle.handle.set_pause(state != 0);
}
#[no_mangle]
/// @brief Terminate the poller
pub extern "C" fn handle_terminate(handle: *mut HandleWrapper) {
    let handle = unsafe { &*handle };
    handle.handle.terminate();
}
#[no_mangle]
/// @brief Destroy the handler
pub extern "C" fn handle_destroy(handle: *mut HandleWrapper) {
    drop(unsafe { Box::from_raw(handle) });
}

#[no_mangle]
/// @brief Get the error message
pub extern "C" fn get_error_message(str_out: *mut c_char, buf_size: usize) {
    ERROR_MESSAGE.with(|v| {
        let borrow_ref = v.borrow();
        let bytes = borrow_ref.as_bytes();
        let out_bytes = unsafe { std::slice::from_raw_parts_mut(str_out as *mut u8, buf_size) };
        let mut i = 0;
        while i + 1 < out_bytes.len() && i < bytes.len() {
            out_bytes[i] = bytes[i];
            i += 1;
        }
        out_bytes[i] = 0;
    });
}
