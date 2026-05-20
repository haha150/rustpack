#![allow(dead_code)]

pub fn service_exe_snippet(body: &str) -> String {
    format!(
        r#"use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::Foundation::*;

static mut SERVICE_STATUS_HANDLE: *mut c_void = std::ptr::null_mut();

fn main() {{
    unsafe {{
        let service_name: Vec<u16> = "RustPackService"
            .encode_utf16().chain(std::iter::once(0)).collect();
        let service_table = [
            SERVICE_TABLE_ENTRYW {{
                lpServiceName: service_name.as_ptr() as *mut _,
                lpServiceProc: Some(service_main),
            }},
            SERVICE_TABLE_ENTRYW {{
                lpServiceName: std::ptr::null_mut(),
                lpServiceProc: None,
            }},
        ];
        StartServiceCtrlDispatcherW(service_table.as_ptr());
    }}
}}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {{
    let service_name: Vec<u16> = "RustPackService"
        .encode_utf16().chain(std::iter::once(0)).collect();
    let handle = RegisterServiceCtrlHandlerExW(
        service_name.as_ptr(),
        Some(service_handler),
        std::ptr::null_mut(),
    );
    if !handle.is_null() {{
        SERVICE_STATUS_HANDLE = handle;

        let mut status = SERVICE_STATUS {{
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_RUNNING,
            dwControlsAccepted: SERVICE_ACCEPT_STOP,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        }};
        SetServiceStatus(SERVICE_STATUS_HANDLE, &status);

        std::thread::spawn(|| {{
{body}
        }});

        loop {{
            std::thread::sleep(std::time::Duration::from_secs(60));
        }}
    }}
}}

unsafe extern "system" fn service_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {{
    if control == SERVICE_CONTROL_STOP {{
        let mut status = SERVICE_STATUS {{
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: SERVICE_STOPPED,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        }};
        let _ = SetServiceStatus(SERVICE_STATUS_HANDLE, &status);
        std::process::exit(0);
    }}
    0 // NO_ERROR
}}"#,
        body = body
    )
}

pub fn service_cargo_features() -> String {
    r#"
# Additional windows features for service
# "Win32_System_Services"
"#
    .to_string()
}
