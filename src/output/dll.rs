#![allow(dead_code)]

pub fn dll_entry_snippet(body: &str) -> String {
    format!(
        r#"
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h_instance: *mut c_void,
    dw_reason: u32,
    _lp_reserved: *mut c_void,
) -> i32 {{
    if dw_reason == 1 {{ // DLL_PROCESS_ATTACH
        std::thread::spawn(|| {{
{body}
        }});
    }}
    1 // TRUE
}}"#,
        body = body
    )
}

pub fn dll_cargo_toml_additions() -> String {
    r#"
[lib]
crate-type = ["cdylib"]
"#
    .to_string()
}
