#![allow(dead_code)]

pub fn xll_entry_snippet(body: &str) -> String {
    format!(
        r#"
// Excel Add-in entry point
#[no_mangle]
pub unsafe extern "system" fn xlAutoOpen() -> i32 {{
    std::thread::spawn(|| {{
{body}
    }});
    1
}}

#[no_mangle]
pub unsafe extern "system" fn xlAutoClose() -> i32 {{
    1
}}

#[no_mangle]
pub unsafe extern "system" fn xlAutoAdd() -> i32 {{
    1
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

pub fn xll_cargo_toml_additions() -> String {
    r#"
[lib]
crate-type = ["cdylib"]
"#
    .to_string()
}
