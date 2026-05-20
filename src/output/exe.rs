#![allow(dead_code)]

pub fn exe_entry_snippet() -> String {
    r#"#![windows_subsystem = "windows"]
"#
    .to_string()
}

pub fn exe_main_wrapper(body: &str) -> String {
    format!(
        r#"fn main() {{
{body}
}}"#,
        body = body
    )
}
