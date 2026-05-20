#![allow(dead_code)]

pub fn pic_build_instructions() -> String {
    r#"// PIC output: After compiling the loader as a standard EXE,
// extract the .text section as raw position-independent shellcode.
//
// Build steps:
// 1. cargo rustc --release -- --emit=obj
// 2. link.exe /subsystem:native /nodefaultlib /entry:main loader.obj
// 3. Extract .text section bytes from the linked PE as raw shellcode
//
// The loader source must be written to avoid any relocations or imports
// that cannot be resolved at PIC time (use dynamic resolution via PEB).
"#
    .to_string()
}

pub fn pic_loader_preamble() -> String {
    r#"// Position-Independent Code preamble
// All API resolution done via PEB -> LDR -> InMemoryOrderModuleList
#![no_std]
#![no_main]
#![feature(asm_sym)]

use core::arch::asm;
"#
    .to_string()
}

pub fn extract_text_section(pe_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    if pe_bytes.len() < 64 {
        anyhow::bail!("PE too small");
    }

    let e_lfanew = u32::from_le_bytes([
        pe_bytes[0x3C], pe_bytes[0x3D], pe_bytes[0x3E], pe_bytes[0x3F],
    ]) as usize;

    let file_header_offset = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([
        pe_bytes[file_header_offset + 2], pe_bytes[file_header_offset + 3],
    ]) as usize;
    let optional_header_size = u16::from_le_bytes([
        pe_bytes[file_header_offset + 16], pe_bytes[file_header_offset + 17],
    ]) as usize;

    let sections_start = file_header_offset + 20 + optional_header_size;

    for i in 0..num_sections {
        let sec_offset = sections_start + i * 40;
        if sec_offset + 40 > pe_bytes.len() {
            break;
        }

        let name = &pe_bytes[sec_offset..sec_offset + 8];
        if name.starts_with(b".text") {
            let raw_data_size = u32::from_le_bytes([
                pe_bytes[sec_offset + 16], pe_bytes[sec_offset + 17],
                pe_bytes[sec_offset + 18], pe_bytes[sec_offset + 19],
            ]) as usize;
            let raw_data_ptr = u32::from_le_bytes([
                pe_bytes[sec_offset + 20], pe_bytes[sec_offset + 21],
                pe_bytes[sec_offset + 22], pe_bytes[sec_offset + 23],
            ]) as usize;

            if raw_data_ptr + raw_data_size <= pe_bytes.len() {
                return Ok(pe_bytes[raw_data_ptr..raw_data_ptr + raw_data_size].to_vec());
            }
        }
    }

    anyhow::bail!("No .text section found")
}
