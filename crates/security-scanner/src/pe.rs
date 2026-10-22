//! Minimal, panic-free Portable Executable parser.
//!
//! Only the subset of the PE format needed for triage is parsed: COFF header,
//! optional header, section table, import directory (data directory index 1),
//! export names (index 0) and the .NET COM descriptor flag (index 14).
//!
//! Every read is bounds-checked via [`checked`] helpers. Malformed input never
//! panics: the function returns `None` when the MZ/PE signatures are missing
//! and otherwise returns whatever metadata could be read.

use security_core::{PeImport, PeMetadata, PeSection};

use crate::hashing::shannon_entropy;

/// Cap on parsed sections (a valid image has at most 96).
const MAX_SECTIONS: usize = 96;
/// Cap on parsed import descriptors.
const MAX_IMPORT_DLLS: usize = 64;
/// Cap on parsed imported function names per DLL.
const MAX_FUNCTIONS_PER_DLL: usize = 512;
/// Cap on parsed export names.
const MAX_EXPORTS: usize = 4096;
/// Cap on the length of a parsed C string (DLL / function / export name).
const MAX_NAME_LEN: usize = 260;

/// Data directory index of the export table.
const DIR_EXPORT: usize = 0;
/// Data directory index of the import table.
const DIR_IMPORT: usize = 1;
/// Data directory index of the CLR/.NET COM descriptor.
const DIR_COM_DESCRIPTOR: usize = 14;

const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Raw section header information needed for RVA -> file offset translation.
#[derive(Debug, Clone, Copy)]
struct SectionMap {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

/// Parses `data` as a PE image.
///
/// Returns `None` only when the data is not a PE image at all (missing or
/// unreadable MZ/PE signatures). Any partially readable image returns the
/// metadata that could be decoded.
pub fn analyze_pe(data: &[u8]) -> Option<PeMetadata> {
    // DOS header: "MZ" plus the offset of the PE signature at 0x3C.
    if read_u16(data, 0)? != 0x5A4D {
        return None;
    }
    let pe_offset = read_u32(data, 0x3C)? as usize;
    let signature_end = pe_offset.checked_add(4)?;
    if data.get(pe_offset..signature_end)? != *b"PE\0\0" {
        return None;
    }

    let coff = signature_end;
    let machine = read_u16(data, coff)?;
    let number_of_sections = read_u16(data, coff.checked_add(2)?)? as usize;
    let timestamp = read_u32(data, coff.checked_add(4)?)?;
    let size_of_optional_header = read_u16(data, coff.checked_add(16)?)? as usize;
    let characteristics = read_u16(data, coff.checked_add(18)?)?;
    let optional = coff.checked_add(20)?;

    let mut metadata = PeMetadata {
        machine: machine_name(machine),
        subsystem: "unknown".to_string(),
        is_dll: characteristics & IMAGE_FILE_DLL != 0,
        is_dotnet: false,
        timestamp: Some(timestamp),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        entry_point: None,
    };

    let mut is_pe32_plus = false;
    let mut directories: Vec<(u32, u32)> = Vec::new();

    if size_of_optional_header >= 2 {
        if let Some(magic) = read_u16(data, optional) {
            is_pe32_plus = magic == 0x20B;
        }
        metadata.entry_point = read_u32(data, optional.checked_add(16)?);
        if let Some(subsystem) = read_u16(data, optional.checked_add(68)?) {
            metadata.subsystem = subsystem_name(subsystem);
        }

        let (count_offset, dir_start) = if is_pe32_plus {
            (optional.checked_add(108)?, optional.checked_add(112)?)
        } else {
            (optional.checked_add(92)?, optional.checked_add(96)?)
        };
        if let Some(count) = read_u32(data, count_offset) {
            let count = count.min(16) as usize;
            for index in 0..count {
                let offset = dir_start.checked_add(index * 8)?;
                match (read_u32(data, offset), read_u32(data, offset + 4)) {
                    (Some(rva), Some(size)) => directories.push((rva, size)),
                    _ => break,
                }
            }
        }
    }

    metadata.is_dotnet = directories
        .get(DIR_COM_DESCRIPTOR)
        .map(|(rva, size)| *rva != 0 && *size != 0)
        .unwrap_or(false);

    // Section table directly follows the optional header.
    let section_table = optional.checked_add(size_of_optional_header)?;
    let mut section_maps: Vec<SectionMap> = Vec::new();
    for index in 0..number_of_sections.min(MAX_SECTIONS) {
        let Some(offset) = section_table.checked_add(index * 40) else {
            break;
        };
        let Some(name_bytes) = data.get(offset..offset + 8) else {
            break;
        };
        let (Some(virtual_size), Some(virtual_address), Some(raw_size), Some(raw_offset)) = (
            read_u32(data, offset + 8),
            read_u32(data, offset + 12),
            read_u32(data, offset + 16),
            read_u32(data, offset + 20),
        ) else {
            break;
        };
        let Some(section_characteristics) = read_u32(data, offset + 36) else {
            break;
        };

        // Section contents are clamped to the actual file size so a bogus
        // header cannot cause an out-of-bounds slice.
        let start = (raw_offset as usize).min(data.len());
        let end = (raw_offset as usize)
            .saturating_add(raw_size as usize)
            .min(data.len());
        let entropy = if start < end {
            shannon_entropy(&data[start..end])
        } else {
            0.0
        };

        metadata.sections.push(PeSection {
            name: section_name(name_bytes),
            virtual_size,
            raw_size,
            entropy,
            executable: section_characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            writable: section_characteristics & IMAGE_SCN_MEM_WRITE != 0,
        });
        section_maps.push(SectionMap {
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
        });
    }

    if let Some((rva, _size)) = directories.get(DIR_IMPORT).copied() {
        if rva != 0 {
            metadata.imports = parse_imports(data, &section_maps, rva, is_pe32_plus);
        }
    }
    if let Some((rva, _size)) = directories.get(DIR_EXPORT).copied() {
        if rva != 0 {
            metadata.exports = parse_exports(data, &section_maps, rva);
        }
    }

    Some(metadata)
}

fn parse_imports(
    data: &[u8],
    sections: &[SectionMap],
    import_rva: u32,
    is_pe32_plus: bool,
) -> Vec<PeImport> {
    let mut imports = Vec::new();
    let Some(table_offset) = rva_to_offset(sections, import_rva) else {
        return imports;
    };

    for index in 0..MAX_IMPORT_DLLS {
        let Some(entry_offset) = table_offset.checked_add(index * 20) else {
            break;
        };
        let (Some(original_first_thunk), Some(name_rva), Some(first_thunk)) = (
            read_u32(data, entry_offset),
            read_u32(data, entry_offset + 12),
            read_u32(data, entry_offset + 16),
        ) else {
            break;
        };
        if name_rva == 0 && first_thunk == 0 {
            break; // terminator
        }
        let Some(name_offset) = rva_to_offset(sections, name_rva) else {
            break;
        };
        let Some(dll) = read_c_string(data, name_offset) else {
            break;
        };

        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let mut functions = Vec::new();
        if let Some(thunk_offset) = rva_to_offset(sections, thunk_rva) {
            let entry_size = if is_pe32_plus { 8 } else { 4 };
            let ordinal_flag: u64 = if is_pe32_plus { 1 << 63 } else { 1 << 31 };
            for thunk_index in 0..MAX_FUNCTIONS_PER_DLL {
                let Some(offset) = thunk_offset.checked_add(thunk_index * entry_size) else {
                    break;
                };
                let value = if is_pe32_plus {
                    read_u64(data, offset)
                } else {
                    read_u32(data, offset).map(u64::from)
                };
                let Some(value) = value else {
                    break;
                };
                if value == 0 {
                    break;
                }
                if value & ordinal_flag != 0 {
                    functions.push(format!("#{}", value & (ordinal_flag - 1)));
                } else {
                    let name_rva = (value & (ordinal_flag - 1)) as u32;
                    // IMAGE_IMPORT_BY_NAME: u16 hint followed by the name.
                    let Some(import_name_offset) = rva_to_offset(sections, name_rva) else {
                        break;
                    };
                    match read_c_string(data, import_name_offset.saturating_add(2)) {
                        Some(name) if !name.is_empty() => functions.push(name),
                        _ => break,
                    }
                }
            }
        }

        imports.push(PeImport { dll, functions });
    }

    imports
}

fn parse_exports(data: &[u8], sections: &[SectionMap], export_rva: u32) -> Vec<String> {
    let mut exports = Vec::new();
    let Some(directory_offset) = rva_to_offset(sections, export_rva) else {
        return exports;
    };
    // IMAGE_EXPORT_DIRECTORY: NumberOfNames at +24, AddressOfNames at +32.
    let (Some(number_of_names), Some(address_of_names)) = (
        read_u32(data, directory_offset + 24),
        read_u32(data, directory_offset + 32),
    ) else {
        return exports;
    };
    let Some(names_offset) = rva_to_offset(sections, address_of_names) else {
        return exports;
    };

    for index in 0..(number_of_names as usize).min(MAX_EXPORTS) {
        let Some(entry) = names_offset.checked_add(index * 4) else {
            break;
        };
        let Some(name_rva) = read_u32(data, entry) else {
            break;
        };
        let Some(name_offset) = rva_to_offset(sections, name_rva) else {
            break;
        };
        match read_c_string(data, name_offset) {
            Some(name) if !name.is_empty() => exports.push(name),
            _ => break,
        }
    }

    exports
}

/// Translates an RVA to a file offset using the section table.
fn rva_to_offset(sections: &[SectionMap], rva: u32) -> Option<usize> {
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        let end = section.virtual_address.checked_add(span)?;
        if rva >= section.virtual_address && rva < end {
            let delta = rva - section.virtual_address;
            let offset = section.raw_offset.checked_add(delta)?;
            return Some(offset as usize);
        }
    }
    None
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let bytes: [u8; 2] = data.get(offset..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = data.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

/// Reads a NUL-terminated string, bounded by [`MAX_NAME_LEN`].
fn read_c_string(data: &[u8], offset: usize) -> Option<String> {
    let slice = data.get(offset..)?;
    let limit = slice.len().min(MAX_NAME_LEN);
    let end = slice[..limit]
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(limit);
    let text = String::from_utf8_lossy(&slice[..end]);
    Some(text.trim().to_string())
}

fn section_name(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn machine_name(machine: u16) -> String {
    match machine {
        0x0000 => "unknown",
        0x014C => "i386",
        0x0162 => "r3000",
        0x0166 => "r4000",
        0x0168 => "mips",
        0x01A2 => "sh3",
        0x01A6 => "sh4",
        0x01C0 => "arm",
        0x01C2 => "thumb",
        0x01C4 => "armv7",
        0x01D3 => "am33",
        0x0200 => "ia64",
        0x0266 => "mips16",
        0x0284 => "alpha64",
        0x0366 => "mipsfpu",
        0x0466 => "mipsfpu16",
        0x0520 => "tricore",
        0x0EBC => "ebc",
        0x8664 => "amd64",
        0x9041 => "m32r",
        0xAA64 => "arm64",
        other => return format!("unknown(0x{other:04x})"),
    }
    .to_string()
}

fn subsystem_name(subsystem: u16) -> String {
    match subsystem {
        0 => "unknown",
        1 => "native",
        2 => "windows_gui",
        3 => "windows_console",
        5 => "os2_console",
        7 => "posix_console",
        8 => "native_windows",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        other => return format!("unknown(0x{other:04x})"),
    }
    .to_string()
}
