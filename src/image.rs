use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use byteorder::{BigEndian, WriteBytesExt};

use crate::error::{AvbToolError as DynoError, Result};
use crate::info::{AvbImageInfo, ScanResult, scan_input};
use crate::parser::{
    AVB_FOOTER_SIZE, AVB_MAGIC, AVB_VBMETA_IMAGE_HEADER_SIZE, AvbFooter, AvbImageType,
    AvbVBMetaHeader, detect_avb_image_type,
};

pub fn inspect_avb_image(path: &Path) -> Result<AvbImageInfo> {
    let mut entries = scan_input(path)?;
    let entry = entries
        .pop()
        .ok_or_else(|| DynoError::Tool(format!("No AVB entries returned for {}", path.display())))?;
    match entry.result {
        ScanResult::Avb(info) => Ok(info),
        ScanResult::None => Err(DynoError::Tool(format!(
            "{} is not an AVB image",
            path.display()
        ))),
        ScanResult::Error(message) => Err(DynoError::Tool(message)),
    }
}

pub fn load_vbmeta_blob(path: &Path) -> Result<Vec<u8>> {
    let image_type = detect_avb_image_type(path)?;
    if image_type == AvbImageType::None {
        return Err(DynoError::Tool(format!(
            "{} is not an AVB image",
            path.display()
        )));
    }

    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    match image_type {
        AvbImageType::Vbmeta => {
            let header = read_header_at(&mut file, 0)?;
            let size = compute_vbmeta_blob_size(&header)?;
            read_exact_at(&mut file, 0, size as usize)
        }
        AvbImageType::Footer => {
            file.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
            let footer = AvbFooter::from_reader(&mut file)?;
            if footer.vbmeta_offset + footer.vbmeta_size > file_size {
                return Err(DynoError::Tool(format!(
                    "VBMeta range exceeds file size in {}",
                    path.display()
                )));
            }
            read_exact_at(&mut file, footer.vbmeta_offset, footer.vbmeta_size as usize)
        }
        AvbImageType::None => unreachable!(),
    }
}

pub fn extract_public_key_metadata(header: &AvbVBMetaHeader, blob: &[u8]) -> Result<Vec<u8>> {
    if header.public_key_metadata_size == 0 {
        return Ok(Vec::new());
    }
    let auth_size = header.authentication_data_block_size as usize;
    let aux_start = AVB_VBMETA_IMAGE_HEADER_SIZE + auth_size;
    let offset = aux_start + header.public_key_metadata_offset as usize;
    let end = offset + header.public_key_metadata_size as usize;
    if end > blob.len() {
        return Err(DynoError::Tool(
            "Public key metadata exceeds vbmeta blob size".into(),
        ));
    }
    Ok(blob[offset..end].to_vec())
}

pub fn compute_vbmeta_blob_size(header: &AvbVBMetaHeader) -> Result<u64> {
    (AVB_VBMETA_IMAGE_HEADER_SIZE as u64)
        .checked_add(header.authentication_data_block_size)
        .and_then(|size| size.checked_add(header.auxiliary_data_block_size))
        .ok_or_else(|| DynoError::Tool("VBMeta size overflow".into()))
}

pub fn read_header_at(file: &mut File, offset: u64) -> Result<AvbVBMetaHeader> {
    let bytes = read_exact_at(file, offset, AVB_VBMETA_IMAGE_HEADER_SIZE)?;
    AvbVBMetaHeader::from_reader(bytes.as_slice())
}

pub fn read_exact_at(file: &mut File, offset: u64, size: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn encode_header(header: &AvbVBMetaHeader) -> Vec<u8> {
    let mut buf = Vec::with_capacity(AVB_VBMETA_IMAGE_HEADER_SIZE);
    buf.extend_from_slice(&header.magic);
    buf.write_u32::<BigEndian>(header.required_libavb_version_major)
        .unwrap();
    buf.write_u32::<BigEndian>(header.required_libavb_version_minor)
        .unwrap();
    buf.write_u64::<BigEndian>(header.authentication_data_block_size)
        .unwrap();
    buf.write_u64::<BigEndian>(header.auxiliary_data_block_size)
        .unwrap();
    buf.write_u32::<BigEndian>(header.algorithm_type).unwrap();
    buf.write_u64::<BigEndian>(header.hash_offset).unwrap();
    buf.write_u64::<BigEndian>(header.hash_size).unwrap();
    buf.write_u64::<BigEndian>(header.signature_offset).unwrap();
    buf.write_u64::<BigEndian>(header.signature_size).unwrap();
    buf.write_u64::<BigEndian>(header.public_key_offset).unwrap();
    buf.write_u64::<BigEndian>(header.public_key_size).unwrap();
    buf.write_u64::<BigEndian>(header.public_key_metadata_offset)
        .unwrap();
    buf.write_u64::<BigEndian>(header.public_key_metadata_size)
        .unwrap();
    buf.write_u64::<BigEndian>(header.descriptors_offset).unwrap();
    buf.write_u64::<BigEndian>(header.descriptors_size).unwrap();
    buf.write_u64::<BigEndian>(header.rollback_index).unwrap();
    buf.write_u32::<BigEndian>(header.flags).unwrap();
    buf.write_u32::<BigEndian>(header.rollback_index_location)
        .unwrap();
    let mut release = [0u8; 48];
    let release_bytes = header.release_string.as_bytes();
    let copy_len = release_bytes.len().min(47);
    release[..copy_len].copy_from_slice(&release_bytes[..copy_len]);
    buf.extend_from_slice(&release);
    buf.resize(AVB_VBMETA_IMAGE_HEADER_SIZE, 0);
    buf
}

pub fn encode_footer(footer: &AvbFooter) -> Vec<u8> {
    let mut buf = vec![0u8; AVB_FOOTER_SIZE as usize];
    {
        let mut cursor = std::io::Cursor::new(&mut buf[..]);
        cursor.write_all(&footer.magic).unwrap();
        cursor.write_u32::<BigEndian>(footer.version_major).unwrap();
        cursor.write_u32::<BigEndian>(footer.version_minor).unwrap();
        cursor.write_u64::<BigEndian>(footer.original_image_size)
            .unwrap();
        cursor.write_u64::<BigEndian>(footer.vbmeta_offset).unwrap();
        cursor.write_u64::<BigEndian>(footer.vbmeta_size).unwrap();
    }
    buf
}

pub fn default_vbmeta_header() -> AvbVBMetaHeader {
    AvbVBMetaHeader {
        magic: *AVB_MAGIC,
        required_libavb_version_major: 1,
        required_libavb_version_minor: 0,
        authentication_data_block_size: 0,
        auxiliary_data_block_size: 0,
        algorithm_type: 0,
        hash_offset: 0,
        hash_size: 0,
        signature_offset: 0,
        signature_size: 0,
        public_key_offset: 0,
        public_key_size: 0,
        public_key_metadata_offset: 0,
        public_key_metadata_size: 0,
        descriptors_offset: 0,
        descriptors_size: 0,
        rollback_index: 0,
        flags: 0,
        rollback_index_location: 0,
        release_string: format!("avbtool-rs {}", env!("CARGO_PKG_VERSION")),
    }
}
