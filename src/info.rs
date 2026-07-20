use std::fmt::Write as _;
use std::fs;
use std::io::{Cursor, Read};
use std::ops::Range;
use std::path::{Path, PathBuf};

use byteorder::{BigEndian, ReadBytesExt};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use sha1::{Digest as Sha1Digest, Sha1};

use crate::crypto::lookup_algorithm_by_type;
use crate::error::{AvbToolError as DynoError, Result};
use crate::image::read_exact_at;
use crate::parser::{
    AVB_FOOTER_SIZE, AVB_VBMETA_IMAGE_HEADER_SIZE, AvbFooter, AvbImageType, AvbVBMetaHeader,
    detect_avb_image_type, sparse_err,
};
use crate::sparse::ImageHandler;

const DESCRIPTOR_HEADER_SIZE: usize = 16;
const PROPERTY_DESCRIPTOR_SIZE: usize = 32;
const HASHTREE_DESCRIPTOR_SIZE: usize = 180;
const HASH_DESCRIPTOR_SIZE: usize = 132;
const KERNEL_CMDLINE_DESCRIPTOR_SIZE: usize = 24;
const CHAIN_PARTITION_DESCRIPTOR_SIZE: usize = 92;

const DESCRIPTOR_TAG_PROPERTY: u64 = 0;
const DESCRIPTOR_TAG_HASHTREE: u64 = 1;
const DESCRIPTOR_TAG_HASH: u64 = 2;
const DESCRIPTOR_TAG_KERNEL_CMDLINE: u64 = 3;
const DESCRIPTOR_TAG_CHAIN_PARTITION: u64 = 4;

/// Optional rendering hooks for sparse markers and cert integration.
///
/// These stay inert until callers supply sparse detection or preformatted cert
/// text; they intentionally avoid importing unfinished modules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InfoRenderOptions {
    /// When true, appends ` (Sparse)` to the Minimum libavb version line.
    pub sparse: bool,
    /// When true and [`Self::cert_text`] is set, appends an avb_cert section.
    pub include_cert: bool,
    /// Optional preformatted certificate block.
    pub cert_text: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanEntry {
    pub path: PathBuf,
    pub file_size: u64,
    pub result: ScanResult,
}

// AvbImageInfo is large; boxing would force image.rs call-site changes outside
// this packet. Keep the ergonomic variant and silence the size lint.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum ScanResult {
    Avb(AvbImageInfo),
    None,
    Error(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct AvbImageInfo {
    pub image_type: AvbImageType,
    pub footer: Option<AvbFooter>,
    pub vbmeta_offset: u64,
    pub vbmeta_size: u64,
    pub header: AvbVBMetaHeader,
    pub algorithm_name: String,
    pub public_key_sha1: Option<String>,
    #[serde(serialize_with = "serialize_descriptors")]
    pub descriptors: Vec<DescriptorInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DescriptorInfo {
    Property {
        key: String,
        value: Vec<u8>,
    },
    Hashtree {
        dm_verity_version: u32,
        image_size: u64,
        tree_offset: u64,
        tree_size: u64,
        data_block_size: u32,
        hash_block_size: u32,
        fec_num_roots: u32,
        fec_offset: u64,
        fec_size: u64,
        hash_algorithm: String,
        partition_name: String,
        salt: Vec<u8>,
        root_digest: Vec<u8>,
        flags: u32,
    },
    Hash {
        image_size: u64,
        hash_algorithm: String,
        partition_name: String,
        salt: Vec<u8>,
        digest: Vec<u8>,
        flags: u32,
    },
    KernelCmdline {
        flags: u32,
        kernel_cmdline: String,
    },
    ChainPartition {
        rollback_index_location: u32,
        partition_name: String,
        public_key: Vec<u8>,
        flags: u32,
    },
    Unknown {
        tag: u64,
        num_bytes_following: u64,
        body: Vec<u8>,
    },
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn serialize_descriptors<S: Serializer>(
    descriptors: &[DescriptorInfo],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = serializer.serialize_seq(Some(descriptors.len()))?;
    for descriptor in descriptors {
        seq.serialize_element(&JsonDescriptor(descriptor))?;
    }
    seq.end()
}

struct JsonDescriptor<'a>(&'a DescriptorInfo);

impl Serialize for JsonDescriptor<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        match self.0 {
            DescriptorInfo::Property { key, value } => {
                #[derive(Serialize)]
                struct V<'b> {
                    key: &'b str,
                    value: String,
                }
                map.serialize_entry(
                    "Property",
                    &V {
                        key,
                        value: String::from_utf8_lossy(value).into_owned(),
                    },
                )?;
            }
            DescriptorInfo::Hash {
                image_size,
                hash_algorithm,
                partition_name,
                salt,
                digest,
                flags,
            } => {
                #[derive(Serialize)]
                struct V<'b> {
                    image_size: u64,
                    hash_algorithm: &'b str,
                    partition_name: &'b str,
                    salt: String,
                    digest: String,
                    flags: u32,
                }
                map.serialize_entry(
                    "Hash",
                    &V {
                        image_size: *image_size,
                        hash_algorithm,
                        partition_name,
                        salt: bytes_to_hex(salt),
                        digest: bytes_to_hex(digest),
                        flags: *flags,
                    },
                )?;
            }
            DescriptorInfo::Hashtree {
                dm_verity_version,
                image_size,
                tree_offset,
                tree_size,
                data_block_size,
                hash_block_size,
                fec_num_roots,
                fec_offset,
                fec_size,
                hash_algorithm,
                partition_name,
                salt,
                root_digest,
                flags,
            } => {
                #[derive(Serialize)]
                struct V<'b> {
                    dm_verity_version: u32,
                    image_size: u64,
                    tree_offset: u64,
                    tree_size: u64,
                    data_block_size: u32,
                    hash_block_size: u32,
                    fec_num_roots: u32,
                    fec_offset: u64,
                    fec_size: u64,
                    hash_algorithm: &'b str,
                    partition_name: &'b str,
                    salt: String,
                    root_digest: String,
                    flags: u32,
                }
                map.serialize_entry(
                    "Hashtree",
                    &V {
                        dm_verity_version: *dm_verity_version,
                        image_size: *image_size,
                        tree_offset: *tree_offset,
                        tree_size: *tree_size,
                        data_block_size: *data_block_size,
                        hash_block_size: *hash_block_size,
                        fec_num_roots: *fec_num_roots,
                        fec_offset: *fec_offset,
                        fec_size: *fec_size,
                        hash_algorithm,
                        partition_name,
                        salt: bytes_to_hex(salt),
                        root_digest: bytes_to_hex(root_digest),
                        flags: *flags,
                    },
                )?;
            }
            DescriptorInfo::KernelCmdline {
                flags,
                kernel_cmdline,
            } => {
                #[derive(Serialize)]
                struct V<'b> {
                    flags: u32,
                    kernel_cmdline: &'b str,
                }
                map.serialize_entry(
                    "KernelCmdline",
                    &V {
                        flags: *flags,
                        kernel_cmdline,
                    },
                )?;
            }
            DescriptorInfo::ChainPartition {
                rollback_index_location,
                partition_name,
                public_key,
                flags,
            } => {
                #[derive(Serialize)]
                struct V<'b> {
                    rollback_index_location: u32,
                    partition_name: &'b str,
                    public_key_sha1: String,
                    flags: u32,
                }
                let pk_sha1 = {
                    let mut hasher = Sha1::new();
                    hasher.update(public_key);
                    format!("{:x}", hasher.finalize())
                };
                map.serialize_entry(
                    "ChainPartition",
                    &V {
                        rollback_index_location: *rollback_index_location,
                        partition_name,
                        public_key_sha1: pk_sha1,
                        flags: *flags,
                    },
                )?;
            }
            DescriptorInfo::Unknown {
                tag,
                num_bytes_following,
                ..
            } => {
                #[derive(Serialize)]
                struct V {
                    tag: u64,
                    num_bytes_following: u64,
                }
                map.serialize_entry(
                    "Unknown",
                    &V {
                        tag: *tag,
                        num_bytes_following: *num_bytes_following,
                    },
                )?;
            }
        }
        map.end()
    }
}

pub fn collect_image_paths(input: &Path) -> Result<Vec<PathBuf>> {
    if input.is_file() {
        return Ok(vec![input.to_path_buf()]);
    }
    if !input.is_dir() {
        return Err(DynoError::MissingFile(input.display().to_string()));
    }

    let mut files = Vec::new();
    collect_dir_images(input, &mut files)?;
    files.sort_by_cached_key(|path| path.to_string_lossy().to_lowercase());

    if files.is_empty() {
        return Err(DynoError::Tool(format!(
            "No .img files found under {}",
            input.display()
        )));
    }

    Ok(files)
}

pub fn scan_input(input: &Path) -> Result<Vec<ScanEntry>> {
    let paths = collect_image_paths(input)?;
    Ok(paths.into_iter().map(scan_one).collect())
}

/// Render multi-entry scan output.
///
/// Directory/multi-file reports intentionally keep local headers (`Image`,
/// `File size`, `AVB image type`) as JSON-era extensions. Single pure AVB
/// bodies still use dense AOSP 1.4.0 field layout.
pub fn render_scan_report(entries: &[ScanEntry]) -> String {
    render_scan_report_with_options(entries, &InfoRenderOptions::default())
}

pub fn render_scan_report_with_options(
    entries: &[ScanEntry],
    options: &InfoRenderOptions,
) -> String {
    let mut out = String::new();

    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            out.push_str("\n================================================================\n\n");
        }

        // Local multi-scan extension headers (not present in AOSP info_image).
        let _ = writeln!(out, "Image:                   {}", entry.path.display());
        let _ = writeln!(out, "File size:               {} bytes", entry.file_size);

        match &entry.result {
            ScanResult::None => {
                out.push_str("AVB image type:          none\n");
                out.push_str("No AVB metadata found.\n");
            }
            ScanResult::Error(message) => {
                out.push_str("AVB image type:          error\n");
                let _ = writeln!(out, "AVB parse error:         {message}");
            }
            ScanResult::Avb(info) => {
                let _ = writeln!(
                    out,
                    "AVB image type:          {}",
                    avb_image_type_name(&info.image_type)
                );
                out.push_str(&render_avb_info_aosp(info, entry.file_size, options));
            }
        }
    }

    out
}

/// Dense AOSP `info_image` text for a parsed AVB image.
pub fn render_avb_info_aosp(
    info: &AvbImageInfo,
    image_size: u64,
    options: &InfoRenderOptions,
) -> String {
    let mut out = String::new();

    if let Some(footer) = &info.footer {
        write_field(
            &mut out,
            "Footer version:",
            format!("{}.{}", footer.version_major, footer.version_minor),
        );
        write_field(&mut out, "Image size:", format!("{image_size} bytes"));
        write_field(
            &mut out,
            "Original image size:",
            format!("{} bytes", footer.original_image_size),
        );
        write_field(&mut out, "VBMeta offset:", footer.vbmeta_offset);
        write_field(
            &mut out,
            "VBMeta size:",
            format!("{} bytes", footer.vbmeta_size),
        );
        out.push_str("--\n");
    }

    let sparse_marker = if options.sparse { " (Sparse)" } else { "" };
    write_field(
        &mut out,
        "Minimum libavb version:",
        format!(
            "{}.{}{sparse_marker}",
            info.header.required_libavb_version_major, info.header.required_libavb_version_minor
        ),
    );
    write_field(
        &mut out,
        "Header Block:",
        format!("{AVB_VBMETA_IMAGE_HEADER_SIZE} bytes"),
    );
    write_field(
        &mut out,
        "Authentication Block:",
        format!("{} bytes", info.header.authentication_data_block_size),
    );
    write_field(
        &mut out,
        "Auxiliary Block:",
        format!("{} bytes", info.header.auxiliary_data_block_size),
    );
    if let Some(public_key_sha1) = &info.public_key_sha1 {
        write_field(&mut out, "Public key (sha1):", public_key_sha1);
    }
    write_field(&mut out, "Algorithm:", &info.algorithm_name);
    write_field(&mut out, "Rollback Index:", info.header.rollback_index);
    write_field(&mut out, "Flags:", info.header.flags);
    write_field(
        &mut out,
        "Rollback Index Location:",
        info.header.rollback_index_location,
    );
    write_field(
        &mut out,
        "Release String:",
        format!("'{}'", info.header.release_string),
    );

    out.push_str("Descriptors:\n");
    if info.descriptors.is_empty() {
        out.push_str("    (none)\n");
    } else {
        for descriptor in &info.descriptors {
            render_descriptor(&mut out, descriptor);
        }
    }

    if options.include_cert {
        match options.cert_text.as_ref() {
            Some(cert_text) if !cert_text.is_empty() => {
                if !cert_text.starts_with("avb_cert certificate:") {
                    out.push_str("avb_cert certificate:\n");
                }
                out.push_str(cert_text);
                if !cert_text.ends_with('\n') {
                    out.push('\n');
                }
            }
            _ => {}
        }
    }

    out
}

pub fn generate_info_report(input: &Path) -> Result<String> {
    generate_info_report_with_options(input, &InfoRenderOptions::default())
}

/// Generate info text with optional sparse/cert hooks.
///
/// Single AVB images emit pure AOSP dense text (no local multi-scan headers).
/// Multi-file scans keep local extension headers for directory workflows.
pub fn generate_info_report_with_options(
    input: &Path,
    options: &InfoRenderOptions,
) -> Result<String> {
    let entries = scan_input(input)?;
    if entries.len() == 1 {
        #[allow(clippy::collapsible_if)]
        if let ScanResult::Avb(info) = &entries[0].result {
            let mut render = options.clone();
            if !render.sparse
                && let Ok(handler) = ImageHandler::open(input, true)
            {
                render.sparse = handler.is_sparse();
            }
            return Ok(render_avb_info_aosp(info, entries[0].file_size, &render));
        }
    }
    let mut render = options.clone();
    if !render.sparse
        && let Ok(handler) = ImageHandler::open(input, true)
    {
        render.sparse = handler.is_sparse();
    }
    Ok(render_scan_report_with_options(&entries, &render))
}

fn write_field(out: &mut String, label: &str, value: impl std::fmt::Display) {
    // AOSP pads labels to width 26 including the trailing colon.
    let _ = writeln!(out, "{label:<26}{value}");
}

fn collect_dir_images(dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir_images(&path, files)?;
            continue;
        }
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("img"))
        {
            files.push(path);
        }
    }
    Ok(())
}

fn scan_one(path: PathBuf) -> ScanEntry {
    match ImageHandler::open(&path, true) {
        Ok(handler) => {
            let logical_size = handler.image_size();
            match inspect_image(&path, logical_size) {
                Ok(Some(info)) => ScanEntry {
                    path,
                    file_size: logical_size,
                    result: ScanResult::Avb(info),
                },
                Ok(None) => ScanEntry {
                    path,
                    file_size: logical_size,
                    result: ScanResult::None,
                },
                Err(error) => ScanEntry {
                    path,
                    file_size: logical_size,
                    result: ScanResult::Error(error.to_string()),
                },
            }
        }
        Err(error) => ScanEntry {
            path,
            file_size: 0,
            result: ScanResult::Error(error.to_string()),
        },
    }
}

fn inspect_image(path: &Path, image_size: u64) -> Result<Option<AvbImageInfo>> {
    let image_type = detect_avb_image_type(path)?;
    if image_type == AvbImageType::None {
        return Ok(None);
    }

    let mut image = ImageHandler::open(path, true).map_err(sparse_err)?;
    match image_type {
        AvbImageType::Vbmeta => {
            let header = crate::image::read_header_at(&mut image, 0)?;
            let vbmeta_size = compute_vbmeta_blob_size(&header)?;
            let blob = read_exact_at(&mut image, 0, u64_to_usize(vbmeta_size, "vbmeta size")?)?;
            let (header, parsed_vbmeta_size, public_key_sha1, descriptors) =
                parse_vbmeta_blob(&blob)?;
            let algorithm_name = lookup_algorithm_by_type(header.algorithm_type)
                .map(|a| a.name.to_string())
                .unwrap_or_else(|_| format!("UNKNOWN({})", header.algorithm_type));
            Ok(Some(AvbImageInfo {
                image_type,
                footer: None,
                vbmeta_offset: 0,
                vbmeta_size: parsed_vbmeta_size,
                header,
                algorithm_name,
                public_key_sha1,
                descriptors,
            }))
        }
        AvbImageType::Footer => {
            if image_size < AVB_FOOTER_SIZE {
                return Err(DynoError::Tool(format!(
                    "Footer image too small: {}",
                    path.display()
                )));
            }

            let footer_bytes = read_exact_at(
                &mut image,
                image_size - AVB_FOOTER_SIZE,
                AVB_FOOTER_SIZE as usize,
            )?;
            let footer = AvbFooter::from_reader(footer_bytes.as_slice())?;
            let footer_end = footer
                .vbmeta_offset
                .checked_add(footer.vbmeta_size)
                .ok_or_else(|| DynoError::Tool("VBMeta range overflow in footer".into()))?;
            if footer_end > image_size {
                return Err(DynoError::Tool(format!(
                    "VBMeta range exceeds file size in {}",
                    path.display()
                )));
            }

            let blob = read_exact_at(
                &mut image,
                footer.vbmeta_offset,
                u64_to_usize(footer.vbmeta_size, "footer vbmeta size")?,
            )?;
            let (header, _, public_key_sha1, descriptors) = parse_vbmeta_blob(&blob)?;
            let algorithm_name = lookup_algorithm_by_type(header.algorithm_type)
                .map(|a| a.name.to_string())
                .unwrap_or_else(|_| format!("UNKNOWN({})", header.algorithm_type));

            Ok(Some(AvbImageInfo {
                image_type,
                footer: Some(footer.clone()),
                vbmeta_offset: footer.vbmeta_offset,
                vbmeta_size: footer.vbmeta_size,
                header,
                algorithm_name,
                public_key_sha1,
                descriptors,
            }))
        }
        AvbImageType::None => Ok(None),
    }
}

fn parse_vbmeta_blob(
    blob: &[u8],
) -> Result<(AvbVBMetaHeader, u64, Option<String>, Vec<DescriptorInfo>)> {
    if blob.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Err(DynoError::Tool(
            "VBMeta blob smaller than header size".into(),
        ));
    }

    let header = AvbVBMetaHeader::from_reader(Cursor::new(&blob[..AVB_VBMETA_IMAGE_HEADER_SIZE]))?;
    let actual_vbmeta_size = compute_vbmeta_blob_size(&header)?;
    let actual_size_usize = u64_to_usize(actual_vbmeta_size, "actual vbmeta size")?;
    if actual_size_usize > blob.len() {
        return Err(DynoError::Tool(format!(
            "VBMeta blob truncated: need {} bytes, got {} bytes",
            actual_size_usize,
            blob.len()
        )));
    }

    let blob = &blob[..actual_size_usize];
    let auth_size = u64_to_usize(
        header.authentication_data_block_size,
        "authentication block size",
    )?;
    let aux_size = u64_to_usize(header.auxiliary_data_block_size, "auxiliary block size")?;
    let aux_start = AVB_VBMETA_IMAGE_HEADER_SIZE
        .checked_add(auth_size)
        .ok_or_else(|| DynoError::Tool("VBMeta auxiliary offset overflow".into()))?;
    let aux_end = aux_start
        .checked_add(aux_size)
        .ok_or_else(|| DynoError::Tool("VBMeta auxiliary size overflow".into()))?;
    if aux_end > blob.len() {
        return Err(DynoError::Tool(
            "VBMeta auxiliary block exceeds blob size".into(),
        ));
    }

    let aux_blob = &blob[aux_start..aux_end];
    let public_key_sha1 = if header.public_key_size > 0 {
        let range = checked_range_u64(
            aux_blob.len(),
            header.public_key_offset,
            header.public_key_size,
            "public key",
        )?;
        Some(sha1_hex(&aux_blob[range]))
    } else {
        None
    };

    let descriptor_range = checked_range_u64(
        aux_blob.len(),
        header.descriptors_offset,
        header.descriptors_size,
        "descriptors",
    )?;
    let descriptors = parse_descriptors(&aux_blob[descriptor_range])?;

    Ok((header, actual_vbmeta_size, public_key_sha1, descriptors))
}

fn parse_descriptors(data: &[u8]) -> Result<Vec<DescriptorInfo>> {
    let mut descriptors = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let remaining = &data[offset..];
        if remaining.len() < DESCRIPTOR_HEADER_SIZE {
            return Err(DynoError::Tool("Descriptor blob ends mid-header".into()));
        }

        let mut cursor = Cursor::new(&remaining[..DESCRIPTOR_HEADER_SIZE]);
        let tag = cursor.read_u64::<BigEndian>()?;
        let num_bytes_following = cursor.read_u64::<BigEndian>()?;
        let body_len = u64_to_usize(num_bytes_following, "descriptor size")?;
        if body_len % 8 != 0 {
            return Err(DynoError::Tool(format!(
                "Descriptor tag {} has non-8-byte-aligned size {}",
                tag, body_len
            )));
        }

        let total_len = DESCRIPTOR_HEADER_SIZE
            .checked_add(body_len)
            .ok_or_else(|| DynoError::Tool("Descriptor total size overflow".into()))?;
        if total_len > remaining.len() {
            return Err(DynoError::Tool(format!(
                "Descriptor tag {} truncated: need {} bytes, got {} bytes",
                tag,
                total_len,
                remaining.len()
            )));
        }

        let descriptor = &remaining[..total_len];
        descriptors.push(parse_descriptor(tag, num_bytes_following, descriptor)?);
        offset += total_len;
    }

    Ok(descriptors)
}

fn parse_descriptor(tag: u64, num_bytes_following: u64, data: &[u8]) -> Result<DescriptorInfo> {
    match tag {
        DESCRIPTOR_TAG_PROPERTY => parse_property_descriptor(num_bytes_following, data),
        DESCRIPTOR_TAG_HASHTREE => parse_hashtree_descriptor(num_bytes_following, data),
        DESCRIPTOR_TAG_HASH => parse_hash_descriptor(num_bytes_following, data),
        DESCRIPTOR_TAG_KERNEL_CMDLINE => parse_kernel_cmdline_descriptor(num_bytes_following, data),
        DESCRIPTOR_TAG_CHAIN_PARTITION => {
            parse_chain_partition_descriptor(num_bytes_following, data)
        }
        _ => Ok(DescriptorInfo::Unknown {
            tag,
            num_bytes_following,
            body: data[DESCRIPTOR_HEADER_SIZE..].to_vec(),
        }),
    }
}

fn parse_property_descriptor(num_bytes_following: u64, data: &[u8]) -> Result<DescriptorInfo> {
    ensure_len(data, PROPERTY_DESCRIPTOR_SIZE, "property descriptor")?;
    let mut cursor = Cursor::new(&data[DESCRIPTOR_HEADER_SIZE..PROPERTY_DESCRIPTOR_SIZE]);
    let key_len = cursor.read_u64::<BigEndian>()?;
    let value_len = cursor.read_u64::<BigEndian>()?;
    let expected_size = round_to_multiple(
        (PROPERTY_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE)
            + u64_to_usize(key_len, "property key length")?
            + 1
            + u64_to_usize(value_len, "property value length")?
            + 1,
        8,
    ) as u64;
    if num_bytes_following != expected_size {
        return Err(DynoError::Tool(format!(
            "Invalid property descriptor size: header says {}, expected {}",
            num_bytes_following, expected_size
        )));
    }

    let body = &data[PROPERTY_DESCRIPTOR_SIZE..];
    let key_len = u64_to_usize(key_len, "property key length")?;
    let value_len = u64_to_usize(value_len, "property value length")?;
    let key_bytes = checked_slice(body, 0, key_len, "property key")?;
    expect_byte(body, key_len, 0, "property key terminator")?;
    let value_start = key_len + 1;
    let value_bytes = checked_slice(body, value_start, value_len, "property value")?;
    expect_byte(
        body,
        value_start + value_len,
        0,
        "property value terminator",
    )?;

    let key = String::from_utf8(key_bytes.to_vec())
        .map_err(|error| DynoError::Tool(format!("Property key is not UTF-8: {}", error)))?;

    Ok(DescriptorInfo::Property {
        key,
        value: value_bytes.to_vec(),
    })
}

fn parse_hashtree_descriptor(num_bytes_following: u64, data: &[u8]) -> Result<DescriptorInfo> {
    ensure_len(data, HASHTREE_DESCRIPTOR_SIZE, "hashtree descriptor")?;
    let mut cursor = Cursor::new(&data[DESCRIPTOR_HEADER_SIZE..HASHTREE_DESCRIPTOR_SIZE]);
    let dm_verity_version = cursor.read_u32::<BigEndian>()?;
    let image_size = cursor.read_u64::<BigEndian>()?;
    let tree_offset = cursor.read_u64::<BigEndian>()?;
    let tree_size = cursor.read_u64::<BigEndian>()?;
    let data_block_size = cursor.read_u32::<BigEndian>()?;
    let hash_block_size = cursor.read_u32::<BigEndian>()?;
    let fec_num_roots = cursor.read_u32::<BigEndian>()?;
    let fec_offset = cursor.read_u64::<BigEndian>()?;
    let fec_size = cursor.read_u64::<BigEndian>()?;
    let mut hash_algorithm = [0u8; 32];
    cursor.read_exact(&mut hash_algorithm)?;
    let partition_name_len = cursor.read_u32::<BigEndian>()?;
    let salt_len = cursor.read_u32::<BigEndian>()?;
    let root_digest_len = cursor.read_u32::<BigEndian>()?;
    let flags = cursor.read_u32::<BigEndian>()?;

    let expected_size = round_to_multiple(
        (HASHTREE_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE)
            + u32_to_usize(partition_name_len, "hashtree partition name length")?
            + u32_to_usize(salt_len, "hashtree salt length")?
            + u32_to_usize(root_digest_len, "hashtree root digest length")?,
        8,
    ) as u64;
    if num_bytes_following != expected_size {
        return Err(DynoError::Tool(format!(
            "Invalid hashtree descriptor size: header says {}, expected {}",
            num_bytes_following, expected_size
        )));
    }

    let body = &data[HASHTREE_DESCRIPTOR_SIZE..];
    let partition_name_len = u32_to_usize(partition_name_len, "hashtree partition name length")?;
    let salt_len = u32_to_usize(salt_len, "hashtree salt length")?;
    let root_digest_len = u32_to_usize(root_digest_len, "hashtree root digest length")?;
    let partition_name = read_utf8(checked_slice(
        body,
        0,
        partition_name_len,
        "hashtree partition name",
    )?)?;
    let salt_start = partition_name_len;
    let salt = checked_slice(body, salt_start, salt_len, "hashtree salt")?.to_vec();
    let root_digest_start = salt_start + salt_len;
    let root_digest = checked_slice(
        body,
        root_digest_start,
        root_digest_len,
        "hashtree root digest",
    )?
    .to_vec();

    Ok(DescriptorInfo::Hashtree {
        dm_verity_version,
        image_size,
        tree_offset,
        tree_size,
        data_block_size,
        hash_block_size,
        fec_num_roots,
        fec_offset,
        fec_size,
        hash_algorithm: read_cstring_ascii(&hash_algorithm)?,
        partition_name,
        salt,
        root_digest,
        flags,
    })
}

fn parse_hash_descriptor(num_bytes_following: u64, data: &[u8]) -> Result<DescriptorInfo> {
    ensure_len(data, HASH_DESCRIPTOR_SIZE, "hash descriptor")?;
    let mut cursor = Cursor::new(&data[DESCRIPTOR_HEADER_SIZE..HASH_DESCRIPTOR_SIZE]);
    let image_size = cursor.read_u64::<BigEndian>()?;
    let mut hash_algorithm = [0u8; 32];
    cursor.read_exact(&mut hash_algorithm)?;
    let partition_name_len = cursor.read_u32::<BigEndian>()?;
    let salt_len = cursor.read_u32::<BigEndian>()?;
    let digest_len = cursor.read_u32::<BigEndian>()?;
    let flags = cursor.read_u32::<BigEndian>()?;

    let expected_size = round_to_multiple(
        (HASH_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE)
            + u32_to_usize(partition_name_len, "hash partition name length")?
            + u32_to_usize(salt_len, "hash salt length")?
            + u32_to_usize(digest_len, "hash digest length")?,
        8,
    ) as u64;
    if num_bytes_following != expected_size {
        return Err(DynoError::Tool(format!(
            "Invalid hash descriptor size: header says {}, expected {}",
            num_bytes_following, expected_size
        )));
    }

    let body = &data[HASH_DESCRIPTOR_SIZE..];
    let partition_name_len = u32_to_usize(partition_name_len, "hash partition name length")?;
    let salt_len = u32_to_usize(salt_len, "hash salt length")?;
    let digest_len = u32_to_usize(digest_len, "hash digest length")?;
    let partition_name = read_utf8(checked_slice(
        body,
        0,
        partition_name_len,
        "hash partition name",
    )?)?;
    let salt_start = partition_name_len;
    let salt = checked_slice(body, salt_start, salt_len, "hash salt")?.to_vec();
    let digest_start = salt_start + salt_len;
    let digest = checked_slice(body, digest_start, digest_len, "hash digest")?.to_vec();

    Ok(DescriptorInfo::Hash {
        image_size,
        hash_algorithm: read_cstring_ascii(&hash_algorithm)?,
        partition_name,
        salt,
        digest,
        flags,
    })
}

fn parse_kernel_cmdline_descriptor(
    num_bytes_following: u64,
    data: &[u8],
) -> Result<DescriptorInfo> {
    ensure_len(
        data,
        KERNEL_CMDLINE_DESCRIPTOR_SIZE,
        "kernel cmdline descriptor",
    )?;
    let mut cursor = Cursor::new(&data[DESCRIPTOR_HEADER_SIZE..KERNEL_CMDLINE_DESCRIPTOR_SIZE]);
    let flags = cursor.read_u32::<BigEndian>()?;
    let kernel_cmdline_length = cursor.read_u32::<BigEndian>()?;

    let expected_size = round_to_multiple(
        (KERNEL_CMDLINE_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE)
            + u32_to_usize(kernel_cmdline_length, "kernel cmdline length")?,
        8,
    ) as u64;
    if num_bytes_following != expected_size {
        return Err(DynoError::Tool(format!(
            "Invalid kernel cmdline descriptor size: header says {}, expected {}",
            num_bytes_following, expected_size
        )));
    }

    let kernel_cmdline = read_utf8(checked_slice(
        &data[KERNEL_CMDLINE_DESCRIPTOR_SIZE..],
        0,
        u32_to_usize(kernel_cmdline_length, "kernel cmdline length")?,
        "kernel cmdline",
    )?)?;

    Ok(DescriptorInfo::KernelCmdline {
        flags,
        kernel_cmdline,
    })
}

fn parse_chain_partition_descriptor(
    num_bytes_following: u64,
    data: &[u8],
) -> Result<DescriptorInfo> {
    ensure_len(
        data,
        CHAIN_PARTITION_DESCRIPTOR_SIZE,
        "chain partition descriptor",
    )?;
    let mut cursor = Cursor::new(&data[DESCRIPTOR_HEADER_SIZE..CHAIN_PARTITION_DESCRIPTOR_SIZE]);
    let rollback_index_location = cursor.read_u32::<BigEndian>()?;
    let partition_name_len = cursor.read_u32::<BigEndian>()?;
    let public_key_len = cursor.read_u32::<BigEndian>()?;
    let flags = cursor.read_u32::<BigEndian>()?;

    let expected_size = round_to_multiple(
        (CHAIN_PARTITION_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE)
            + u32_to_usize(partition_name_len, "chain partition name length")?
            + u32_to_usize(public_key_len, "chain public key length")?,
        8,
    ) as u64;
    if num_bytes_following != expected_size {
        return Err(DynoError::Tool(format!(
            "Invalid chain partition descriptor size: header says {}, expected {}",
            num_bytes_following, expected_size
        )));
    }

    let body = &data[CHAIN_PARTITION_DESCRIPTOR_SIZE..];
    let partition_name_len = u32_to_usize(partition_name_len, "chain partition name length")?;
    let public_key_len = u32_to_usize(public_key_len, "chain public key length")?;
    let partition_name = read_utf8(checked_slice(
        body,
        0,
        partition_name_len,
        "chain partition name",
    )?)?;
    let public_key = checked_slice(body, partition_name_len, public_key_len, "chain public key")?;

    Ok(DescriptorInfo::ChainPartition {
        rollback_index_location,
        partition_name,
        public_key: public_key.to_vec(),
        flags,
    })
}

fn render_descriptor(out: &mut String, descriptor: &DescriptorInfo) {
    match descriptor {
        DescriptorInfo::Property { key, value } => {
            if value.len() < 256 {
                let _ = writeln!(out, "    Prop: {key} -> {}", format_property_value(value));
            } else {
                let _ = writeln!(out, "    Prop: {key} -> ({} bytes)", value.len());
            }
        }
        DescriptorInfo::Hashtree {
            dm_verity_version,
            image_size,
            tree_offset,
            tree_size,
            data_block_size,
            hash_block_size,
            fec_num_roots,
            fec_offset,
            fec_size,
            hash_algorithm,
            partition_name,
            salt,
            root_digest,
            flags,
        } => {
            out.push_str("    Hashtree descriptor:\n");
            let _ = writeln!(out, "      Version of dm-verity:  {dm_verity_version}");
            let _ = writeln!(out, "      Image Size:            {image_size} bytes");
            let _ = writeln!(out, "      Tree Offset:           {tree_offset}");
            let _ = writeln!(out, "      Tree Size:             {tree_size} bytes");
            let _ = writeln!(out, "      Data Block Size:       {data_block_size} bytes");
            let _ = writeln!(out, "      Hash Block Size:       {hash_block_size} bytes");
            let _ = writeln!(out, "      FEC num roots:         {fec_num_roots}");
            let _ = writeln!(out, "      FEC offset:            {fec_offset}");
            let _ = writeln!(out, "      FEC size:              {fec_size} bytes");
            let _ = writeln!(out, "      Hash Algorithm:        {hash_algorithm}");
            let _ = writeln!(out, "      Partition Name:        {partition_name}");
            let _ = writeln!(out, "      Salt:                  {}", bytes_to_hex(salt));
            let _ = writeln!(
                out,
                "      Root Digest:           {}",
                bytes_to_hex(root_digest)
            );
            let _ = writeln!(out, "      Flags:                 {flags}");
        }
        DescriptorInfo::Hash {
            image_size,
            hash_algorithm,
            partition_name,
            salt,
            digest,
            flags,
        } => {
            out.push_str("    Hash descriptor:\n");
            let _ = writeln!(out, "      Image Size:            {image_size} bytes");
            let _ = writeln!(out, "      Hash Algorithm:        {hash_algorithm}");
            let _ = writeln!(out, "      Partition Name:        {partition_name}");
            let _ = writeln!(out, "      Salt:                  {}", bytes_to_hex(salt));
            let _ = writeln!(out, "      Digest:                {}", bytes_to_hex(digest));
            let _ = writeln!(out, "      Flags:                 {flags}");
        }
        DescriptorInfo::KernelCmdline {
            flags,
            kernel_cmdline,
        } => {
            out.push_str("    Kernel Cmdline descriptor:\n");
            let _ = writeln!(out, "      Flags:                 {flags}");
            let _ = writeln!(out, "      Kernel Cmdline:        '{kernel_cmdline}'");
        }
        DescriptorInfo::ChainPartition {
            rollback_index_location,
            partition_name,
            public_key,
            flags,
        } => {
            out.push_str("    Chain Partition descriptor:\n");
            let _ = writeln!(out, "      Partition Name:          {partition_name}");
            let _ = writeln!(
                out,
                "      Rollback Index Location: {rollback_index_location}"
            );
            let _ = writeln!(
                out,
                "      Public key (sha1):       {}",
                sha1_hex(public_key)
            );
            let _ = writeln!(out, "      Flags:                   {flags}");
        }
        DescriptorInfo::Unknown { tag, body, .. } => {
            out.push_str("    Unknown descriptor:\n");
            let _ = writeln!(out, "      Tag:  {tag}");
            if body.len() < 256 {
                let _ = writeln!(
                    out,
                    "      Data: {} ({} bytes)",
                    format_property_value(body),
                    body.len()
                );
            } else {
                let _ = writeln!(out, "      Data: {} bytes", body.len());
            }
        }
    }
}

fn compute_vbmeta_blob_size(header: &AvbVBMetaHeader) -> Result<u64> {
    (AVB_VBMETA_IMAGE_HEADER_SIZE as u64)
        .checked_add(header.authentication_data_block_size)
        .and_then(|size| size.checked_add(header.auxiliary_data_block_size))
        .ok_or_else(|| DynoError::Tool("VBMeta size overflow".into()))
}

fn checked_range_u64(total: usize, offset: u64, size: u64, field: &str) -> Result<Range<usize>> {
    let offset = u64_to_usize(offset, &format!("{field} offset"))?;
    let size = u64_to_usize(size, &format!("{field} size"))?;
    checked_range(total, offset, size, field)
}

fn checked_range(total: usize, offset: usize, size: usize, field: &str) -> Result<Range<usize>> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| DynoError::Tool(format!("{field} range overflow")))?;
    if end > total {
        return Err(DynoError::Tool(format!(
            "{field} range exceeds buffer: offset {offset} size {size} total {total}"
        )));
    }
    Ok(offset..end)
}

fn checked_slice<'a>(data: &'a [u8], offset: usize, size: usize, field: &str) -> Result<&'a [u8]> {
    let range = checked_range(data.len(), offset, size, field)?;
    Ok(&data[range])
}

fn expect_byte(data: &[u8], offset: usize, expected: u8, field: &str) -> Result<()> {
    let actual = data
        .get(offset)
        .copied()
        .ok_or_else(|| DynoError::Tool(format!("{field} missing at offset {offset}")))?;
    if actual != expected {
        return Err(DynoError::Tool(format!(
            "{field} invalid: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn ensure_len(data: &[u8], minimum_len: usize, field: &str) -> Result<()> {
    if data.len() < minimum_len {
        return Err(DynoError::Tool(format!(
            "{field} shorter than expected: need at least {minimum_len} bytes, got {} bytes",
            data.len()
        )));
    }
    Ok(())
}

fn read_utf8(data: &[u8]) -> Result<String> {
    String::from_utf8(data.to_vec())
        .map_err(|error| DynoError::Tool(format!("Invalid UTF-8 data: {error}")))
}

fn read_cstring_ascii(data: &[u8]) -> Result<String> {
    let len = data
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(data.len());
    let slice = &data[..len];
    let text = std::str::from_utf8(slice)
        .map_err(|error| DynoError::Tool(format!("Invalid ASCII/UTF-8 string: {error}")))?;
    Ok(text.to_string())
}

/// Format property bytes like Python `repr(bytes)` with the leading `b` removed.
fn format_property_value(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for &byte in value {
        match byte {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            0x20..=0x7e => out.push(byte as char),
            _ => {
                let _ = write!(out, "\\x{byte:02x}");
            }
        }
    }
    out.push('\'');
    out
}

fn sha1_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    bytes_to_hex(&digest)
}

fn round_to_multiple(number: usize, size: usize) -> usize {
    let remainder = number % size;
    if remainder == 0 {
        number
    } else {
        number + size - remainder
    }
}

fn u64_to_usize(value: u64, field: &str) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| DynoError::Tool(format!("{field} does not fit in usize: {value}")))
}

fn u32_to_usize(value: u32, field: &str) -> Result<usize> {
    usize::try_from(value)
        .map_err(|_| DynoError::Tool(format!("{field} does not fit in usize: {value}")))
}

fn avb_image_type_name(image_type: &AvbImageType) -> &'static str {
    match image_type {
        AvbImageType::Vbmeta => "vbmeta",
        AvbImageType::Footer => "footer",
        AvbImageType::None => "none",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use byteorder::WriteBytesExt;
    use tempfile::NamedTempFile;

    #[test]
    fn pure_vbmeta_info_matches_aosp_layout() -> Result<()> {
        let descriptor = make_hash_descriptor("boot", b"\x11\x22", &[0x33; 32])?;
        let prop = make_property_descriptor("foo", b"brillo")?;
        let vbmeta = make_vbmeta_blob(vec![prop, descriptor], b"public-key");

        let mut file = NamedTempFile::new()?;
        std::io::Write::write_all(&mut file, &vbmeta)?;

        let report = generate_info_report(file.path())?;

        // Pure single-image path: no local multi-scan headers.
        assert!(!report.contains("Image:"));
        assert!(!report.contains("AVB image type:"));
        assert!(!report.contains("File size:"));
        assert!(!report.starts_with("Footer version:"));

        let expected_prefix = format!(
            "Minimum libavb version:   1.0\n\
Header Block:             {AVB_VBMETA_IMAGE_HEADER_SIZE} bytes\n\
Authentication Block:     0 bytes\n\
Auxiliary Block:          "
        );
        assert!(
            report.starts_with(&expected_prefix),
            "report was:\n{report}"
        );
        assert!(report.contains("Public key (sha1):        "));
        assert!(report.contains("Algorithm:                NONE"));
        assert!(report.contains("Rollback Index:           7"));
        assert!(report.contains("Flags:                    0"));
        assert!(report.contains("Rollback Index Location:  0"));
        assert!(report.contains("Release String:           'unit-test'"));
        assert!(report.contains("    Prop: foo -> 'brillo'\n"));
        assert!(report.contains("    Hash descriptor:\n"));
        assert!(report.contains("      Partition Name:        boot\n"));
        assert!(report.contains("      Salt:                  1122\n"));
        Ok(())
    }

    #[test]
    fn footer_info_includes_image_size_line() -> Result<()> {
        let vbmeta = make_vbmeta_blob(Vec::new(), b"footer-key");
        let original_size = 4096u64;

        let mut image = vec![0u8; original_size as usize];
        image.extend_from_slice(&vbmeta);
        image.extend_from_slice(&make_footer(
            original_size,
            original_size,
            vbmeta.len() as u64,
        ));

        let mut file = NamedTempFile::new()?;
        std::io::Write::write_all(&mut file, &image)?;

        let report = generate_info_report(file.path())?;
        let image_size = image.len() as u64;

        assert!(!report.contains("Image:"));
        assert!(report.starts_with("Footer version:           1.0\n"));
        assert!(report.contains(&format!("Image size:               {image_size} bytes\n")));
        assert!(report.contains("Original image size:      4096 bytes\n"));
        assert!(report.contains(&format!("VBMeta offset:            {original_size}\n")));
        assert!(report.contains(&format!(
            "VBMeta size:              {} bytes\n",
            vbmeta.len()
        )));
        assert!(report.contains("--\nMinimum libavb version:   1.0\n"));
        Ok(())
    }

    #[test]
    fn property_and_unknown_descriptor_formatting() {
        let mut out = String::new();
        render_descriptor(
            &mut out,
            &DescriptorInfo::Property {
                key: "blob".into(),
                value: b"\x00\x00brillo ftw!\n".to_vec(),
            },
        );
        assert_eq!(out, "    Prop: blob -> '\\x00\\x00brillo ftw!\\n'\n");

        out.clear();
        render_descriptor(
            &mut out,
            &DescriptorInfo::Property {
                key: "large_blob".into(),
                value: vec![0u8; 2048],
            },
        );
        assert_eq!(out, "    Prop: large_blob -> (2048 bytes)\n");

        out.clear();
        render_descriptor(
            &mut out,
            &DescriptorInfo::Unknown {
                tag: 99,
                num_bytes_following: 8,
                body: b"abcd".to_vec(),
            },
        );
        assert_eq!(
            out,
            "    Unknown descriptor:\n      Tag:  99\n      Data: 'abcd' (4 bytes)\n"
        );
    }

    #[test]
    fn sparse_and_cert_hooks_are_optional() {
        let info = AvbImageInfo {
            image_type: AvbImageType::Vbmeta,
            footer: None,
            vbmeta_offset: 0,
            vbmeta_size: AVB_VBMETA_IMAGE_HEADER_SIZE as u64,
            header: crate::image::default_vbmeta_header(),
            algorithm_name: "NONE".into(),
            public_key_sha1: None,
            descriptors: Vec::new(),
        };

        let sparse = render_avb_info_aosp(
            &info,
            0,
            &InfoRenderOptions {
                sparse: true,
                include_cert: false,
                cert_text: None,
            },
        );
        assert!(sparse.contains("Minimum libavb version:   1.0 (Sparse)\n"));

        let with_cert = render_avb_info_aosp(
            &info,
            0,
            &InfoRenderOptions {
                sparse: false,
                include_cert: true,
                cert_text: Some(
                    "    Metadata version:        1\n    Product Intermediate Key:\n".into(),
                ),
            },
        );
        assert!(with_cert.contains("avb_cert certificate:\n"));
        assert!(with_cert.contains("    Metadata version:        1\n"));
    }

    #[test]
    fn scan_standalone_vbmeta_image() -> Result<()> {
        let descriptor = make_hash_descriptor("boot", b"\x11\x22", &[0x33; 32])?;
        let vbmeta = make_vbmeta_blob(vec![descriptor], b"public-key");

        let mut file = NamedTempFile::new()?;
        std::io::Write::write_all(&mut file, &vbmeta)?;

        let entries = scan_input(file.path())?;
        assert_eq!(entries.len(), 1);
        let report = render_scan_report(&entries);

        assert!(report.contains("AVB image type:          vbmeta"));
        assert!(report.contains("Hash descriptor:"));
        assert!(report.contains("Partition Name:        boot"));
        Ok(())
    }

    #[test]
    fn scan_footer_image() -> Result<()> {
        let vbmeta = make_vbmeta_blob(Vec::new(), b"footer-key");
        let original_size = 4096u64;

        let mut image = vec![0u8; original_size as usize];
        image.extend_from_slice(&vbmeta);
        image.extend_from_slice(&make_footer(
            original_size,
            original_size,
            vbmeta.len() as u64,
        ));

        let mut file = NamedTempFile::new()?;
        std::io::Write::write_all(&mut file, &image)?;

        let entries = scan_input(file.path())?;
        let report = render_scan_report(&entries);

        assert!(report.contains("AVB image type:          footer"));
        assert!(report.contains("Footer version:           1.0"));
        assert!(report.contains("Image size:               "));
        assert!(report.contains("Original image size:      4096 bytes"));
        Ok(())
    }

    fn make_vbmeta_blob(descriptors: Vec<Vec<u8>>, public_key: &[u8]) -> Vec<u8> {
        let descriptors_blob: Vec<u8> = descriptors.into_iter().flatten().collect();
        let descriptors_size = descriptors_blob.len() as u64;
        let public_key_offset = descriptors_blob.len() as u64;
        let public_key_size = public_key.len() as u64;

        let mut aux = descriptors_blob;
        aux.extend_from_slice(public_key);
        let aux_size = round_to_multiple(aux.len(), 64);
        aux.resize(aux_size, 0);

        let mut header = Vec::with_capacity(AVB_VBMETA_IMAGE_HEADER_SIZE);
        header.extend_from_slice(b"AVB0");
        header.write_u32::<BigEndian>(1).unwrap();
        header.write_u32::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(aux_size as u64).unwrap();
        header.write_u32::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(public_key_offset).unwrap();
        header.write_u64::<BigEndian>(public_key_size).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(0).unwrap();
        header.write_u64::<BigEndian>(descriptors_size).unwrap();
        header.write_u64::<BigEndian>(7).unwrap();
        header.write_u32::<BigEndian>(0).unwrap();
        header.write_u32::<BigEndian>(0).unwrap();

        let mut release = [0u8; 48];
        let release_bytes = b"unit-test";
        release[..release_bytes.len()].copy_from_slice(release_bytes);
        header.extend_from_slice(&release);
        header.resize(AVB_VBMETA_IMAGE_HEADER_SIZE, 0);

        header.extend_from_slice(&aux);
        header
    }

    fn make_hash_descriptor(partition_name: &str, salt: &[u8], digest: &[u8]) -> Result<Vec<u8>> {
        let name_bytes = partition_name.as_bytes();
        let mut descriptor = Vec::new();
        let num_bytes_following = round_to_multiple(
            (HASH_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE)
                + name_bytes.len()
                + salt.len()
                + digest.len(),
            8,
        ) as u64;

        descriptor.write_u64::<BigEndian>(DESCRIPTOR_TAG_HASH)?;
        descriptor.write_u64::<BigEndian>(num_bytes_following)?;
        descriptor.write_u64::<BigEndian>(1234)?;

        let mut hash_algorithm = [0u8; 32];
        hash_algorithm[..6].copy_from_slice(b"sha256");
        descriptor.extend_from_slice(&hash_algorithm);
        descriptor.write_u32::<BigEndian>(name_bytes.len() as u32)?;
        descriptor.write_u32::<BigEndian>(salt.len() as u32)?;
        descriptor.write_u32::<BigEndian>(digest.len() as u32)?;
        descriptor.write_u32::<BigEndian>(0)?;
        descriptor.extend_from_slice(&[0u8; 60]);
        descriptor.extend_from_slice(name_bytes);
        descriptor.extend_from_slice(salt);
        descriptor.extend_from_slice(digest);

        let total_size = DESCRIPTOR_HEADER_SIZE + (num_bytes_following as usize);
        descriptor.resize(total_size, 0);
        Ok(descriptor)
    }

    fn make_property_descriptor(key: &str, value: &[u8]) -> Result<Vec<u8>> {
        let key_bytes = key.as_bytes();
        let mut descriptor = Vec::new();
        let num_bytes_following = round_to_multiple(
            (PROPERTY_DESCRIPTOR_SIZE - DESCRIPTOR_HEADER_SIZE)
                + key_bytes.len()
                + 1
                + value.len()
                + 1,
            8,
        ) as u64;

        descriptor.write_u64::<BigEndian>(DESCRIPTOR_TAG_PROPERTY)?;
        descriptor.write_u64::<BigEndian>(num_bytes_following)?;
        descriptor.write_u64::<BigEndian>(key_bytes.len() as u64)?;
        descriptor.write_u64::<BigEndian>(value.len() as u64)?;
        descriptor.extend_from_slice(key_bytes);
        descriptor.push(0);
        descriptor.extend_from_slice(value);
        descriptor.push(0);

        let total_size = DESCRIPTOR_HEADER_SIZE + (num_bytes_following as usize);
        descriptor.resize(total_size, 0);
        Ok(descriptor)
    }

    fn make_footer(original_image_size: u64, vbmeta_offset: u64, vbmeta_size: u64) -> Vec<u8> {
        let mut footer = Vec::with_capacity(AVB_FOOTER_SIZE as usize);
        footer.extend_from_slice(b"AVBf");
        footer.write_u32::<BigEndian>(1).unwrap();
        footer.write_u32::<BigEndian>(0).unwrap();
        footer.write_u64::<BigEndian>(original_image_size).unwrap();
        footer.write_u64::<BigEndian>(vbmeta_offset).unwrap();
        footer.write_u64::<BigEndian>(vbmeta_size).unwrap();
        footer.resize(AVB_FOOTER_SIZE as usize, 0);
        footer
    }
}
