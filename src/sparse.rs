//! Android sparse image engine matching AOSP avbtool.py ImageHandler sparse semantics.
//!
//! This module is intentionally self-contained so later callers can use it instead of dense
//! `std::fs` I/O. Parsing, random-access logical reads, append, truncate/resize, and rewrite
//! of sparse images are all implemented in pure Rust.

use std::cmp::min;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Sparse image magic (`0xed26ff3a`).
pub const SPARSE_MAGIC: u32 = 0xed26_ff3a;
/// Supported major version.
pub const SPARSE_MAJOR_VERSION: u16 = 1;
/// Supported minor version.
pub const SPARSE_MINOR_VERSION: u16 = 0;
/// Sparse file header size in bytes.
pub const SPARSE_HEADER_SIZE: usize = 28;
/// Sparse chunk header size in bytes.
pub const CHUNK_HEADER_SIZE: usize = 12;
/// Default Android sparse block size.
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;
/// Bounded write size used when materializing dense fill ranges on disk.
const DENSE_FILL_WRITE_CHUNK: usize = 64 * 1024;

/// Chunk type identifiers from sparse_format.h / avbtool.ImageChunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ChunkType {
    /// Raw data chunk.
    Raw = 0xcac1,
    /// Fill pattern chunk.
    Fill = 0xcac2,
    /// Don't-care (zero) chunk.
    DontCare = 0xcac3,
    /// CRC32 chunk (structurally validated only).
    Crc32 = 0xcac4,
}

impl ChunkType {
    fn from_u16(value: u16) -> Result<Self, SparseError> {
        match value {
            0xcac1 => Ok(Self::Raw),
            0xcac2 => Ok(Self::Fill),
            0xcac3 => Ok(Self::DontCare),
            0xcac4 => Ok(Self::Crc32),
            other => Err(SparseError::UnknownChunkType(other)),
        }
    }

    fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Errors produced while parsing or mutating Android sparse images.
#[derive(Debug)]
pub enum SparseError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// Unsupported sparse version.
    UnsupportedVersion {
        /// Major version from the header.
        major: u16,
        /// Minor version from the header.
        minor: u16,
    },
    /// Unexpected sparse file header size.
    UnexpectedFileHeaderSize(u16),
    /// Unexpected sparse chunk header size.
    UnexpectedChunkHeaderSize(u16),
    /// Unknown chunk type value.
    UnknownChunkType(u16),
    /// Malformed chunk payload size.
    InvalidChunkPayload {
        /// Chunk type that failed validation.
        chunk_type: ChunkType,
        /// Declared data size after the chunk header.
        data_size: u32,
        /// Expected data size for this chunk type.
        expected: u32,
    },
    /// Header total blocks did not match the sum of chunk sizes.
    BlockCountMismatch {
        /// `total_blocks` from the sparse header.
        header_blocks: u32,
        /// Sum of `chunk_sz` values observed while parsing.
        observed_blocks: u32,
    },
    /// Trailing junk after the last sparse chunk.
    TrailingData(u64),
    /// Truncated or incomplete sparse stream.
    TruncatedData {
        /// Human-readable context.
        context: &'static str,
        /// Bytes requested.
        needed: usize,
        /// Bytes actually available.
        available: usize,
    },
    /// Arithmetic overflow while validating sizes/offsets.
    Overflow(&'static str),
    /// Operation requires a sparse image, but the buffer is dense/non-sparse.
    NotSparse,
    /// Operation is invalid for the current image state.
    InvalidOperation(String),
}

impl fmt::Display for SparseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "sparse I/O error: {err}"),
            Self::UnsupportedVersion { major, minor } => write!(
                f,
                "encountered sparse image format version {major}.{minor} but only 1.0 is supported"
            ),
            Self::UnexpectedFileHeaderSize(size) => {
                write!(f, "unexpected file_hdr_sz value {size}")
            }
            Self::UnexpectedChunkHeaderSize(size) => {
                write!(f, "unexpected chunk_hdr_sz value {size}")
            }
            Self::UnknownChunkType(value) => write!(f, "unknown chunk type {value}"),
            Self::InvalidChunkPayload {
                chunk_type,
                data_size,
                expected,
            } => write!(
                f,
                "invalid {chunk_type:?} chunk payload size {data_size}, expected {expected}"
            ),
            Self::BlockCountMismatch {
                header_blocks,
                observed_blocks,
            } => write!(
                f,
                "the header said we should have {header_blocks} output blocks, but we saw {observed_blocks}"
            ),
            Self::TrailingData(len) => write!(
                f,
                "there were {len} bytes of extra data at the end of the file"
            ),
            Self::TruncatedData {
                context,
                needed,
                available,
            } => write!(
                f,
                "truncated sparse data while reading {context}: needed {needed} bytes, got {available}"
            ),
            Self::Overflow(context) => write!(f, "size overflow while {context}"),
            Self::NotSparse => write!(f, "image is not an Android sparse image"),
            Self::InvalidOperation(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SparseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for SparseError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Result alias for sparse operations.
pub type SparseResult<T> = Result<T, SparseError>;

/// Parsed sparse file header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseHeader {
    /// Magic number.
    pub magic: u32,
    /// Major version.
    pub major_version: u16,
    /// Minor version.
    pub minor_version: u16,
    /// File header size.
    pub file_hdr_sz: u16,
    /// Chunk header size.
    pub chunk_hdr_sz: u16,
    /// Logical block size in bytes.
    pub block_size: u32,
    /// Total number of output blocks.
    pub total_blocks: u32,
    /// Total number of chunks (including CRC32 chunks).
    pub total_chunks: u32,
    /// Image checksum field from the header (not validated by avbtool).
    pub image_checksum: u32,
}

impl SparseHeader {
    fn new(block_size: u32, total_blocks: u32, total_chunks: u32) -> Self {
        Self {
            magic: SPARSE_MAGIC,
            major_version: SPARSE_MAJOR_VERSION,
            minor_version: SPARSE_MINOR_VERSION,
            file_hdr_sz: SPARSE_HEADER_SIZE as u16,
            chunk_hdr_sz: CHUNK_HEADER_SIZE as u16,
            block_size,
            total_blocks,
            total_chunks,
            image_checksum: 0,
        }
    }

    fn encode(&self) -> [u8; SPARSE_HEADER_SIZE] {
        let mut out = [0u8; SPARSE_HEADER_SIZE];
        write_u32_le(&mut out[0..4], self.magic);
        write_u16_le(&mut out[4..6], self.major_version);
        write_u16_le(&mut out[6..8], self.minor_version);
        write_u16_le(&mut out[8..10], self.file_hdr_sz);
        write_u16_le(&mut out[10..12], self.chunk_hdr_sz);
        write_u32_le(&mut out[12..16], self.block_size);
        write_u32_le(&mut out[16..20], self.total_blocks);
        write_u32_le(&mut out[20..24], self.total_chunks);
        write_u32_le(&mut out[24..28], self.image_checksum);
        out
    }

    fn decode(bytes: &[u8]) -> SparseResult<Self> {
        if bytes.len() < SPARSE_HEADER_SIZE {
            return Err(SparseError::TruncatedData {
                context: "sparse header",
                needed: SPARSE_HEADER_SIZE,
                available: bytes.len(),
            });
        }
        Ok(Self {
            magic: read_u32_le(&bytes[0..4]),
            major_version: read_u16_le(&bytes[4..6]),
            minor_version: read_u16_le(&bytes[6..8]),
            file_hdr_sz: read_u16_le(&bytes[8..10]),
            chunk_hdr_sz: read_u16_le(&bytes[10..12]),
            block_size: read_u32_le(&bytes[12..16]),
            total_blocks: read_u32_le(&bytes[16..20]),
            total_chunks: read_u32_le(&bytes[20..24]),
            image_checksum: read_u32_le(&bytes[24..28]),
        })
    }
}

/// A sparse chunk after parsing. CRC32 chunks are retained structurally so rewrites can
/// preserve them, but they do not contribute logical output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparseChunk {
    /// Raw logical data.
    Raw {
        /// Logical output size in bytes.
        output_size: u64,
        /// Payload bytes.
        data: Vec<u8>,
    },
    /// Repeated 4-byte fill pattern.
    Fill {
        /// Logical output size in bytes.
        output_size: u64,
        /// Four-byte fill pattern.
        fill: [u8; 4],
    },
    /// Don't-care (reads as zeroes).
    DontCare {
        /// Logical output size in bytes.
        output_size: u64,
    },
    /// Structural CRC32 chunk.
    Crc32 {
        /// Four-byte CRC payload from the sparse stream.
        crc: [u8; 4],
    },
}

impl SparseChunk {
    fn output_size(&self) -> u64 {
        match self {
            Self::Raw { output_size, .. }
            | Self::Fill { output_size, .. }
            | Self::DontCare { output_size } => *output_size,
            Self::Crc32 { .. } => 0,
        }
    }

    fn block_count(&self, block_size: u32) -> SparseResult<u32> {
        let output_size = self.output_size();
        if output_size == 0 {
            return Ok(0);
        }
        if block_size == 0 {
            return Err(SparseError::InvalidOperation(
                "block size must be non-zero".into(),
            ));
        }
        if !output_size.is_multiple_of(u64::from(block_size)) {
            return Err(SparseError::InvalidOperation(format!(
                "chunk output size {output_size} is not a multiple of block size {block_size}"
            )));
        }
        u32::try_from(output_size / u64::from(block_size))
            .map_err(|_| SparseError::Overflow("converting chunk block count to u32"))
    }
}

/// In-memory Android sparse image with random-access logical I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SparseImage {
    block_size: u32,
    chunks: Vec<SparseChunk>,
    cursor: u64,
}

impl SparseImage {
    /// Creates an empty sparse image with the given block size.
    ///
    /// # Errors
    ///
    /// Returns an error if `block_size` is zero.
    pub fn new(block_size: u32) -> SparseResult<Self> {
        if block_size == 0 {
            return Err(SparseError::InvalidOperation(
                "block size must be non-zero".into(),
            ));
        }
        Ok(Self {
            block_size,
            chunks: Vec::new(),
            cursor: 0,
        })
    }

    /// Returns `true` when `data` starts with the Android sparse magic.
    pub fn looks_sparse(data: &[u8]) -> bool {
        data.len() >= 4 && read_u32_le(&data[0..4]) == SPARSE_MAGIC
    }

    /// Parses a sparse image from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for non-sparse input or malformed sparse data.
    pub fn parse(data: &[u8]) -> SparseResult<Self> {
        if !Self::looks_sparse(data) {
            return Err(SparseError::NotSparse);
        }
        let header = SparseHeader::decode(data)?;
        if header.major_version != SPARSE_MAJOR_VERSION
            || header.minor_version != SPARSE_MINOR_VERSION
        {
            return Err(SparseError::UnsupportedVersion {
                major: header.major_version,
                minor: header.minor_version,
            });
        }
        if header.file_hdr_sz as usize != SPARSE_HEADER_SIZE {
            return Err(SparseError::UnexpectedFileHeaderSize(header.file_hdr_sz));
        }
        if header.chunk_hdr_sz as usize != CHUNK_HEADER_SIZE {
            return Err(SparseError::UnexpectedChunkHeaderSize(header.chunk_hdr_sz));
        }
        if header.block_size == 0 {
            return Err(SparseError::InvalidOperation(
                "block size must be non-zero".into(),
            ));
        }

        let mut offset = SPARSE_HEADER_SIZE;
        let mut chunks = Vec::with_capacity(header.total_chunks as usize);
        let mut observed_blocks: u32 = 0;

        for _ in 0..header.total_chunks {
            if data.len() < offset + CHUNK_HEADER_SIZE {
                return Err(SparseError::TruncatedData {
                    context: "chunk header",
                    needed: CHUNK_HEADER_SIZE,
                    available: data.len().saturating_sub(offset),
                });
            }
            let chunk_type = ChunkType::from_u16(read_u16_le(&data[offset..offset + 2]))?;
            let chunk_sz = read_u32_le(&data[offset + 4..offset + 8]);
            let total_sz = read_u32_le(&data[offset + 8..offset + 12]);
            if (total_sz as usize) < CHUNK_HEADER_SIZE {
                return Err(SparseError::InvalidOperation(format!(
                    "chunk total size {total_sz} is smaller than chunk header"
                )));
            }
            let data_sz = total_sz as usize - CHUNK_HEADER_SIZE;
            offset += CHUNK_HEADER_SIZE;

            let payload_end = offset
                .checked_add(data_sz)
                .ok_or(SparseError::Overflow("computing chunk payload end"))?;
            if data.len() < payload_end {
                return Err(SparseError::TruncatedData {
                    context: "chunk payload",
                    needed: data_sz,
                    available: data.len().saturating_sub(offset),
                });
            }
            let payload = &data[offset..payload_end];
            let output_size = mul_u32_to_u64(chunk_sz, header.block_size)?;

            match chunk_type {
                ChunkType::Raw => {
                    if data_sz as u64 != output_size {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: u32::try_from(output_size).unwrap_or(u32::MAX),
                        });
                    }
                    chunks.push(SparseChunk::Raw {
                        output_size,
                        data: payload.to_vec(),
                    });
                }
                ChunkType::Fill => {
                    if data_sz != 4 {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: 4,
                        });
                    }
                    let mut fill = [0u8; 4];
                    fill.copy_from_slice(payload);
                    chunks.push(SparseChunk::Fill { output_size, fill });
                }
                ChunkType::DontCare => {
                    if data_sz != 0 {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: 0,
                        });
                    }
                    chunks.push(SparseChunk::DontCare { output_size });
                }
                ChunkType::Crc32 => {
                    if data_sz != 4 {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: 4,
                        });
                    }
                    if chunk_sz != 0 {
                        return Err(SparseError::InvalidOperation(
                            "CRC32 chunk must have zero output blocks".into(),
                        ));
                    }
                    let mut crc = [0u8; 4];
                    crc.copy_from_slice(payload);
                    chunks.push(SparseChunk::Crc32 { crc });
                }
            }

            observed_blocks = observed_blocks
                .checked_add(chunk_sz)
                .ok_or(SparseError::Overflow("summing observed blocks"))?;
            offset = payload_end;
        }

        if observed_blocks != header.total_blocks {
            return Err(SparseError::BlockCountMismatch {
                header_blocks: header.total_blocks,
                observed_blocks,
            });
        }
        if offset != data.len() {
            return Err(SparseError::TrailingData((data.len() - offset) as u64));
        }

        Ok(Self {
            block_size: header.block_size,
            chunks,
            cursor: 0,
        })
    }

    /// Detects whether `data` is sparse and parses it when it is.
    ///
    /// # Errors
    ///
    /// Returns an error when sparse magic is present but the image is malformed.
    pub fn try_parse(data: &[u8]) -> SparseResult<Option<Self>> {
        if !Self::looks_sparse(data) {
            return Ok(None);
        }
        Self::parse(data).map(Some)
    }

    /// Logical image size in bytes (unsparsified size).
    pub fn image_size(&self) -> u64 {
        self.chunks.iter().map(SparseChunk::output_size).sum()
    }

    /// Block size used by this sparse image.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Returns a view of the parsed chunks.
    pub fn chunks(&self) -> &[SparseChunk] {
        &self.chunks
    }

    /// Sets the logical read cursor, matching ImageHandler.seek.
    pub fn seek_logical(&mut self, offset: u64) {
        self.cursor = offset;
    }

    /// Returns the logical read cursor.
    pub fn tell(&self) -> u64 {
        self.cursor
    }

    /// Reads up to `buf.len()` logical bytes from the current cursor into `buf`, advancing
    /// the cursor. Returns the number of bytes read (may be short at EOF).
    ///
    /// # Errors
    ///
    /// Returns an error if the sparse image state is inconsistent.
    pub fn read_logical_cursor(&mut self, buf: &mut [u8]) -> SparseResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let image_size = self.image_size();
        if self.cursor >= image_size {
            return Ok(0);
        }

        let to_read = min(buf.len() as u64, image_size - self.cursor) as usize;
        self.read_at(self.cursor, &mut buf[..to_read])?;
        self.cursor += to_read as u64;
        Ok(to_read)
    }

    /// Reads exactly `buf.len()` logical bytes at `offset` without moving the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested range exceeds the logical image size or the
    /// image state is inconsistent.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> SparseResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(SparseError::Overflow("computing logical read end"))?;
        if end > self.image_size() {
            return Err(SparseError::InvalidOperation(format!(
                "logical read range {offset}..{end} exceeds image size {}",
                self.image_size()
            )));
        }

        let mut logical = 0u64;
        let mut written = 0usize;
        let mut remaining = buf.len();
        let mut pos = offset;

        for chunk in &self.chunks {
            let chunk_size = chunk.output_size();
            if chunk_size == 0 {
                continue;
            }
            let chunk_end = logical
                .checked_add(chunk_size)
                .ok_or(SparseError::Overflow("computing chunk logical end"))?;
            if pos >= chunk_end {
                logical = chunk_end;
                continue;
            }

            while remaining > 0 && pos < chunk_end {
                let into_chunk = pos - logical;
                let available = (chunk_size - into_chunk) as usize;
                let take = min(available, remaining);
                let dst = &mut buf[written..written + take];
                fill_from_chunk(chunk, into_chunk, dst)?;
                written += take;
                remaining -= take;
                pos += take as u64;
            }

            if remaining == 0 {
                break;
            }
            logical = chunk_end;
        }

        if remaining != 0 {
            return Err(SparseError::InvalidOperation(
                "failed to satisfy logical read from sparse chunks".into(),
            ));
        }
        Ok(())
    }

    /// Convenience helper that allocates and returns a logical slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested range is out of bounds.
    pub fn read_logical(&self, offset: u64, size: usize) -> SparseResult<Vec<u8>> {
        let mut buf = vec![0u8; size];
        self.read_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// Appends a RAW chunk.
    ///
    /// When `require_block_multiple` is true (avbtool default), `data.len()` must be a
    /// multiple of the block size.
    ///
    /// # Errors
    ///
    /// Returns an error if size constraints fail.
    pub fn append_raw(&mut self, data: &[u8], require_block_multiple: bool) -> SparseResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        if require_block_multiple && !(data.len() as u64).is_multiple_of(u64::from(self.block_size))
        {
            return Err(SparseError::InvalidOperation(format!(
                "raw data length {} is not a multiple of block size {}",
                data.len(),
                self.block_size
            )));
        }
        self.chunks.push(SparseChunk::Raw {
            output_size: data.len() as u64,
            data: data.to_vec(),
        });
        Ok(())
    }

    /// Appends a FILL chunk with a 4-byte pattern covering `size` logical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `size` is not a multiple of 4 and the block size.
    pub fn append_fill(&mut self, fill: [u8; 4], size: u64) -> SparseResult<()> {
        if size == 0 {
            return Ok(());
        }
        if !size.is_multiple_of(4) {
            return Err(SparseError::InvalidOperation(format!(
                "fill size {size} is not a multiple of 4"
            )));
        }
        if !size.is_multiple_of(u64::from(self.block_size)) {
            return Err(SparseError::InvalidOperation(format!(
                "fill size {size} is not a multiple of block size {}",
                self.block_size
            )));
        }
        self.chunks.push(SparseChunk::Fill {
            output_size: size,
            fill,
        });
        Ok(())
    }

    /// Appends a DONT_CARE chunk covering `size` logical bytes (reads as zeroes).
    ///
    /// # Errors
    ///
    /// Returns an error if `size` is not a multiple of the block size.
    pub fn append_dont_care(&mut self, size: u64) -> SparseResult<()> {
        if size == 0 {
            return Ok(());
        }
        if !size.is_multiple_of(u64::from(self.block_size)) {
            return Err(SparseError::InvalidOperation(format!(
                "dont-care size {size} is not a multiple of block size {}",
                self.block_size
            )));
        }
        self.chunks
            .push(SparseChunk::DontCare { output_size: size });
        Ok(())
    }

    /// Truncates or grows the logical image to `size`.
    ///
    /// Behavior mirrors ImageHandler.truncate for sparse images:
    /// - `size` must be a multiple of the block size
    /// - shrinking may split the final retained chunk
    /// - growing appends a DONT_CARE range
    ///
    /// # Errors
    ///
    /// Returns an error if `size` is not block-aligned or the image cannot be rewritten.
    pub fn truncate(&mut self, size: u64) -> SparseResult<()> {
        if !size.is_multiple_of(u64::from(self.block_size)) {
            return Err(SparseError::InvalidOperation(
                "cannot truncate to a size which is not a multiple of the block size".into(),
            ));
        }

        let image_size = self.image_size();
        if size == image_size {
            return Ok(());
        }

        if size > image_size {
            return self.append_dont_care(size - image_size);
        }

        while matches!(self.chunks.last(), Some(SparseChunk::Crc32 { .. })) {
            self.chunks.pop();
        }

        let mut logical = 0u64;
        let mut keep_upto = 0usize;
        let mut split: Option<SparseChunk> = None;

        for (idx, chunk) in self.chunks.iter().enumerate() {
            let chunk_size = chunk.output_size();
            if chunk_size == 0 {
                keep_upto = idx + 1;
                continue;
            }
            let chunk_end = logical
                .checked_add(chunk_size)
                .ok_or(SparseError::Overflow("computing truncate boundary"))?;

            if size <= logical {
                break;
            }

            if size == chunk_end {
                keep_upto = idx + 1;
                break;
            }

            if size < chunk_end {
                let keep = size - logical;
                split = Some(truncate_chunk(chunk, keep)?);
                keep_upto = idx;
                break;
            }

            keep_upto = idx + 1;
            logical = chunk_end;
        }

        self.chunks.truncate(keep_upto);
        if let Some(chunk) = split {
            self.chunks.push(chunk);
        }

        if self.cursor > size {
            self.cursor = size;
        }
        Ok(())
    }

    /// Alias for [`truncate`](Self::truncate).
    pub fn resize(&mut self, size: u64) -> SparseResult<()> {
        self.truncate(size)
    }

    /// Serializes this image into a valid Android sparse byte stream.
    ///
    /// # Errors
    ///
    /// Returns an error if chunk sizes cannot be encoded into the sparse header fields.
    pub fn to_sparse_bytes(&self) -> SparseResult<Vec<u8>> {
        let mut total_blocks: u32 = 0;
        let mut total_chunks: u32 = 0;
        let mut body = Vec::new();

        for chunk in &self.chunks {
            let chunk_sz = chunk.block_count(self.block_size)?;
            let (chunk_type, payload) = match chunk {
                SparseChunk::Raw { data, .. } => (ChunkType::Raw, data.as_slice()),
                SparseChunk::Fill { fill, .. } => (ChunkType::Fill, fill.as_slice()),
                SparseChunk::DontCare { .. } => (ChunkType::DontCare, &[][..]),
                SparseChunk::Crc32 { crc } => (ChunkType::Crc32, crc.as_slice()),
            };

            let total_sz = (CHUNK_HEADER_SIZE as u32)
                .checked_add(payload.len() as u32)
                .ok_or(SparseError::Overflow("encoding chunk total size"))?;

            let mut header = [0u8; CHUNK_HEADER_SIZE];
            write_u16_le(&mut header[0..2], chunk_type.as_u16());
            write_u16_le(&mut header[2..4], 0);
            write_u32_le(&mut header[4..8], chunk_sz);
            write_u32_le(&mut header[8..12], total_sz);
            body.extend_from_slice(&header);
            body.extend_from_slice(payload);

            total_blocks = total_blocks
                .checked_add(chunk_sz)
                .ok_or(SparseError::Overflow("encoding total blocks"))?;
            total_chunks = total_chunks
                .checked_add(1)
                .ok_or(SparseError::Overflow("encoding total chunks"))?;
        }

        let header = SparseHeader::new(self.block_size, total_blocks, total_chunks);
        let mut out = Vec::with_capacity(SPARSE_HEADER_SIZE + body.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Rewrites the image as sparse bytes, preserving logical content.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn rewrite(&self) -> SparseResult<Vec<u8>> {
        self.to_sparse_bytes()
    }

    /// Materializes the full logical (unsparsified) image into a dense byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error if the logical size does not fit in memory/`usize`.
    pub fn to_dense_bytes(&self) -> SparseResult<Vec<u8>> {
        let size = usize::try_from(self.image_size())
            .map_err(|_| SparseError::Overflow("materializing dense image into usize"))?;
        let mut out = vec![0u8; size];
        self.read_at(0, &mut out)?;
        Ok(out)
    }
}

impl Read for SparseImage {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_logical_cursor(buf).map_err(sparse_to_io)
    }
}

impl Seek for SparseImage {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(delta) => {
                let end = i128::from(self.image_size());
                let next = end + i128::from(delta);
                if next < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start of sparse image",
                    ));
                }
                u64::try_from(next)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek overflow"))?
            }
            SeekFrom::Current(delta) => {
                let cur = i128::from(self.cursor);
                let next = cur + i128::from(delta);
                if next < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start of sparse image",
                    ));
                }
                u64::try_from(next)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "seek overflow"))?
            }
        };
        self.cursor = new_pos;
        Ok(self.cursor)
    }
}

/// Writes sparse bytes produced by [`SparseImage::to_sparse_bytes`] into any `Write`.
///
/// # Errors
///
/// Returns an error if serialization or writing fails.
pub fn write_sparse_image<W: Write>(image: &SparseImage, mut writer: W) -> SparseResult<()> {
    let bytes = image.to_sparse_bytes()?;
    writer.write_all(&bytes)?;
    Ok(())
}

/// Parses sparse content from a seekable reader.
///
/// # Errors
///
/// Returns an error if reading or parsing fails.
pub fn parse_sparse_reader<R: Read + Seek>(mut reader: R) -> SparseResult<SparseImage> {
    reader.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    SparseImage::parse(&data)
}

/// Indexed sparse chunk metadata. Payload bytes stay on disk for RAW chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IndexedChunk {
    chunk_type: ChunkType,
    /// File offset of this chunk's header.
    chunk_offset: u64,
    /// Logical (unsparsified) output offset.
    output_offset: u64,
    /// Logical output size in bytes.
    output_size: u64,
    /// File offset of RAW payload, if any.
    input_offset: Option<u64>,
    /// FILL pattern, if any.
    fill_data: Option<[u8; 4]>,
}

/// Snapshot used to roll back a failed sparse/dense mutation when feasible.
#[derive(Debug, Clone)]
struct ImageMutationSnapshot {
    file_len: u64,
    is_sparse: bool,
    block_size: u32,
    image_size: u64,
    num_total_blocks: u32,
    num_total_chunks: u32,
    sparse_end: u64,
    header_total_blocks_bytes: Option<[u8; 8]>,
}

/// File-backed image I/O matching AOSP `avbtool.py` `ImageHandler`.
///
/// Opens a path read-only or read-write, auto-detects dense vs Android sparse,
/// and indexes sparse chunks by file offsets without loading RAW payloads.
///
/// Sparse mutations update on-disk headers/chunks directly. Failed mutations
/// restore the previous file length (and sparse header counters when possible).
#[derive(Debug)]
pub struct ImageHandler {
    filename: PathBuf,
    file: File,
    read_only: bool,
    is_sparse: bool,
    block_size: u32,
    image_size: u64,
    file_pos: u64,
    num_total_blocks: u32,
    num_total_chunks: u32,
    sparse_end: u64,
    chunks: Vec<IndexedChunk>,
    chunk_output_offsets: Vec<u64>,
}

impl ImageHandler {
    /// Opens `path` and prepares dense or sparse image access.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or sparse content is malformed.
    pub fn open(path: impl AsRef<Path>, read_only: bool) -> SparseResult<Self> {
        let filename = path.as_ref().to_path_buf();
        let file = if read_only {
            OpenOptions::new().read(true).open(&filename)?
        } else {
            OpenOptions::new().read(true).write(true).open(&filename)?
        };

        let mut handler = Self {
            filename,
            file,
            read_only,
            is_sparse: false,
            block_size: DEFAULT_BLOCK_SIZE,
            image_size: 0,
            file_pos: 0,
            num_total_blocks: 0,
            num_total_chunks: 0,
            sparse_end: 0,
            chunks: Vec::new(),
            chunk_output_offsets: Vec::new(),
        };
        handler.read_header()?;
        Ok(handler)
    }

    /// Path used to open this handler.
    pub fn filename(&self) -> &Path {
        &self.filename
    }

    /// Whether the file is an Android sparse image.
    pub fn is_sparse(&self) -> bool {
        self.is_sparse
    }

    /// Block size used by this image (default 4096 for dense files).
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Logical unsparsified image size in bytes.
    pub fn image_size(&self) -> u64 {
        self.image_size
    }

    /// Logical read cursor.
    pub fn tell(&self) -> u64 {
        self.file_pos
    }

    /// Sets the logical read cursor from the start of the unsparsified image.
    ///
    /// # Errors
    ///
    /// Returns an error only for API symmetry; `offset` is always non-negative as `u64`.
    pub fn seek(&mut self, offset: u64) -> SparseResult<()> {
        self.file_pos = offset;
        Ok(())
    }

    /// Reads up to `size` logical bytes from the current cursor.
    ///
    /// May return fewer than `size` bytes at EOF (partial read semantics).
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failure or inconsistent sparse metadata.
    pub fn read(&mut self, size: usize) -> SparseResult<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }

        if !self.is_sparse {
            self.file.seek(SeekFrom::Start(self.file_pos))?;
            let mut buf = vec![0u8; size];
            let n = self.file.read(&mut buf)?;
            buf.truncate(n);
            self.file_pos = self
                .file_pos
                .checked_add(n as u64)
                .ok_or(SparseError::Overflow("advancing dense read cursor"))?;
            return Ok(buf);
        }

        if self.chunks.is_empty() || self.file_pos >= self.image_size {
            return Ok(Vec::new());
        }

        // bisect_right(chunk_output_offsets, file_pos) - 1
        let mut chunk_idx = self
            .chunk_output_offsets
            .partition_point(|&off| off <= self.file_pos)
            .saturating_sub(1);
        let mut data = Vec::with_capacity(size);
        let mut to_go = size;

        while to_go > 0 {
            if chunk_idx >= self.chunks.len() {
                break;
            }
            let chunk = self.chunks[chunk_idx].clone();
            if self.file_pos < chunk.output_offset {
                return Err(SparseError::InvalidOperation(
                    "sparse read cursor is before the selected chunk".into(),
                ));
            }
            let chunk_pos_offset = self.file_pos - chunk.output_offset;
            if chunk_pos_offset >= chunk.output_size {
                chunk_idx += 1;
                continue;
            }
            let chunk_pos_to_go = min((chunk.output_size - chunk_pos_offset) as usize, to_go);

            match chunk.chunk_type {
                ChunkType::Raw => {
                    let input_offset = chunk.input_offset.ok_or_else(|| {
                        SparseError::InvalidOperation("RAW chunk missing input offset".into())
                    })?;
                    let abs = input_offset
                        .checked_add(chunk_pos_offset)
                        .ok_or(SparseError::Overflow("computing raw payload read offset"))?;
                    self.file.seek(SeekFrom::Start(abs))?;
                    let start = data.len();
                    data.resize(start + chunk_pos_to_go, 0);
                    self.file.read_exact(&mut data[start..])?;
                }
                ChunkType::Fill => {
                    let fill = chunk.fill_data.ok_or_else(|| {
                        SparseError::InvalidOperation("FILL chunk missing fill pattern".into())
                    })?;
                    let start_mod = (chunk_pos_offset % 4) as usize;
                    for i in 0..chunk_pos_to_go {
                        data.push(fill[(start_mod + i) % 4]);
                    }
                }
                ChunkType::DontCare => {
                    data.resize(data.len() + chunk_pos_to_go, 0);
                }
                ChunkType::Crc32 => {
                    return Err(SparseError::InvalidOperation(
                        "CRC32 chunks are not part of the logical sparse map".into(),
                    ));
                }
            }

            to_go -= chunk_pos_to_go;
            self.file_pos = self
                .file_pos
                .checked_add(chunk_pos_to_go as u64)
                .ok_or(SparseError::Overflow("advancing sparse read cursor"))?;
            chunk_idx += 1;
        }

        Ok(data)
    }

    /// Appends a DONT_CARE range of `num_bytes` logical bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the handler is read-only, sizes are invalid, or the update fails.
    pub fn append_dont_care(&mut self, num_bytes: u64) -> SparseResult<()> {
        self.ensure_writable()?;
        if num_bytes == 0 {
            return Ok(());
        }
        if !num_bytes.is_multiple_of(u64::from(self.block_size)) {
            return Err(SparseError::InvalidOperation(format!(
                "dont-care size {num_bytes} is not a multiple of block size {}",
                self.block_size
            )));
        }

        if !self.is_sparse {
            let snapshot = self.snapshot_for_mutation()?;
            let result = (|| {
                let end = self.file.seek(SeekFrom::End(0))?;
                let new_len = end.checked_add(num_bytes).ok_or(SparseError::Overflow(
                    "extending dense image with dont-care",
                ))?;
                self.file.set_len(new_len)?;
                self.read_header()
            })();
            return self.finish_mutation(snapshot, result);
        }

        let blocks = u32::try_from(num_bytes / u64::from(self.block_size))
            .map_err(|_| SparseError::Overflow("dont-care block count to u32"))?;
        self.append_sparse_chunk(ChunkType::DontCare, blocks, &[])
    }

    /// Appends a RAW range.
    ///
    /// When `multiple_block_size` is true (avbtool default), `data.len()` must be a multiple
    /// of the block size.
    ///
    /// # Errors
    ///
    /// Returns an error if the handler is read-only, sizes are invalid, or the update fails.
    pub fn append_raw(&mut self, data: &[u8], multiple_block_size: bool) -> SparseResult<()> {
        self.ensure_writable()?;
        if data.is_empty() {
            return Ok(());
        }
        if multiple_block_size && !(data.len() as u64).is_multiple_of(u64::from(self.block_size)) {
            return Err(SparseError::InvalidOperation(format!(
                "raw data length {} is not a multiple of block size {}",
                data.len(),
                self.block_size
            )));
        }

        if !self.is_sparse {
            let snapshot = self.snapshot_for_mutation()?;
            let result = (|| {
                self.file.seek(SeekFrom::End(0))?;
                self.file.write_all(data)?;
                self.file.flush()?;
                self.read_header()
            })();
            return self.finish_mutation(snapshot, result);
        }

        // Match upstream integer division for chunk_sz when multiple_block_size is false.
        let blocks = u32::try_from(data.len() as u64 / u64::from(self.block_size))
            .map_err(|_| SparseError::Overflow("raw block count to u32"))?;
        self.append_sparse_chunk(ChunkType::Raw, blocks, data)
    }

    /// Appends a FILL range covering `size` logical bytes with a 4-byte pattern.
    ///
    /// # Errors
    ///
    /// Returns an error if the handler is read-only, sizes are invalid, or the update fails.
    pub fn append_fill(&mut self, fill_data: [u8; 4], size: u64) -> SparseResult<()> {
        self.ensure_writable()?;
        if size == 0 {
            return Ok(());
        }
        if !size.is_multiple_of(4) {
            return Err(SparseError::InvalidOperation(format!(
                "fill size {size} is not a multiple of 4"
            )));
        }
        if !size.is_multiple_of(u64::from(self.block_size)) {
            return Err(SparseError::InvalidOperation(format!(
                "fill size {size} is not a multiple of block size {}",
                self.block_size
            )));
        }

        if !self.is_sparse {
            let snapshot = self.snapshot_for_mutation()?;
            let result = (|| {
                self.file.seek(SeekFrom::End(0))?;
                write_dense_fill_pattern(&mut self.file, fill_data, size)?;
                self.file.flush()?;
                self.read_header()
            })();
            return self.finish_mutation(snapshot, result);
        }

        let blocks = u32::try_from(size / u64::from(self.block_size))
            .map_err(|_| SparseError::Overflow("fill block count to u32"))?;
        self.append_sparse_chunk(ChunkType::Fill, blocks, &fill_data)
    }

    /// Truncates or grows the unsparsified image to `size`.
    ///
    /// Sparse images require `size` to be a multiple of the block size. Growing appends a
    /// DONT_CARE range; shrinking rewrites the final retained chunk header when needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the handler is read-only, sizes are invalid, or the update fails.
    pub fn truncate(&mut self, size: u64) -> SparseResult<()> {
        self.ensure_writable()?;

        if !self.is_sparse {
            let snapshot = self.snapshot_for_mutation()?;
            let result = (|| {
                self.file.set_len(size)?;
                self.file.flush()?;
                self.read_header()
            })();
            return self.finish_mutation(snapshot, result);
        }

        if !size.is_multiple_of(u64::from(self.block_size)) {
            return Err(SparseError::InvalidOperation(
                "cannot truncate to a size which is not a multiple of the block size".into(),
            ));
        }
        if size == self.image_size {
            return Ok(());
        }
        if size > self.image_size {
            return self.append_dont_care(size - self.image_size);
        }

        let snapshot = self.snapshot_for_mutation()?;
        let result = (|| {
            // bisect_right(offsets, size) - 1
            let chunk_idx = self
                .chunk_output_offsets
                .partition_point(|&off| off <= size)
                .saturating_sub(1);
            if chunk_idx >= self.chunks.len() {
                return Err(SparseError::InvalidOperation(
                    "truncate could not locate sparse chunk".into(),
                ));
            }

            let chunk = self.chunks[chunk_idx].clone();
            let (truncate_at, chunk_idx_for_update, maybe_rewrite) = if chunk.output_offset == size
            {
                (chunk.chunk_offset, chunk_idx, None)
            } else {
                let num_to_keep = size - chunk.output_offset;
                if !num_to_keep.is_multiple_of(u64::from(self.block_size)) {
                    return Err(SparseError::InvalidOperation(
                        "internal truncate split is not block aligned".into(),
                    ));
                }
                let (truncate_at, data_sz) = match chunk.chunk_type {
                    ChunkType::Raw => (
                        chunk
                            .chunk_offset
                            .checked_add(CHUNK_HEADER_SIZE as u64)
                            .and_then(|v| v.checked_add(num_to_keep))
                            .ok_or(SparseError::Overflow("computing raw truncate offset"))?,
                        num_to_keep,
                    ),
                    ChunkType::Fill => (
                        chunk
                            .chunk_offset
                            .checked_add(CHUNK_HEADER_SIZE as u64 + 4)
                            .ok_or(SparseError::Overflow("computing fill truncate offset"))?,
                        4u64,
                    ),
                    ChunkType::DontCare => (
                        chunk
                            .chunk_offset
                            .checked_add(CHUNK_HEADER_SIZE as u64)
                            .ok_or(SparseError::Overflow("computing dont-care truncate offset"))?,
                        0u64,
                    ),
                    ChunkType::Crc32 => {
                        return Err(SparseError::InvalidOperation(
                            "cannot truncate inside a CRC32 chunk".into(),
                        ));
                    }
                };
                let chunk_sz = u32::try_from(num_to_keep / u64::from(self.block_size))
                    .map_err(|_| SparseError::Overflow("truncated chunk_sz to u32"))?;
                let total_sz = u32::try_from(
                    data_sz
                        .checked_add(CHUNK_HEADER_SIZE as u64)
                        .ok_or(SparseError::Overflow("truncate total_sz"))?,
                )
                .map_err(|_| SparseError::Overflow("truncate total_sz to u32"))?;
                (
                    truncate_at,
                    chunk_idx + 1,
                    Some((chunk.chunk_offset, chunk.chunk_type, chunk_sz, total_sz)),
                )
            };

            if let Some((chunk_offset, chunk_type, chunk_sz, total_sz)) = maybe_rewrite {
                let mut header = [0u8; CHUNK_HEADER_SIZE];
                write_u16_le(&mut header[0..2], chunk_type.as_u16());
                write_u16_le(&mut header[2..4], 0);
                write_u32_le(&mut header[4..8], chunk_sz);
                write_u32_le(&mut header[8..12], total_sz);
                self.file.seek(SeekFrom::Start(chunk_offset))?;
                self.file.write_all(&header)?;
            }

            let mut num_total_blocks = 0u32;
            for i in 0..chunk_idx_for_update {
                let output_size = if maybe_rewrite.is_some() && i + 1 == chunk_idx_for_update {
                    // Split chunk: use the rewritten kept size, not the stale index entry.
                    size - self.chunks[i].output_offset
                } else {
                    self.chunks[i].output_size
                };
                let add = u32::try_from(output_size / u64::from(self.block_size))
                    .map_err(|_| SparseError::Overflow("summing truncated sparse blocks"))?;
                num_total_blocks = num_total_blocks
                    .checked_add(add)
                    .ok_or(SparseError::Overflow("summing truncated sparse blocks"))?;
            }
            self.num_total_chunks = u32::try_from(chunk_idx_for_update)
                .map_err(|_| SparseError::Overflow("truncated total chunks to u32"))?;
            self.num_total_blocks = num_total_blocks;
            self.update_chunks_and_blocks()?;
            self.file.set_len(truncate_at)?;
            self.file.flush()?;
            self.read_header()
        })();
        self.finish_mutation(snapshot, result)
    }

    fn ensure_writable(&self) -> SparseResult<()> {
        if self.read_only {
            return Err(SparseError::Io(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ImageHandler is in read-only mode",
            )));
        }
        Ok(())
    }

    fn snapshot_for_mutation(&mut self) -> SparseResult<ImageMutationSnapshot> {
        let file_len = self.file.seek(SeekFrom::End(0))?;
        let header_total_blocks_bytes = if self.is_sparse {
            let mut buf = [0u8; 8];
            self.file.seek(SeekFrom::Start(16))?;
            self.file.read_exact(&mut buf)?;
            Some(buf)
        } else {
            None
        };
        Ok(ImageMutationSnapshot {
            file_len,
            is_sparse: self.is_sparse,
            block_size: self.block_size,
            image_size: self.image_size,
            num_total_blocks: self.num_total_blocks,
            num_total_chunks: self.num_total_chunks,
            sparse_end: self.sparse_end,
            header_total_blocks_bytes,
        })
    }

    fn restore_snapshot(&mut self, snapshot: &ImageMutationSnapshot) -> SparseResult<()> {
        self.file.set_len(snapshot.file_len)?;
        if let Some(bytes) = snapshot.header_total_blocks_bytes {
            self.file.seek(SeekFrom::Start(16))?;
            self.file.write_all(&bytes)?;
        }
        self.file.flush()?;
        match self.read_header() {
            Ok(()) => Ok(()),
            Err(_) => {
                self.is_sparse = snapshot.is_sparse;
                self.block_size = snapshot.block_size;
                self.image_size = snapshot.image_size;
                self.num_total_blocks = snapshot.num_total_blocks;
                self.num_total_chunks = snapshot.num_total_chunks;
                self.sparse_end = snapshot.sparse_end;
                self.file_pos = 0;
                Ok(())
            }
        }
    }

    fn finish_mutation(
        &mut self,
        snapshot: ImageMutationSnapshot,
        result: SparseResult<()>,
    ) -> SparseResult<()> {
        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                let _ = self.restore_snapshot(&snapshot);
                Err(err)
            }
        }
    }

    fn append_sparse_chunk(
        &mut self,
        chunk_type: ChunkType,
        chunk_sz: u32,
        payload: &[u8],
    ) -> SparseResult<()> {
        let snapshot = self.snapshot_for_mutation()?;
        let result = (|| {
            let total_sz = (CHUNK_HEADER_SIZE as u32)
                .checked_add(payload.len() as u32)
                .ok_or(SparseError::Overflow("encoding appended chunk total size"))?;

            self.num_total_chunks = self
                .num_total_chunks
                .checked_add(1)
                .ok_or(SparseError::Overflow("incrementing total chunks"))?;
            self.num_total_blocks = self
                .num_total_blocks
                .checked_add(chunk_sz)
                .ok_or(SparseError::Overflow("incrementing total blocks"))?;
            self.update_chunks_and_blocks()?;

            self.file.seek(SeekFrom::Start(self.sparse_end))?;
            let mut header = [0u8; CHUNK_HEADER_SIZE];
            write_u16_le(&mut header[0..2], chunk_type.as_u16());
            write_u16_le(&mut header[2..4], 0);
            write_u32_le(&mut header[4..8], chunk_sz);
            write_u32_le(&mut header[8..12], total_sz);
            self.file.write_all(&header)?;
            if !payload.is_empty() {
                self.file.write_all(payload)?;
            }
            self.file.flush()?;
            self.read_header()
        })();
        self.finish_mutation(snapshot, result)
    }

    fn update_chunks_and_blocks(&mut self) -> SparseResult<()> {
        // total_blocks at offset 16, total_chunks at offset 20.
        self.file.seek(SeekFrom::Start(16))?;
        let mut buf = [0u8; 8];
        write_u32_le(&mut buf[0..4], self.num_total_blocks);
        write_u32_le(&mut buf[4..8], self.num_total_chunks);
        self.file.write_all(&buf)?;
        self.file.flush()?;
        Ok(())
    }

    fn read_header(&mut self) -> SparseResult<()> {
        self.is_sparse = false;
        self.block_size = DEFAULT_BLOCK_SIZE;
        self.file_pos = 0;
        self.num_total_blocks = 0;
        self.num_total_chunks = 0;
        self.sparse_end = 0;
        self.chunks.clear();
        self.chunk_output_offsets.clear();

        let file_len = self.file.seek(SeekFrom::End(0))?;
        self.image_size = file_len;
        self.file.seek(SeekFrom::Start(0))?;

        // Dense short files are valid; only full headers are considered for sparse detection.
        if file_len < SPARSE_HEADER_SIZE as u64 {
            return Ok(());
        }

        let mut header_bin = [0u8; SPARSE_HEADER_SIZE];
        self.file.read_exact(&mut header_bin)?;
        let header = SparseHeader::decode(&header_bin)?;
        if header.magic != SPARSE_MAGIC {
            return Ok(());
        }

        if header.major_version != SPARSE_MAJOR_VERSION
            || header.minor_version != SPARSE_MINOR_VERSION
        {
            return Err(SparseError::UnsupportedVersion {
                major: header.major_version,
                minor: header.minor_version,
            });
        }
        if header.file_hdr_sz as usize != SPARSE_HEADER_SIZE {
            return Err(SparseError::UnexpectedFileHeaderSize(header.file_hdr_sz));
        }
        if header.chunk_hdr_sz as usize != CHUNK_HEADER_SIZE {
            return Err(SparseError::UnexpectedChunkHeaderSize(header.chunk_hdr_sz));
        }
        if header.block_size == 0 {
            return Err(SparseError::InvalidOperation(
                "block size must be non-zero".into(),
            ));
        }

        self.block_size = header.block_size;
        self.num_total_blocks = header.total_blocks;
        self.num_total_chunks = header.total_chunks;

        let mut observed_blocks: u32 = 0;
        let mut output_offset: u64 = 0;
        let mut chunks = Vec::with_capacity(header.total_chunks as usize);

        for _ in 0..header.total_chunks {
            let chunk_offset = self.file.stream_position()?;
            let mut chunk_hdr = [0u8; CHUNK_HEADER_SIZE];
            if let Err(err) = self.file.read_exact(&mut chunk_hdr) {
                if err.kind() == io::ErrorKind::UnexpectedEof {
                    let available = self.file.seek(SeekFrom::End(0))? as usize;
                    return Err(SparseError::TruncatedData {
                        context: "chunk header",
                        needed: CHUNK_HEADER_SIZE,
                        available: available.saturating_sub(chunk_offset as usize),
                    });
                }
                return Err(SparseError::Io(err));
            }

            let chunk_type = ChunkType::from_u16(read_u16_le(&chunk_hdr[0..2]))?;
            let chunk_sz = read_u32_le(&chunk_hdr[4..8]);
            let total_sz = read_u32_le(&chunk_hdr[8..12]);
            if (total_sz as usize) < CHUNK_HEADER_SIZE {
                return Err(SparseError::InvalidOperation(format!(
                    "chunk total size {total_sz} is smaller than chunk header"
                )));
            }
            let data_sz = total_sz as u64 - CHUNK_HEADER_SIZE as u64;
            let output_size = mul_u32_to_u64(chunk_sz, self.block_size)?;

            match chunk_type {
                ChunkType::Raw => {
                    if data_sz != output_size {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: u32::try_from(output_size).unwrap_or(u32::MAX),
                        });
                    }
                    let input_offset = self.file.stream_position()?;
                    let end = input_offset
                        .checked_add(data_sz)
                        .ok_or(SparseError::Overflow("seeking past raw chunk payload"))?;
                    if end > file_len {
                        return Err(SparseError::TruncatedData {
                            context: "chunk payload",
                            needed: data_sz as usize,
                            available: file_len.saturating_sub(input_offset) as usize,
                        });
                    }
                    self.file.seek(SeekFrom::Start(end))?;
                    chunks.push(IndexedChunk {
                        chunk_type,
                        chunk_offset,
                        output_offset,
                        output_size,
                        input_offset: Some(input_offset),
                        fill_data: None,
                    });
                }
                ChunkType::Fill => {
                    if data_sz != 4 {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: 4,
                        });
                    }
                    let mut fill = [0u8; 4];
                    self.file.read_exact(&mut fill)?;
                    chunks.push(IndexedChunk {
                        chunk_type,
                        chunk_offset,
                        output_offset,
                        output_size,
                        input_offset: None,
                        fill_data: Some(fill),
                    });
                }
                ChunkType::DontCare => {
                    if data_sz != 0 {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: 0,
                        });
                    }
                    chunks.push(IndexedChunk {
                        chunk_type,
                        chunk_offset,
                        output_offset,
                        output_size,
                        input_offset: None,
                        fill_data: None,
                    });
                }
                ChunkType::Crc32 => {
                    if data_sz != 4 {
                        return Err(SparseError::InvalidChunkPayload {
                            chunk_type,
                            data_size: data_sz as u32,
                            expected: 4,
                        });
                    }
                    if chunk_sz != 0 {
                        return Err(SparseError::InvalidOperation(
                            "CRC32 chunk must have zero output blocks".into(),
                        ));
                    }
                    let mut crc = [0u8; 4];
                    self.file.read_exact(&mut crc)?;
                }
            }

            observed_blocks = observed_blocks
                .checked_add(chunk_sz)
                .ok_or(SparseError::Overflow("summing observed blocks"))?;
            output_offset = output_offset
                .checked_add(output_size)
                .ok_or(SparseError::Overflow("summing sparse output size"))?;
        }

        self.sparse_end = self.file.stream_position()?;
        if observed_blocks != header.total_blocks {
            return Err(SparseError::BlockCountMismatch {
                header_blocks: header.total_blocks,
                observed_blocks,
            });
        }

        let trailing = file_len.saturating_sub(self.sparse_end);
        if trailing > 0 {
            return Err(SparseError::TrailingData(trailing));
        }

        self.chunk_output_offsets = chunks.iter().map(|c| c.output_offset).collect();
        self.chunks = chunks;
        self.image_size = output_offset;
        self.is_sparse = true;
        Ok(())
    }
}

fn write_dense_fill_pattern(file: &mut File, fill: [u8; 4], size: u64) -> SparseResult<()> {
    if size == 0 {
        return Ok(());
    }
    if !size.is_multiple_of(4) {
        return Err(SparseError::InvalidOperation(format!(
            "fill size {size} is not a multiple of 4"
        )));
    }

    // Build a bounded buffer of the exact 4-byte pattern, then write whole chunks.
    // This avoids per-4-byte syscalls while remaining correct for multi-gigabyte fills.
    let pattern_repeats = DENSE_FILL_WRITE_CHUNK / 4;
    let mut chunk = Vec::with_capacity(DENSE_FILL_WRITE_CHUNK);
    for _ in 0..pattern_repeats {
        chunk.extend_from_slice(&fill);
    }

    let mut remaining = size;
    while remaining > 0 {
        let to_write = min(remaining, DENSE_FILL_WRITE_CHUNK as u64) as usize;
        // to_write is always a multiple of 4 because both size and the chunk size are.
        file.write_all(&chunk[..to_write])?;
        remaining -= to_write as u64;
    }
    Ok(())
}

fn fill_from_chunk(chunk: &SparseChunk, into_chunk: u64, dst: &mut [u8]) -> SparseResult<()> {
    match chunk {
        SparseChunk::Raw { data, output_size } => {
            let start = usize::try_from(into_chunk)
                .map_err(|_| SparseError::Overflow("raw chunk offset to usize"))?;
            let end = start
                .checked_add(dst.len())
                .ok_or(SparseError::Overflow("raw chunk end"))?;
            if end as u64 > *output_size || end > data.len() {
                return Err(SparseError::InvalidOperation(
                    "raw chunk read out of bounds".into(),
                ));
            }
            dst.copy_from_slice(&data[start..end]);
        }
        SparseChunk::Fill {
            fill, output_size, ..
        } => {
            if into_chunk.saturating_add(dst.len() as u64) > *output_size {
                return Err(SparseError::InvalidOperation(
                    "fill chunk read out of bounds".into(),
                ));
            }
            let start_mod = (into_chunk % 4) as usize;
            for (i, byte) in dst.iter_mut().enumerate() {
                *byte = fill[(start_mod + i) % 4];
            }
        }
        SparseChunk::DontCare { output_size } => {
            if into_chunk.saturating_add(dst.len() as u64) > *output_size {
                return Err(SparseError::InvalidOperation(
                    "dont-care chunk read out of bounds".into(),
                ));
            }
            dst.fill(0);
        }
        SparseChunk::Crc32 { .. } => {
            return Err(SparseError::InvalidOperation(
                "CRC32 chunks have no logical output".into(),
            ));
        }
    }
    Ok(())
}

fn truncate_chunk(chunk: &SparseChunk, keep: u64) -> SparseResult<SparseChunk> {
    if keep == 0 {
        return Err(SparseError::InvalidOperation(
            "internal truncate produced empty chunk".into(),
        ));
    }
    match chunk {
        SparseChunk::Raw { data, .. } => {
            let keep_usize = usize::try_from(keep)
                .map_err(|_| SparseError::Overflow("truncating raw chunk to usize"))?;
            if keep_usize > data.len() {
                return Err(SparseError::InvalidOperation(
                    "truncate length exceeds raw chunk data".into(),
                ));
            }
            Ok(SparseChunk::Raw {
                output_size: keep,
                data: data[..keep_usize].to_vec(),
            })
        }
        SparseChunk::Fill { fill, .. } => Ok(SparseChunk::Fill {
            output_size: keep,
            fill: *fill,
        }),
        SparseChunk::DontCare { .. } => Ok(SparseChunk::DontCare { output_size: keep }),
        SparseChunk::Crc32 { .. } => Err(SparseError::InvalidOperation(
            "cannot truncate a CRC32 chunk".into(),
        )),
    }
}

fn mul_u32_to_u64(a: u32, b: u32) -> SparseResult<u64> {
    u64::from(a)
        .checked_mul(u64::from(b))
        .ok_or(SparseError::Overflow("multiplying blocks by block size"))
}

fn read_u16_le(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32_le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn write_u16_le(dst: &mut [u8], value: u16) {
    dst.copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le(dst: &mut [u8], value: u32) {
    dst.copy_from_slice(&value.to_le_bytes());
}

fn sparse_to_io(err: SparseError) -> io::Error {
    match err {
        SparseError::Io(err) => err,
        other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
    }
}

/// Builds a sparse image in memory for tests and callers that want a builder-style API.
#[derive(Debug, Default)]
pub struct SparseImageBuilder {
    block_size: u32,
    chunks: Vec<SparseChunk>,
}

impl SparseImageBuilder {
    /// Creates a builder with the given block size.
    pub fn new(block_size: u32) -> Self {
        Self {
            block_size,
            chunks: Vec::new(),
        }
    }

    /// Appends a raw chunk.
    pub fn raw(mut self, data: impl Into<Vec<u8>>) -> Self {
        let data = data.into();
        self.chunks.push(SparseChunk::Raw {
            output_size: data.len() as u64,
            data,
        });
        self
    }

    /// Appends a fill chunk.
    pub fn fill(mut self, fill: [u8; 4], size: u64) -> Self {
        self.chunks.push(SparseChunk::Fill {
            output_size: size,
            fill,
        });
        self
    }

    /// Appends a dont-care chunk.
    pub fn dont_care(mut self, size: u64) -> Self {
        self.chunks
            .push(SparseChunk::DontCare { output_size: size });
        self
    }

    /// Appends a structural CRC32 chunk.
    pub fn crc32(mut self, crc: [u8; 4]) -> Self {
        self.chunks.push(SparseChunk::Crc32 { crc });
        self
    }

    /// Finalizes the builder into a [`SparseImage`].
    ///
    /// # Errors
    ///
    /// Returns an error if block size is zero or chunk sizes are not block-aligned.
    pub fn build(self) -> SparseResult<SparseImage> {
        let mut image = SparseImage::new(self.block_size)?;
        for chunk in self.chunks {
            let _ = chunk.block_count(self.block_size)?;
            image.chunks.push(chunk);
        }
        Ok(image)
    }
}

#[cfg(test)]
fn encode_raw_sparse_for_test(
    block_size: u32,
    chunks: &[(ChunkType, u32, &[u8])],
    total_blocks_override: Option<u32>,
    total_chunks_override: Option<u32>,
    trailing: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut total_blocks = 0u32;
    for (chunk_type, chunk_sz, payload) in chunks {
        let total_sz = (CHUNK_HEADER_SIZE + payload.len()) as u32;
        let mut header = [0u8; CHUNK_HEADER_SIZE];
        write_u16_le(&mut header[0..2], chunk_type.as_u16());
        write_u16_le(&mut header[2..4], 0);
        write_u32_le(&mut header[4..8], *chunk_sz);
        write_u32_le(&mut header[8..12], total_sz);
        body.extend_from_slice(&header);
        body.extend_from_slice(payload);
        total_blocks = total_blocks.wrapping_add(*chunk_sz);
    }

    let header = SparseHeader::new(
        block_size,
        total_blocks_override.unwrap_or(total_blocks),
        total_chunks_override.unwrap_or(chunks.len() as u32),
    )
    .encode();

    let mut out = Vec::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(&body);
    out.extend_from_slice(trailing);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const BLOCK: u32 = 4;

    fn sample_image() -> SparseImage {
        SparseImageBuilder::new(BLOCK)
            .raw(b"AABB".to_vec())
            .dont_care(4)
            .fill([1, 2, 3, 4], 4)
            .raw(b"CCDD".to_vec())
            .crc32([0xde, 0xad, 0xbe, 0xef])
            .build()
            .expect("sample image")
    }

    #[test]
    fn detects_sparse_magic() {
        let image = sample_image();
        let bytes = image.to_sparse_bytes().unwrap();
        assert!(SparseImage::looks_sparse(&bytes));
        assert!(!SparseImage::looks_sparse(b"not sparse"));
        assert!(SparseImage::try_parse(b"not sparse").unwrap().is_none());
    }

    #[test]
    fn parses_all_chunk_types_and_round_trips() {
        let image = sample_image();
        assert_eq!(image.image_size(), 16);
        assert_eq!(image.chunks().len(), 5);

        let sparse = image.to_sparse_bytes().unwrap();
        let parsed = SparseImage::parse(&sparse).unwrap();
        assert_eq!(parsed.image_size(), 16);
        assert_eq!(parsed.block_size(), BLOCK);
        assert_eq!(
            parsed.to_dense_bytes().unwrap(),
            b"AABB\0\0\0\0\x01\x02\x03\x04CCDD"
        );

        assert!(matches!(
            parsed.chunks().last(),
            Some(SparseChunk::Crc32 {
                crc: [0xde, 0xad, 0xbe, 0xef]
            })
        ));

        let rewritten = parsed.rewrite().unwrap();
        let reparsed = SparseImage::parse(&rewritten).unwrap();
        assert_eq!(
            reparsed.to_dense_bytes().unwrap(),
            parsed.to_dense_bytes().unwrap()
        );
    }

    #[test]
    fn random_access_and_cross_chunk_reads() {
        let mut image = sample_image();
        assert_eq!(image.read_logical(2, 4).unwrap(), b"BB\0\0");
        assert_eq!(image.read_logical(6, 4).unwrap(), b"\0\0\x01\x02");
        assert_eq!(image.read_logical(9, 3).unwrap(), b"\x02\x03\x04");
        assert_eq!(image.read_logical(10, 4).unwrap(), b"\x03\x04CC");

        image.seek_logical(0);
        let mut buf = [0u8; 4];
        assert_eq!(image.read_logical_cursor(&mut buf).unwrap(), 4);
        assert_eq!(&buf, b"AABB");
        assert_eq!(image.tell(), 4);

        image.seek_logical(14);
        let mut tail = [0u8; 8];
        assert_eq!(image.read_logical_cursor(&mut tail).unwrap(), 2);
        assert_eq!(&tail[..2], b"DD");
    }

    #[test]
    fn append_raw_fill_and_dont_care() {
        let mut image = SparseImage::new(BLOCK).unwrap();
        image.append_raw(b"ZZZZ", true).unwrap();
        image.append_fill([9, 9, 9, 9], 4).unwrap();
        image.append_dont_care(8).unwrap();
        assert_eq!(image.image_size(), 16);
        assert_eq!(
            image.to_dense_bytes().unwrap(),
            b"ZZZZ\x09\x09\x09\x09\0\0\0\0\0\0\0\0"
        );

        let parsed = SparseImage::parse(&image.to_sparse_bytes().unwrap()).unwrap();
        assert_eq!(
            parsed.to_dense_bytes().unwrap(),
            image.to_dense_bytes().unwrap()
        );
    }

    #[test]
    fn truncate_shrink_split_and_grow() {
        let mut image = sample_image();
        image.truncate(8).unwrap();
        assert_eq!(image.image_size(), 8);
        assert_eq!(image.to_dense_bytes().unwrap(), b"AABB\0\0\0\0");

        image.truncate(12).unwrap();
        assert_eq!(image.image_size(), 12);
        assert_eq!(image.to_dense_bytes().unwrap(), b"AABB\0\0\0\0\0\0\0\0");

        image.truncate(4).unwrap();
        assert_eq!(image.to_dense_bytes().unwrap(), b"AABB");

        let mut image = sample_image();
        image.truncate(12).unwrap();
        assert_eq!(
            image.to_dense_bytes().unwrap(),
            b"AABB\0\0\0\0\x01\x02\x03\x04"
        );

        let mut image = SparseImageBuilder::new(BLOCK)
            .raw(b"ABCDEFGH".to_vec())
            .build()
            .unwrap();
        image.truncate(4).unwrap();
        assert_eq!(image.to_dense_bytes().unwrap(), b"ABCD");
        assert!(matches!(
            &image.chunks()[0],
            SparseChunk::Raw {
                data,
                output_size: 4
            } if data == b"ABCD"
        ));
    }

    #[test]
    fn rejects_malformed_headers_and_chunks() {
        let mut bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::DontCare, 1, &[])], None, None, &[]);
        write_u16_le(&mut bad[4..6], 2);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::UnsupportedVersion { major: 2, .. })
        ));

        let mut bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::DontCare, 1, &[])], None, None, &[]);
        write_u16_le(&mut bad[8..10], 30);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::UnexpectedFileHeaderSize(30))
        ));

        let bad = encode_raw_sparse_for_test(BLOCK, &[(ChunkType::Raw, 1, b"AB")], None, None, &[]);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::InvalidChunkPayload {
                chunk_type: ChunkType::Raw,
                ..
            })
        ));

        let bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::Fill, 1, b"12345")], None, None, &[]);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::InvalidChunkPayload {
                chunk_type: ChunkType::Fill,
                ..
            })
        ));

        let bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::DontCare, 1, b"x")], None, None, &[]);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::InvalidChunkPayload {
                chunk_type: ChunkType::DontCare,
                ..
            })
        ));

        let bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::Crc32, 0, b"12")], Some(0), None, &[]);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::InvalidChunkPayload {
                chunk_type: ChunkType::Crc32,
                ..
            })
        ));

        let bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::DontCare, 1, &[])], Some(9), None, &[]);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::BlockCountMismatch {
                header_blocks: 9,
                observed_blocks: 1
            })
        ));

        let bad = encode_raw_sparse_for_test(
            BLOCK,
            &[(ChunkType::DontCare, 1, &[])],
            None,
            None,
            b"junk",
        );
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::TrailingData(4))
        ));

        let mut bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::DontCare, 1, &[])], None, None, &[]);
        write_u16_le(&mut bad[SPARSE_HEADER_SIZE..SPARSE_HEADER_SIZE + 2], 0x1234);
        assert!(matches!(
            SparseImage::parse(&bad),
            Err(SparseError::UnknownChunkType(0x1234))
        ));

        assert!(matches!(
            SparseImage::parse(b"this is dense data!!!!"),
            Err(SparseError::NotSparse)
        ));
    }

    #[test]
    fn accepts_crc32_structurally_and_serializes() {
        let image = SparseImageBuilder::new(BLOCK)
            .raw(b"DATA".to_vec())
            .crc32([1, 2, 3, 4])
            .build()
            .unwrap();
        let bytes = image.to_sparse_bytes().unwrap();
        let parsed = SparseImage::parse(&bytes).unwrap();
        assert_eq!(parsed.image_size(), 4);
        assert_eq!(parsed.chunks().len(), 2);
        assert!(matches!(
            &parsed.chunks()[1],
            SparseChunk::Crc32 { crc: [1, 2, 3, 4] }
        ));
    }

    #[test]
    fn std_read_seek_impls_work() {
        let mut image = sample_image();
        image.seek(SeekFrom::Start(8)).unwrap();
        let mut buf = [0u8; 4];
        Read::read(&mut image, &mut buf).unwrap();
        assert_eq!(&buf, b"\x01\x02\x03\x04");
        assert_eq!(image.seek(SeekFrom::Current(-2)).unwrap(), 10);
    }

    #[test]
    fn parse_sparse_reader_and_write_helpers() {
        let image = sample_image();
        let bytes = image.to_sparse_bytes().unwrap();
        let parsed = parse_sparse_reader(Cursor::new(bytes.clone())).unwrap();
        assert_eq!(
            parsed.to_dense_bytes().unwrap(),
            image.to_dense_bytes().unwrap()
        );

        let mut out = Vec::new();
        write_sparse_image(&image, &mut out).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn append_rejects_unaligned_sizes() {
        let mut image = SparseImage::new(BLOCK).unwrap();
        assert!(image.append_raw(b"ABC", true).is_err());
        assert!(image.append_fill([0; 4], 2).is_err());
        assert!(image.append_dont_care(3).is_err());
        assert!(image.truncate(3).is_err());
    }

    #[test]
    fn empty_image_serializes_valid_header() {
        let image = SparseImage::new(BLOCK).unwrap();
        let bytes = image.to_sparse_bytes().unwrap();
        assert_eq!(bytes.len(), SPARSE_HEADER_SIZE);
        let parsed = SparseImage::parse(&bytes).unwrap();
        assert_eq!(parsed.image_size(), 0);
        assert!(parsed.chunks().is_empty());
    }

    #[test]
    fn image_handler_dense_read_append_truncate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dense.img");
        std::fs::write(&path, b"ABCDEFGH").unwrap();

        let mut h = ImageHandler::open(&path, false).unwrap();
        assert!(!h.is_sparse());
        assert_eq!(h.block_size(), DEFAULT_BLOCK_SIZE);
        assert_eq!(h.image_size(), 8);
        assert_eq!(h.read(3).unwrap(), b"ABC");
        assert_eq!(h.tell(), 3);
        h.seek(6).unwrap();
        assert_eq!(h.read(8).unwrap(), b"GH"); // partial EOF

        h.append_raw(b"IJKL", false).unwrap();
        assert_eq!(h.image_size(), 12);
        assert_eq!(h.tell(), 0); // re-parse resets cursor like avbtool
        assert_eq!(h.read(12).unwrap(), b"ABCDEFGHIJKL");

        h.append_fill([0x11, 0x22, 0x33, 0x44], u64::from(DEFAULT_BLOCK_SIZE))
            .unwrap();
        assert_eq!(h.image_size(), 12 + u64::from(DEFAULT_BLOCK_SIZE));
        h.seek(12).unwrap();
        let fill = h.read(4).unwrap();
        assert_eq!(fill, [0x11, 0x22, 0x33, 0x44]);

        h.truncate(4).unwrap();
        assert_eq!(h.image_size(), 4);
        assert_eq!(h.read(10).unwrap(), b"ABCD");

        h.append_dont_care(u64::from(DEFAULT_BLOCK_SIZE)).unwrap();
        assert_eq!(h.image_size(), 4 + u64::from(DEFAULT_BLOCK_SIZE));
        h.seek(4).unwrap();
        assert_eq!(h.read(4).unwrap(), [0, 0, 0, 0]);
    }

    #[test]
    fn image_handler_dense_append_fill_chunked_large() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dense_fill_large.img");
        std::fs::write(&path, b"").unwrap();

        let fill = [0xde, 0xad, 0xbe, 0xef];
        // Larger than DENSE_FILL_WRITE_CHUNK and a multiple of DEFAULT_BLOCK_SIZE.
        let fill_size = (DENSE_FILL_WRITE_CHUNK as u64) + u64::from(DEFAULT_BLOCK_SIZE);

        let mut h = ImageHandler::open(&path, false).unwrap();
        assert!(!h.is_sparse());
        h.append_fill(fill, fill_size).unwrap();
        assert_eq!(h.image_size(), fill_size);

        // Exact length on disk.
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len() as u64, fill_size);

        // Exact repeated 4-byte pattern across full content, including across chunk boundary.
        for (idx, chunk) in bytes.chunks_exact(4).enumerate() {
            assert_eq!(chunk, fill, "mismatch at pattern index {idx}");
        }
        assert!(bytes.len().is_multiple_of(4));

        // Read path also returns the same pattern around the first write-chunk boundary.
        h.seek(DENSE_FILL_WRITE_CHUNK as u64 - 2).unwrap();
        let around = h.read(8).unwrap();
        assert_eq!(around, [0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad]);
    }

    #[test]
    fn image_handler_sparse_index_mutate_and_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sparse.img");

        let mem = SparseImageBuilder::new(BLOCK)
            .raw(b"AABB".to_vec())
            .dont_care(4)
            .fill([1, 2, 3, 4], 4)
            .raw(b"CCDD".to_vec())
            .build()
            .unwrap();
        std::fs::write(&path, mem.to_sparse_bytes().unwrap()).unwrap();

        let mut h = ImageHandler::open(&path, false).unwrap();
        assert!(h.is_sparse());
        assert_eq!(h.block_size(), BLOCK);
        assert_eq!(h.image_size(), 16);

        assert_eq!(h.read(4).unwrap(), b"AABB");
        h.seek(4).unwrap();
        assert_eq!(h.read(4).unwrap(), [0, 0, 0, 0]);
        h.seek(8).unwrap();
        assert_eq!(h.read(4).unwrap(), [1, 2, 3, 4]);
        h.seek(10).unwrap();
        assert_eq!(h.read(4).unwrap(), [3, 4, b'C', b'C']);

        h.append_raw(b"EEEEFFFF", true).unwrap();
        assert_eq!(h.image_size(), 24);
        h.seek(16).unwrap();
        assert_eq!(h.read(8).unwrap(), b"EEEEFFFF");

        h.append_fill([9, 9, 9, 9], 4).unwrap();
        h.append_dont_care(4).unwrap();
        assert_eq!(h.image_size(), 32);
        h.seek(24).unwrap();
        assert_eq!(h.read(8).unwrap(), [9, 9, 9, 9, 0, 0, 0, 0]);

        // Shrink splitting a multi-block RAW chunk (keep one block of EEEEFFFF).
        h.truncate(20).unwrap();
        assert_eq!(h.image_size(), 20);
        h.seek(16).unwrap();
        assert_eq!(h.read(4).unwrap(), b"EEEE");
        assert!(h.read(1).unwrap().is_empty());

        // Grow via truncate.
        h.truncate(24).unwrap();
        assert_eq!(h.image_size(), 24);
        h.seek(20).unwrap();
        assert_eq!(h.read(4).unwrap(), [0, 0, 0, 0]);

        // Truncate at chunk boundary.
        h.truncate(8).unwrap();
        assert_eq!(h.image_size(), 8);
        h.seek(0).unwrap();
        assert_eq!(h.read(8).unwrap(), [b'A', b'A', b'B', b'B', 0, 0, 0, 0]);
    }

    #[test]
    fn image_handler_rejects_malformed_sparse_and_readonly() {
        let dir = tempfile::tempdir().expect("tempdir");

        let bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::DontCare, 1, &[])], Some(9), None, &[]);
        let path = dir.path().join("bad_blocks.img");
        std::fs::write(&path, &bad).unwrap();
        assert!(matches!(
            ImageHandler::open(&path, true),
            Err(SparseError::BlockCountMismatch { .. })
        ));

        let trailing = encode_raw_sparse_for_test(
            BLOCK,
            &[(ChunkType::DontCare, 1, &[])],
            None,
            None,
            b"junk",
        );
        let path = dir.path().join("trailing.img");
        std::fs::write(&path, &trailing).unwrap();
        assert!(matches!(
            ImageHandler::open(&path, true),
            Err(SparseError::TrailingData(4))
        ));

        let raw_bad =
            encode_raw_sparse_for_test(BLOCK, &[(ChunkType::Raw, 1, b"AB")], None, None, &[]);
        let path = dir.path().join("raw_bad.img");
        std::fs::write(&path, &raw_bad).unwrap();
        assert!(matches!(
            ImageHandler::open(&path, true),
            Err(SparseError::InvalidChunkPayload {
                chunk_type: ChunkType::Raw,
                ..
            })
        ));

        // Valid sparse opened read-only rejects mutations.
        let mem = SparseImageBuilder::new(BLOCK)
            .raw(b"DATA".to_vec())
            .build()
            .unwrap();
        let path = dir.path().join("ro.img");
        std::fs::write(&path, mem.to_sparse_bytes().unwrap()).unwrap();
        let mut h = ImageHandler::open(&path, true).unwrap();
        assert!(h.append_raw(b"XXXX", true).is_err());
        assert!(h.append_fill([0; 4], 4).is_err());
        assert!(h.append_dont_care(4).is_err());
        assert!(h.truncate(0).is_err());
    }

    #[test]
    fn image_handler_sparse_partial_eof_and_cross_chunk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cross.img");
        let mem = SparseImageBuilder::new(BLOCK)
            .raw(b"AAAA".to_vec())
            .fill([0xab, 0xcd, 0xef, 0x01], 8)
            .dont_care(4)
            .build()
            .unwrap();
        std::fs::write(&path, mem.to_sparse_bytes().unwrap()).unwrap();

        let mut h = ImageHandler::open(&path, true).unwrap();
        h.seek(2).unwrap();
        assert_eq!(h.read(6).unwrap(), [b'A', b'A', 0xab, 0xcd, 0xef, 0x01]);
        h.seek(14).unwrap();
        // image size 16, request 8 -> partial 2 zero bytes
        assert_eq!(h.read(8).unwrap(), [0, 0]);
        h.seek(100).unwrap();
        assert!(h.read(4).unwrap().is_empty());
    }
}
