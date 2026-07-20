//! Reed-Solomon FEC encoder for AVB-style hashtree FEC regions.
//!
//! AVB's FEC matches the configuration `init_rs_char(8, 0x11d, 0, 1, nroots, 0)`
//! used by AOSP's `system/extras/libfec` / `verity/fec`:
//!
//!   * `symsize = 8`     — bytes are GF(2^8) symbols
//!   * `gfpoly  = 0x11d` — primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
//!   * `fcr     = 0`     — first consecutive root α^0 = 1
//!   * `prim    = 1`     — primitive element step
//!   * `nroots  = 2`     — typical AVB choice; corrects 1 byte / RS codeword
//!
//! Encoding is systematic and **block-interleaved**, matching AOSP
//! `image_get_interleaved_byte` / `fec_ecc_interleave`:
//!
//!   * `rsn = 255 - nroots`
//!   * `blocks = ceil(input_size / 4096)`
//!   * `rounds = ceil(blocks / rsn)`
//!   * actual FEC data size = `rounds * nroots * 4096`
//!
//! Codeword `k` (0 .. rounds*4096) consumes `rsn` data symbols taken from
//! physical offsets `k + j * rounds * 4096` for `j = 0 .. rsn-1` (zero when
//! beyond the input), then appends `nroots` parity bytes. AVB stores only the
//! parity stream; the covered data lives again on disk for recovery.
//!
//! The FEC input is the data area of the partition concatenated with the
//! dm-verity hash tree, in that order. Use [`generate_fec_bytes`] when you
//! already hold the input in memory, or [`generate_fec_from_image`] to
//! stream it from a file (for multi-GB partitions where holding the full
//! buffer is wasteful).
//!
//! Size helpers:
//!   * [`fec_size_for_input`] — actual parity bytes written into the image /
//!     hashtree descriptor (`image_ecc_new`).
//!   * [`calc_fec_data_size`] — AOSP `fec --print-fec-size` / avbtool
//!     `calc_fec_data_size` reserve: actual size plus one 4096-byte FEC tool
//!     footer. Used only for conservative `calc_max` budgeting.

use std::path::Path;

use crate::error::{AvbToolError as DynoError, Result};
use crate::parser::sparse_err;
use crate::sparse::ImageHandler;

/// Size each FEC region is rounded up to (matches AOSP `FEC_BLOCKSIZE`).
pub const FEC_BLOCKSIZE: u64 = 4096;

/// AVB's primitive polynomial for GF(2^8): x^8 + x^4 + x^3 + x^2 + 1.
const GF_POLY: u32 = 0x11d;

/// Total non-zero elements in GF(2^8): `2^8 - 1 = 255`.
const NN: u8 = 255;

/// Sentinel index used for the log of the zero element.
const A0: usize = 255;

/// Encoder/state for a single Reed-Solomon configuration. The tables are
/// built once per encoder; encoding many rounds reuses them.
pub struct ReedSolomonEncoder {
    nroots: usize,
    /// `alpha_to[i] = α^i` in GF(2^8).
    alpha_to: [u8; 256],
    /// `index_of[x] = log_α(x)`, with `index_of[0] = A0`.
    index_of: [u8; 256],
    /// Generator polynomial in log form, length `nroots + 1`. `genpoly[i]`
    /// holds `log_α(coef of x^i)`. `genpoly[nroots]` is the monic top
    /// (always `0` because `α^0 = 1`).
    genpoly_log: Vec<u8>,
}

impl ReedSolomonEncoder {
    /// Build an encoder for AVB's `init_rs_char(8, 0x11d, 0, 1, nroots, 0)`.
    pub fn new_avb(nroots: usize) -> Result<Self> {
        if nroots == 0 || nroots >= 255 {
            return Err(DynoError::Validation(format!(
                "Reed-Solomon nroots must be in 1..255 (got {})",
                nroots
            )));
        }
        let (alpha_to, index_of) = build_gf_tables();
        let genpoly_log = build_genpoly_log(&alpha_to, &index_of, nroots);
        Ok(Self {
            nroots,
            alpha_to,
            index_of,
            genpoly_log,
        })
    }

    /// Number of data bytes consumed per codeword (`255 - nroots`).
    pub fn data_bytes_per_round(&self) -> usize {
        (NN as usize) - self.nroots
    }

    /// Produce `nroots` parity bytes for one RS codeword. `data` must have at
    /// most `data_bytes_per_round()` bytes; missing tail bytes are treated
    /// as zero, matching libfec's pad behavior on shortened symbols.
    pub fn encode_round(&self, data: &[u8], parity_out: &mut [u8]) -> Result<()> {
        let rsn = self.data_bytes_per_round();
        if data.len() > rsn {
            return Err(DynoError::Validation(format!(
                "Reed-Solomon round must take ≤ {} data bytes (got {})",
                rsn,
                data.len()
            )));
        }
        if parity_out.len() != self.nroots {
            return Err(DynoError::Validation(format!(
                "Reed-Solomon parity output buffer must be {} bytes (got {})",
                self.nroots,
                parity_out.len()
            )));
        }

        // Feed `rsn` bytes; pad the trailing region with zeros to mirror
        // libfec's pad-with-zero behavior on shortened symbols.
        let mut parity = vec![0u8; self.nroots];
        for i in 0..rsn {
            let symbol = if i < data.len() { data[i] } else { 0u8 };
            let feedback_value = symbol ^ parity[0];
            let feedback = self.index_of[feedback_value as usize] as usize;

            if feedback != A0 {
                // parity[j] ^= alpha_to[(feedback + genpoly_log[nroots - j]) mod 255]
                // for j in 1..nroots
                for (j, parity_byte) in parity.iter_mut().enumerate().skip(1) {
                    let g_log = self.genpoly_log[self.nroots - j] as usize;
                    let idx = mod_nn(feedback + g_log);
                    *parity_byte ^= self.alpha_to[idx];
                }
            }

            // Shift parity register: parity[0..nroots-1] = parity[1..nroots]
            for j in 0..self.nroots - 1 {
                parity[j] = parity[j + 1];
            }
            // New parity[nroots-1] from genpoly[0] coefficient.
            parity[self.nroots - 1] = if feedback != A0 {
                let g_log = self.genpoly_log[0] as usize;
                self.alpha_to[mod_nn(feedback + g_log)]
            } else {
                0
            };
        }

        parity_out.copy_from_slice(&parity);
        Ok(())
    }
}

/// Build `(alpha_to, index_of)` tables for GF(2^8) with the supplied
/// primitive polynomial. Mirrors AOSP `init_rs_char`'s table setup.
fn build_gf_tables() -> ([u8; 256], [u8; 256]) {
    let mut alpha_to = [0u8; 256];
    let mut index_of = [0u8; 256];

    // Generate alpha_to[i] = α^i, starting from α^0 = 1.
    let mut sr: u32 = 1;
    for alpha in alpha_to.iter_mut().take(NN as usize) {
        *alpha = sr as u8;
        // Multiply by α (= 2 in GF(2^8)) and reduce mod GF_POLY when degree ≥ 8.
        sr <<= 1;
        if sr & 0x100 != 0 {
            sr ^= GF_POLY;
        }
        sr &= 0xff;
    }
    // Mark NN-th slot as 0 sentinel; index_of[0] is set below to A0.
    alpha_to[NN as usize] = 0;

    // Build inverse table: index_of[α^i] = i.
    for slot in index_of.iter_mut() {
        *slot = A0 as u8; // 0 → A0 sentinel
    }
    for i in 0..(NN as usize) {
        index_of[alpha_to[i] as usize] = i as u8;
    }
    (alpha_to, index_of)
}

/// Build the AVB generator polynomial in log form for the given `nroots`.
/// AVB uses `fcr = 0`, `prim = 1`, so the consecutive roots are
/// α^0, α^1, …, α^(nroots-1).
fn build_genpoly_log(alpha_to: &[u8; 256], index_of: &[u8; 256], nroots: usize) -> Vec<u8> {
    // Build genpoly in *value* form first, then convert to log form at the
    // end. genpoly[0] is the lowest-degree coefficient; the monic top is
    // genpoly[nroots] = 1.
    let mut genpoly = vec![0u8; nroots + 1];
    genpoly[0] = 1;

    let fcr = 0usize;
    let prim = 1usize;
    let mut root = fcr * prim;
    for i in 0..nroots {
        // Multiply current polynomial by (x - α^root). Since GF(2^8) has
        // characteristic 2, subtraction equals XOR.
        genpoly[i + 1] = 1;
        for j in (1..=i).rev() {
            if genpoly[j] != 0 {
                let log_g = index_of[genpoly[j] as usize] as usize;
                genpoly[j] = genpoly[j - 1] ^ alpha_to[mod_nn(log_g + root)];
            } else {
                genpoly[j] = genpoly[j - 1];
            }
        }
        // genpoly[0] *= α^root.
        let log_g0 = index_of[genpoly[0] as usize] as usize;
        genpoly[0] = alpha_to[mod_nn(log_g0 + root)];

        root += prim;
    }

    // Convert to log form, matching libfec's storage convention.
    genpoly.iter().map(|&v| index_of[v as usize]).collect()
}

#[inline]
fn mod_nn(x: usize) -> usize {
    x % (NN as usize)
}

/// Number of 4096-byte source blocks covered by FEC.
#[inline]
fn fec_blocks(input_size: u64) -> u64 {
    input_size.div_ceil(FEC_BLOCKSIZE)
}

/// Number of RS interleave rounds for an input of `input_size` bytes.
#[inline]
fn fec_rounds(input_size: u64, nroots: u32) -> u64 {
    let rsn = (NN as u64) - u64::from(nroots);
    fec_blocks(input_size).div_ceil(rsn)
}

/// Actual AVB FEC data size for a given combined input length.
///
/// `input_size` is the number of bytes covered by FEC (typically the
/// partition's aligned data area concatenated with the dm-verity hash
/// tree). Result equals AOSP `image_ecc_new`: `rounds * nroots * 4096`.
///
/// This is the size written into the hashtree descriptor and appended to
/// the image. It does **not** include the external `fec` tool footer.
pub fn fec_size_for_input(input_size: u64, nroots: u32) -> u64 {
    fec_rounds(input_size, nroots) * u64::from(nroots) * FEC_BLOCKSIZE
}

/// Size returned by AOSP `fec --print-fec-size` / avbtool `calc_fec_data_size`.
///
/// Equals [`fec_size_for_input`] plus one 4096-byte FEC tool footer
/// (`fec_ecc_get_size`). Use this only for conservative partition budgeting
/// (`calc_max`); the descriptor and on-image FEC region use the actual size.
pub fn calc_fec_data_size(input_size: u64, nroots: u32) -> u64 {
    fec_size_for_input(input_size, nroots) + FEC_BLOCKSIZE
}

/// AOSP `fec` encoder requires a non-empty, 4096-byte-aligned input.
fn validate_fec_input_size(input_size: u64) -> Result<()> {
    if input_size == 0 {
        return Err(DynoError::Validation(
            "FEC input is empty; AOSP fec rejects empty files".into(),
        ));
    }
    if !input_size.is_multiple_of(FEC_BLOCKSIZE) {
        return Err(DynoError::Validation(format!(
            "FEC input size {} is not a multiple of {} bytes",
            input_size, FEC_BLOCKSIZE
        )));
    }
    Ok(())
}

/// Encode FEC over an in-memory input buffer using AOSP block interleaving.
///
/// Returns a buffer of length `fec_size_for_input(input.len(), nroots)`
/// containing only the parity stream (no tool footer).
///
/// # Errors
///
/// Returns an error when `nroots` is out of range, the input is empty, or
/// the input length is not a multiple of [`FEC_BLOCKSIZE`].
pub fn generate_fec_bytes(input: &[u8], nroots: u32) -> Result<Vec<u8>> {
    let input_size = input.len() as u64;
    validate_fec_input_size(input_size)?;
    let nroots_usize = nroots as usize;
    let encoder = ReedSolomonEncoder::new_avb(nroots_usize)?;
    let rsn = encoder.data_bytes_per_round();
    let rounds = fec_rounds(input_size, nroots);
    let blocks = fec_blocks(input_size);
    let total_size = fec_size_for_input(input_size, nroots) as usize;

    let mut out = vec![0u8; total_size];
    let mut parity_buf = vec![0u8; nroots_usize];
    let mut data = vec![0u8; rsn];
    // One interleave round: up to `rsn` source blocks (~1 MiB for roots=2).
    let mut source_blocks = vec![0u8; rsn * FEC_BLOCKSIZE as usize];
    let mut out_pos = 0usize;

    for round_idx in 0..rounds {
        source_blocks.fill(0);
        for j in 0..rsn {
            let block_idx = round_idx + (j as u64) * rounds;
            if block_idx < blocks {
                let start = (block_idx * FEC_BLOCKSIZE) as usize;
                let end = start + FEC_BLOCKSIZE as usize;
                let dst = j * FEC_BLOCKSIZE as usize;
                source_blocks[dst..dst + FEC_BLOCKSIZE as usize]
                    .copy_from_slice(&input[start..end]);
            }
        }

        for byte_in_block in 0..FEC_BLOCKSIZE as usize {
            for j in 0..rsn {
                data[j] = source_blocks[j * FEC_BLOCKSIZE as usize + byte_in_block];
            }
            encoder.encode_round(&data, &mut parity_buf)?;
            out[out_pos..out_pos + nroots_usize].copy_from_slice(&parity_buf);
            out_pos += nroots_usize;
        }
    }

    debug_assert_eq!(out_pos, total_size);
    Ok(out)
}

/// Encode FEC over the first `input_size` bytes of an image file using AOSP
/// block interleaving. Source blocks are read whole (no per-byte seeks).
///
/// # Errors
///
/// Returns an error when `nroots` is out of range, the input is empty/non-
/// aligned, or the image cannot supply `input_size` bytes.
pub fn generate_fec_from_image(
    image_filename: &Path,
    input_size: u64,
    nroots: u32,
) -> Result<Vec<u8>> {
    validate_fec_input_size(input_size)?;
    let nroots_usize = nroots as usize;
    let encoder = ReedSolomonEncoder::new_avb(nroots_usize)?;
    let rsn = encoder.data_bytes_per_round();
    let rounds = fec_rounds(input_size, nroots);
    let blocks = fec_blocks(input_size);
    let total_size = fec_size_for_input(input_size, nroots) as usize;

    let mut image = ImageHandler::open(image_filename, true).map_err(sparse_err)?;
    let mut out = vec![0u8; total_size];
    let mut parity_buf = vec![0u8; nroots_usize];
    let mut data = vec![0u8; rsn];
    let mut source_blocks = vec![0u8; rsn * FEC_BLOCKSIZE as usize];
    let mut out_pos = 0usize;

    for round_idx in 0..rounds {
        source_blocks.fill(0);
        for j in 0..rsn {
            let block_idx = round_idx + (j as u64) * rounds;
            if block_idx < blocks {
                let offset = block_idx * FEC_BLOCKSIZE;
                image.seek(offset).map_err(sparse_err)?;
                let buf = image.read(FEC_BLOCKSIZE as usize).map_err(sparse_err)?;
                if buf.len() != FEC_BLOCKSIZE as usize {
                    return Err(DynoError::Tool(
                        "Unexpected EOF while generating FEC from image".into(),
                    ));
                }
                let dst = j * FEC_BLOCKSIZE as usize;
                source_blocks[dst..dst + FEC_BLOCKSIZE as usize].copy_from_slice(&buf);
            }
        }

        for byte_in_block in 0..FEC_BLOCKSIZE as usize {
            for j in 0..rsn {
                data[j] = source_blocks[j * FEC_BLOCKSIZE as usize + byte_in_block];
            }
            encoder.encode_round(&data, &mut parity_buf)?;
            out[out_pos..out_pos + nroots_usize].copy_from_slice(&parity_buf);
            out_pos += nroots_usize;
        }
    }

    debug_assert_eq!(out_pos, total_size);
    Ok(out)
}

/// Reference (naive) AOSP interleave encoder used by tests.
#[cfg(test)]
fn generate_fec_bytes_naive(input: &[u8], nroots: u32) -> Result<Vec<u8>> {
    let input_size = input.len() as u64;
    validate_fec_input_size(input_size)?;
    let encoder = ReedSolomonEncoder::new_avb(nroots as usize)?;
    let rsn = encoder.data_bytes_per_round();
    let rounds = fec_rounds(input_size, nroots);
    let codewords = rounds * FEC_BLOCKSIZE;
    let mut out = Vec::with_capacity((codewords * u64::from(nroots)) as usize);
    let mut data = vec![0u8; rsn];
    let mut parity = vec![0u8; nroots as usize];
    for k in 0..codewords {
        for (j, symbol) in data.iter_mut().enumerate() {
            let offset = k + (j as u64) * rounds * FEC_BLOCKSIZE;
            *symbol = if offset < input_size {
                input[offset as usize]
            } else {
                0
            };
        }
        encoder.encode_round(&data, &mut parity)?;
        out.extend_from_slice(&parity);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn fec_size_matches_libfec_formula_for_avb_vendor_typical_case() {
        // Real Lenovo Y700 Gen 4 vendor.img: image_size + tree_size with
        // nroots = 2. Actual FEC data (no tool footer).
        let input_size = 1_511_202_816 + 11_907_072;
        assert_eq!(fec_size_for_input(input_size, 2), 12_042_240);
        assert_eq!(
            calc_fec_data_size(input_size, 2),
            12_042_240 + FEC_BLOCKSIZE
        );
    }

    #[test]
    fn fec_size_block_aligns() {
        for &nroots in &[1u32, 2, 3, 4] {
            for &size in &[0u64, 1, 4096, 4097, 1_000_000, 1024 * 1024] {
                let s = fec_size_for_input(size, nroots);
                assert!(
                    s.is_multiple_of(FEC_BLOCKSIZE),
                    "size {s} not 4096-aligned for input {size} roots {nroots}"
                );
                assert_eq!(calc_fec_data_size(size, nroots), s + FEC_BLOCKSIZE);
            }
        }
    }

    #[test]
    fn fec_size_one_mib_actual_roots_two_and_four() {
        let input_size = 1024 * 1024;
        // blocks=256; roots2 rsn=253 rounds=2 => 2*2*4096=16384
        // roots4 rsn=251 rounds=2 => 2*4*4096=32768
        assert_eq!(fec_size_for_input(input_size, 2), 16_384);
        assert_eq!(fec_size_for_input(input_size, 4), 32_768);
        assert_eq!(calc_fec_data_size(input_size, 2), 16_384 + FEC_BLOCKSIZE);
        assert_eq!(calc_fec_data_size(input_size, 4), 32_768 + FEC_BLOCKSIZE);
    }

    #[test]
    fn fec_aligned_input_is_deterministic() {
        let input = vec![0x5au8; 8192];
        let parity = generate_fec_bytes(&input, 2).unwrap();
        assert_eq!(
            parity.len(),
            fec_size_for_input(input.len() as u64, 2) as usize
        );
        let parity2 = generate_fec_bytes(&input, 2).unwrap();
        assert_eq!(parity, parity2);
    }

    #[test]
    fn rs_encoder_zero_input_yields_zero_parity() {
        let encoder = ReedSolomonEncoder::new_avb(2).unwrap();
        let mut parity = [0xffu8; 2];
        encoder.encode_round(&[0u8; 253], &mut parity).unwrap();
        assert_eq!(parity, [0u8, 0u8]);
    }

    #[test]
    fn generate_fec_rejects_empty_and_non_aligned() {
        let err = generate_fec_bytes(&[], 2).unwrap_err();
        assert!(err.to_string().contains("empty"));

        let err = generate_fec_bytes(&[1u8; 100], 2).unwrap_err();
        assert!(err.to_string().contains("multiple of"));
    }

    #[test]
    fn interleave_matches_manual_rs_for_two_rounds() {
        // roots=2, rsn=253: 254 blocks => rounds=2. Pattern tags every block.
        let blocks = 254u64;
        let mut input = vec![0u8; (blocks * FEC_BLOCKSIZE) as usize];
        for block_idx in 0..blocks {
            let start = (block_idx * FEC_BLOCKSIZE) as usize;
            let end = start + FEC_BLOCKSIZE as usize;
            let tag = (block_idx as u8).wrapping_mul(17).wrapping_add(3);
            input[start..end].fill(tag);
            // Distinct first bytes so codewords are not all identical.
            input[start] = block_idx as u8;
            if end - start > 1 {
                input[start + 1] = (block_idx >> 8) as u8;
            }
        }

        let actual = generate_fec_bytes(&input, 2).unwrap();
        let expected = generate_fec_bytes_naive(&input, 2).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 16_384);

        // Spot-check both rounds via ReedSolomonEncoder directly.
        let encoder = ReedSolomonEncoder::new_avb(2).unwrap();
        let rsn = encoder.data_bytes_per_round();
        let rounds = 2u64;
        for &(round_idx, byte_in_block) in &[(0u64, 0usize), (0, 1), (1, 0), (1, 4095)] {
            let k = round_idx * FEC_BLOCKSIZE + byte_in_block as u64;
            let mut data = vec![0u8; rsn];
            for (j, symbol) in data.iter_mut().enumerate() {
                let offset = k + (j as u64) * rounds * FEC_BLOCKSIZE;
                if offset < input.len() as u64 {
                    *symbol = input[offset as usize];
                }
            }
            let mut parity = [0u8; 2];
            encoder.encode_round(&data, &mut parity).unwrap();
            let out_off = (k as usize) * 2;
            assert_eq!(&actual[out_off..out_off + 2], &parity);
        }
    }

    #[test]
    fn in_memory_and_file_backed_fec_match() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("fec_src.bin");
        // 3 blocks: roots=2 => rounds=1.
        let mut input = vec![0u8; 3 * FEC_BLOCKSIZE as usize];
        for (i, b) in input.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        fs::write(&path, &input).unwrap();

        let mem = generate_fec_bytes(&input, 2).unwrap();
        let file = generate_fec_from_image(&path, input.len() as u64, 2).unwrap();
        assert_eq!(mem, file);
        assert_eq!(mem.len() as u64, fec_size_for_input(input.len() as u64, 2));
    }

    #[test]
    fn file_backed_rejects_non_aligned() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("odd.bin");
        fs::write(&path, vec![0u8; 100]).unwrap();
        let err = generate_fec_from_image(&path, 100, 2).unwrap_err();
        assert!(err.to_string().contains("multiple of"));
    }

    #[test]
    fn roots_two_and_four_produce_distinct_parity() {
        let input = vec![0x5au8; 8192];
        let p2 = generate_fec_bytes(&input, 2).unwrap();
        let p4 = generate_fec_bytes(&input, 4).unwrap();
        assert_eq!(p2.len() as u64, fec_size_for_input(input.len() as u64, 2));
        assert_eq!(p4.len() as u64, fec_size_for_input(input.len() as u64, 4));
        assert_ne!(p2, p4[..p2.len()]);
    }
}
