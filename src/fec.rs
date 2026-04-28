//! Reed-Solomon FEC encoder for AVB-style hashtree FEC regions.
//!
//! AVB's FEC matches the configuration `init_rs_char(8, 0x11d, 0, 1, nroots, 0)`
//! used by AOSP's `system/extras/libfec`:
//!
//!   * `symsize = 8`     — bytes are GF(2^8) symbols
//!   * `gfpoly  = 0x11d` — primitive polynomial x^8 + x^4 + x^3 + x^2 + 1
//!   * `fcr     = 0`     — first consecutive root α^0 = 1
//!   * `prim    = 1`     — primitive element step
//!   * `nroots  = 2`     — typical AVB choice; corrects 1 byte / RS codeword
//!
//! Encoding is systematic. Each "round" consumes `255 - nroots` data bytes
//! (zero-padded for the final round) and produces `nroots` parity bytes.
//! AVB writes only the parity stream out, concatenating all rounds; the
//! data is consulted again during recovery from disk. The total parity
//! byte count is rounded up to the next multiple of `FEC_BLOCKSIZE`
//! (`4096`) by zero-padding the tail.
//!
//! The FEC input is the data area of the partition concatenated with the
//! dm-verity hash tree, in that order. Use [`generate_fec_bytes`] when you
//! already hold the input in memory, or [`generate_fec_from_image`] to
//! stream it from a file (for multi-GB partitions where holding the full
//! buffer is wasteful).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::{AvbToolError as DynoError, Result};

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

    /// Number of data bytes consumed per round (`255 - nroots`).
    pub fn data_bytes_per_round(&self) -> usize {
        (NN as usize) - self.nroots
    }

    /// Produce `nroots` parity bytes for one round. `data` must have at
    /// most `data_bytes_per_round()` bytes; missing tail bytes are treated
    /// as zero, matching libfec's pad behavior on the final round.
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
        // libfec's pad-with-zero behavior on the final round.
        let mut parity = vec![0u8; self.nroots];
        for i in 0..rsn {
            let symbol = if i < data.len() { data[i] } else { 0u8 };
            let feedback_value = symbol ^ parity[0];
            let feedback = self.index_of[feedback_value as usize] as usize;

            if feedback != A0 {
                // parity[j] ^= alpha_to[(feedback + genpoly_log[nroots - j]) mod 255]
                // for j in 1..nroots
                for j in 1..self.nroots {
                    let g_log = self.genpoly_log[self.nroots - j] as usize;
                    let idx = mod_nn(feedback + g_log);
                    parity[j] ^= self.alpha_to[idx];
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
    for i in 0..(NN as usize) {
        alpha_to[i] = sr as u8;
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
    for i in 0..256 {
        index_of[i] = A0 as u8; // 0 → A0 sentinel
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

/// Compute the AVB FEC region size for a given combined input length.
/// `input_size` is the number of bytes covered by FEC (typically the
/// partition's aligned data area concatenated with the dm-verity hash
/// tree). Result is rounded up to [`FEC_BLOCKSIZE`].
pub fn fec_size_for_input(input_size: u64, nroots: u32) -> u64 {
    let rsn = (NN as u64) - nroots as u64;
    let rounds = input_size.div_ceil(rsn);
    let bytes = rounds * nroots as u64;
    round_up_to_block(bytes)
}

fn round_up_to_block(value: u64) -> u64 {
    (value + FEC_BLOCKSIZE - 1) & !(FEC_BLOCKSIZE - 1)
}

/// Encode FEC over an in-memory input buffer.
///
/// Returns a buffer of length `fec_size_for_input(input.len(), nroots)`
/// containing the parity stream followed by zero padding.
pub fn generate_fec_bytes(input: &[u8], nroots: u32) -> Result<Vec<u8>> {
    let nroots = nroots as usize;
    let encoder = ReedSolomonEncoder::new_avb(nroots)?;
    let rsn = encoder.data_bytes_per_round();
    let total_size = fec_size_for_input(input.len() as u64, nroots as u32) as usize;
    let mut out = Vec::with_capacity(total_size);

    let mut offset = 0usize;
    let mut parity_buf = vec![0u8; nroots];
    while offset < input.len() {
        let end = (offset + rsn).min(input.len());
        let chunk = &input[offset..end];
        encoder.encode_round(chunk, &mut parity_buf)?;
        out.extend_from_slice(&parity_buf);
        offset += rsn;
    }
    // Zero-pad up to FEC_BLOCKSIZE multiple.
    out.resize(total_size, 0);
    Ok(out)
}

/// Encode FEC over the first `input_size` bytes of an image file. The
/// stream is read in `rsn`-sized chunks from the supplied path; the
/// returned buffer matches the layout of AVB's `fec` region.
pub fn generate_fec_from_image(
    image_filename: &Path,
    input_size: u64,
    nroots: u32,
) -> Result<Vec<u8>> {
    let nroots = nroots as usize;
    let encoder = ReedSolomonEncoder::new_avb(nroots)?;
    let rsn = encoder.data_bytes_per_round();
    let total_size = fec_size_for_input(input_size, nroots as u32) as usize;
    let mut out = Vec::with_capacity(total_size);

    let mut file = File::open(image_filename)?;
    file.seek(SeekFrom::Start(0))?;
    let mut data_buf = vec![0u8; rsn];
    let mut parity_buf = vec![0u8; nroots];
    let mut remaining = input_size;
    while remaining > 0 {
        let to_read = remaining.min(rsn as u64) as usize;
        let buf = &mut data_buf[..to_read];
        file.read_exact(buf)?;
        encoder.encode_round(buf, &mut parity_buf)?;
        out.extend_from_slice(&parity_buf);
        remaining -= to_read as u64;
    }
    out.resize(total_size, 0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fec_size_matches_libfec_formula_for_avb_vendor_typical_case() {
        // Real Lenovo Y700 Gen 4 vendor.img: image_size + tree_size with
        // nroots = 2. Should round up to the descriptor's recorded value.
        let input_size = 1_511_202_816 + 11_907_072;
        assert_eq!(fec_size_for_input(input_size, 2), 12_042_240);
    }

    #[test]
    fn fec_size_block_aligns() {
        for &nroots in &[1u32, 2, 3, 4] {
            for &size in &[0u64, 1, 4096, 4097, 1_000_000] {
                let s = fec_size_for_input(size, nroots);
                assert!(s % FEC_BLOCKSIZE == 0, "size {s} not 4096-aligned");
            }
        }
    }

    #[test]
    fn fec_short_input_round_trip() {
        // Encode a short string with nroots=2; verify length matches the
        // formula and parity bytes are deterministic.
        let input = b"Hello, AVB FEC test. Quick brown fox jumps over lazy dog.".to_vec();
        let parity = generate_fec_bytes(&input, 2).unwrap();
        assert_eq!(
            parity.len(),
            fec_size_for_input(input.len() as u64, 2) as usize
        );
        // Two encodings of the same input must agree byte-for-byte.
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
}
