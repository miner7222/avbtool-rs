use crate::error::{AvbToolError as DynoError, Result};
use byteorder::{BigEndian, ReadBytesExt};
use num_bigint_dig::{BigInt, Sign};
use num_integer::Integer;
use num_traits::Signed;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{BigUint, RsaPrivateKey, traits::PrivateKeyParts, traits::PublicKeyParts};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use std::io::Cursor;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvbAlgorithm {
    pub name: &'static str,
    pub algorithm_type: u32,
    pub hash_name: &'static str,
    pub hash_num_bytes: usize,
    pub signature_num_bytes: usize,
    pub public_key_num_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct AvbPublicKey {
    pub num_bits: u32,
    pub modulus: BigUint,
}

pub struct AvbKey {
    private_key: RsaPrivateKey,
}

impl AvbKey {
    pub fn load_pem(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| DynoError::Tool(format!("Failed to load RSA key: {}", e)))?;

        Ok(Self { private_key })
    }

    pub fn bits(&self) -> u32 {
        (self.private_key.size() * 8) as u32
    }

    pub fn algorithm(&self) -> Result<String> {
        default_algorithm_name_for_bits(self.bits()).map(str::to_string)
    }

    pub fn encode_public_key(&self) -> Vec<u8> {
        let n = self.private_key.n();
        let num_bits = self.bits();

        let b = BigUint::from(1u64 << 32);
        let n_mod_b = n % &b;
        let n0inv = if let Some(inv) = mod_inverse(&n_mod_b, &b) {
            let n0inv_val = &b - (inv % &b);
            let bytes = n0inv_val.to_bytes_le();
            let mut buf = [0u8; 4];
            let len = std::cmp::min(bytes.len(), 4);
            buf[..len].copy_from_slice(&bytes[..len]);
            u32::from_le_bytes(buf)
        } else {
            0
        };

        let r = BigUint::from(1u8) << (n.bits() as usize);
        let rr = (&r * &r) % n;

        let mut ret = Vec::new();
        ret.extend_from_slice(&num_bits.to_be_bytes());
        ret.extend_from_slice(&n0inv.to_be_bytes());
        ret.extend(encode_biguint(n, num_bits / 8));
        ret.extend(encode_biguint(&rr, num_bits / 8));
        ret
    }

    pub fn public_key_sha1(&self) -> String {
        let mut hasher = Sha1::new();
        hasher.update(self.encode_public_key());
        format!("{:x}", hasher.finalize())
    }

    pub fn sign(&self, data: &[u8], algorithm_name: &str) -> Result<Vec<u8>> {
        let algorithm = lookup_algorithm_by_name(algorithm_name)?;
        if algorithm.name == "NONE" {
            return Ok(Vec::new());
        }
        if self.bits() as usize != algorithm.signature_num_bytes * 8 {
            return Err(DynoError::Tool(format!(
                "Requested algorithm {} does not match key size {}",
                algorithm_name,
                self.bits()
            )));
        }

        let mut to_sign = build_pkcs1_message(algorithm, data)?;
        let n = self.private_key.n();
        let d = self.private_key.d();
        let m = BigUint::from_bytes_be(&to_sign);
        let s = m.modpow(d, n);
        to_sign.fill(0);

        Ok(encode_biguint(&s, self.bits() / 8))
    }

    pub fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data, &self.algorithm()?)
    }
}

impl AvbPublicKey {
    pub fn decode(blob: &[u8]) -> Result<Self> {
        if blob.len() < 8 {
            return Err(DynoError::Tool("AVB public key blob too small".into()));
        }
        let mut cursor = Cursor::new(blob);
        let num_bits = cursor.read_u32::<BigEndian>()?;
        let _n0inv = cursor.read_u32::<BigEndian>()?;
        let word_len = (num_bits as usize) / 8;
        let expected_size = 8 + word_len * 2;
        if blob.len() != expected_size {
            return Err(DynoError::Tool(format!(
                "AVB public key blob size mismatch: expected {}, got {}",
                expected_size,
                blob.len()
            )));
        }
        let modulus = BigUint::from_bytes_be(&blob[8..8 + word_len]);
        Ok(Self { num_bits, modulus })
    }

    pub fn verify(&self, algorithm: AvbAlgorithm, signature: &[u8], data: &[u8]) -> Result<bool> {
        if algorithm.name == "NONE" {
            return Ok(true);
        }
        if signature.len() != algorithm.signature_num_bytes {
            return Ok(false);
        }
        if self.num_bits as usize != algorithm.signature_num_bytes * 8 {
            return Ok(false);
        }

        let exponent = BigUint::from(65537u32);
        let signature_value = BigUint::from_bytes_be(signature);
        let message = signature_value.modpow(&exponent, &self.modulus);
        let decoded = encode_biguint(&message, self.num_bits / 8);
        let expected = build_pkcs1_message(algorithm, data)?;
        Ok(decoded == expected)
    }
}

pub fn get_embedded_key(name: &str) -> Option<&'static str> {
    match name {
        "testkey_rsa2048" => Some(include_str!("keys/testkey_rsa2048.pem")),
        "testkey_rsa2048_2" => Some(include_str!("keys/testkey_rsa2048_2.pem")),
        "testkey_rsa4096" => Some(include_str!("keys/testkey_rsa4096.pem")),
        "testkey_rsa8192" => Some(include_str!("keys/testkey_rsa8192.pem")),
        _ => None,
    }
}

pub fn load_key_from_spec(key_spec: &str) -> Result<AvbKey> {
    if let Some(pem) = get_embedded_key(key_spec) {
        AvbKey::from_pem(pem)
    } else {
        AvbKey::load_pem(Path::new(key_spec))
    }
}

pub fn extract_public_key(key_spec: &str) -> Result<Vec<u8>> {
    Ok(load_key_from_spec(key_spec)?.encode_public_key())
}

pub fn extract_public_key_digest(key_spec: &str) -> Result<String> {
    let public_key = extract_public_key(key_spec)?;
    let digest = Sha256::digest(public_key);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub fn lookup_algorithm_by_name(name: &str) -> Result<AvbAlgorithm> {
    match name {
        "NONE" => Ok(AvbAlgorithm {
            name: "NONE",
            algorithm_type: 0,
            hash_name: "",
            hash_num_bytes: 0,
            signature_num_bytes: 0,
            public_key_num_bytes: 0,
        }),
        "SHA256_RSA2048" => Ok(AvbAlgorithm {
            name: "SHA256_RSA2048",
            algorithm_type: 1,
            hash_name: "sha256",
            hash_num_bytes: 32,
            signature_num_bytes: 256,
            public_key_num_bytes: 8 + 2 * 2048 / 8,
        }),
        "SHA256_RSA4096" => Ok(AvbAlgorithm {
            name: "SHA256_RSA4096",
            algorithm_type: 2,
            hash_name: "sha256",
            hash_num_bytes: 32,
            signature_num_bytes: 512,
            public_key_num_bytes: 8 + 2 * 4096 / 8,
        }),
        "SHA256_RSA8192" => Ok(AvbAlgorithm {
            name: "SHA256_RSA8192",
            algorithm_type: 3,
            hash_name: "sha256",
            hash_num_bytes: 32,
            signature_num_bytes: 1024,
            public_key_num_bytes: 8 + 2 * 8192 / 8,
        }),
        "SHA512_RSA2048" => Ok(AvbAlgorithm {
            name: "SHA512_RSA2048",
            algorithm_type: 4,
            hash_name: "sha512",
            hash_num_bytes: 64,
            signature_num_bytes: 256,
            public_key_num_bytes: 8 + 2 * 2048 / 8,
        }),
        "SHA512_RSA4096" => Ok(AvbAlgorithm {
            name: "SHA512_RSA4096",
            algorithm_type: 5,
            hash_name: "sha512",
            hash_num_bytes: 64,
            signature_num_bytes: 512,
            public_key_num_bytes: 8 + 2 * 4096 / 8,
        }),
        "SHA512_RSA8192" => Ok(AvbAlgorithm {
            name: "SHA512_RSA8192",
            algorithm_type: 6,
            hash_name: "sha512",
            hash_num_bytes: 64,
            signature_num_bytes: 1024,
            public_key_num_bytes: 8 + 2 * 8192 / 8,
        }),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported AVB algorithm {}",
            other
        ))),
    }
}

pub fn lookup_algorithm_by_type(algorithm_type: u32) -> Result<AvbAlgorithm> {
    match algorithm_type {
        0 => lookup_algorithm_by_name("NONE"),
        1 => lookup_algorithm_by_name("SHA256_RSA2048"),
        2 => lookup_algorithm_by_name("SHA256_RSA4096"),
        3 => lookup_algorithm_by_name("SHA256_RSA8192"),
        4 => lookup_algorithm_by_name("SHA512_RSA2048"),
        5 => lookup_algorithm_by_name("SHA512_RSA4096"),
        6 => lookup_algorithm_by_name("SHA512_RSA8192"),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported AVB algorithm type {}",
            other
        ))),
    }
}

pub fn default_algorithm_name_for_bits(bits: u32) -> Result<&'static str> {
    match bits {
        2048 => Ok("SHA256_RSA2048"),
        4096 => Ok("SHA256_RSA4096"),
        8192 => Ok("SHA256_RSA8192"),
        _ => Err(DynoError::Tool(format!(
            "No standard AVB algorithm for {} bits",
            bits
        ))),
    }
}

pub fn compute_hash_for_algorithm(algorithm: AvbAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm.hash_name {
        "" => Ok(Vec::new()),
        "sha256" => Ok(Sha256::digest(data).to_vec()),
        "sha512" => Ok(Sha512::digest(data).to_vec()),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported AVB hash algorithm {}",
            other
        ))),
    }
}

pub fn round_to_multiple(number: u64, size: u64) -> u64 {
    let remainder = number % size;
    if remainder == 0 {
        number
    } else {
        number + size - remainder
    }
}

pub fn round_to_pow2(number: usize) -> usize {
    if number <= 1 {
        1
    } else {
        1usize << (usize::BITS as usize - (number - 1).leading_zeros() as usize)
    }
}

fn build_pkcs1_message(algorithm: AvbAlgorithm, data: &[u8]) -> Result<Vec<u8>> {
    if algorithm.name == "NONE" {
        return Ok(Vec::new());
    }

    let digest = compute_hash_for_algorithm(algorithm, data)?;
    let prefix = digest_info_prefix(algorithm.hash_name)?;
    let key_size = algorithm.signature_num_bytes;
    let pad_len = key_size
        .checked_sub(3 + prefix.len() + digest.len())
        .ok_or_else(|| DynoError::Tool("RSA key too small for digest padding".into()))?;

    let mut out = Vec::with_capacity(key_size);
    out.push(0x00);
    out.push(0x01);
    out.extend(std::iter::repeat_n(0xff, pad_len));
    out.push(0x00);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&digest);
    Ok(out)
}

fn digest_info_prefix(hash_name: &str) -> Result<&'static [u8]> {
    match hash_name {
        "sha256" => Ok(&[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
        ]),
        "sha512" => Ok(&[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
            0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
        ]),
        other => Err(DynoError::UnsupportedOperation(format!(
            "Unsupported digest info prefix for {}",
            other
        ))),
    }
}

fn encode_biguint(val: &BigUint, len: u32) -> Vec<u8> {
    let bytes = val.to_bytes_be();
    if bytes.len() >= len as usize {
        bytes[bytes.len() - len as usize..].to_vec()
    } else {
        let mut ret = vec![0u8; len as usize - bytes.len()];
        ret.extend_from_slice(&bytes);
        ret
    }
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let a_bytes = a.to_bytes_be();
    let m_bytes = m.to_bytes_be();
    let a_dig = BigInt::from_bytes_be(Sign::Plus, &a_bytes);
    let m_dig = BigInt::from_bytes_be(Sign::Plus, &m_bytes);

    let egcd = a_dig.extended_gcd(&m_dig);
    if egcd.gcd != BigInt::from(1) {
        return None;
    }

    let mut res = egcd.x % &m_dig;
    if res.is_negative() {
        res += &m_dig;
    }

    let (_, res_bytes) = res.to_bytes_be();
    Some(BigUint::from_bytes_be(&res_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_public_key_digest_is_sha256_hex() {
        let digest = extract_public_key_digest("testkey_rsa2048").unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = load_key_from_spec("testkey_rsa2048").unwrap();
        let algorithm = lookup_algorithm_by_name("SHA256_RSA2048").unwrap();
        let public_key = AvbPublicKey::decode(&key.encode_public_key()).unwrap();
        let signature = key.sign(b"hello", algorithm.name).unwrap();
        assert!(public_key.verify(algorithm, &signature, b"hello").unwrap());
    }
}
