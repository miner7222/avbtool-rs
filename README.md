# avbtool-rs

Pure Rust reimplementation of AOSP `avbtool` for standalone AVB parse/info/sign/verify/footer tooling.

## Goals

- exact `avbtool.py`-style CLI spellings for implemented commands
- pure Rust operation on Windows without Python/WSL
- pure-Rust RSA + ML-DSA signing, Android sparse image handling, and avb_cert/ATX helpers

## Implemented commands

- `version` (prints `avbtool 1.4.0`)
- `check_mldsa_support`
- `generate_test_image`
- `extract_public_key`
- `extract_public_key_digest`
- `make_vbmeta_image`
- `append_vbmeta_image`
- `add_hash_footer`
- `add_hashtree_footer`
- `erase_footer`
- `zero_hashtree`
- `extract_vbmeta_image`
- `resize_image`
- `info_image` (`--cert` / `--atx`)
- `verify_image`
- `print_partition_digests`
- `calculate_vbmeta_digest`
- `calculate_kernel_cmdline`
- `set_ab_metadata`
- `resign_image` (`--algorithm` required, like upstream)
- `update_partition_descriptor`
- `make_certificate` / `make_atx_certificate`
- `make_cert_permanent_attributes` / `make_atx_permanent_attributes`
- `make_cert_metadata` / `make_atx_metadata`
- `make_cert_unlock_credential` / `make_atx_unlock_credential`

Unknown subcommands fail closed.

## CLI compatibility

Binary accepts `avbtool.py` command spellings and underscore flags:

```powershell
avbtool-rs version
avbtool-rs check_mldsa_support
avbtool-rs info_image --image vbmeta.img --cert
avbtool-rs make_vbmeta_image --algorithm SHA256_RSA2048 --key testkey_rsa2048 --output vbmeta.img
avbtool-rs add_hash_footer --image boot.img --partition_size 131072 --partition_name boot --algorithm SHA256_RSA2048 --key testkey_rsa2048
avbtool-rs add_hashtree_footer --image system.img --partition_size 1048576 --partition_name system --hash_algorithm sha256 --fec_num_roots 2
avbtool-rs resign_image --image boot.img --key testkey_rsa2048 --algorithm SHA256_RSA2048
```

Supported AOSP option surface includes:

- `--signing_helper` / `--signing_helper_with_files`
- ML-DSA algorithms `MLDSA65` / `MLDSA87`
- `--use_persistent_digest` (alias: `--use_persistent_root_digest`)
- `--setup_rootfs_from_kernel` (alias: `--generate_dm_verity_cmdline_from_hashtree`)
- `--setup_as_rootfs_from_kernel`
- `--set_hashtree_disabled_flag` / `--set_verification_disabled_flag`
- `--internal_release_string`
- `--calc_max_image_size` for hash and hashtree footers
- arbitrary `--fec_num_roots`
- SHA-1 default warning + deprecated `--generate_fec` warning on `add_hashtree_footer`

## Pure-Rust support

- RSA and ML-DSA signing/verification without OpenSSL
- Android sparse image I/O via `sparse` module
- avb_cert / ATX certificate, permanent attributes, metadata, unlock credential helpers
- external signing helpers for RSA and ML-DSA

## Intentional local extensions

Preserved without weakening AOSP defaults:

- `info_image --format json` and multi-file/directory scan report mode
- `verify_image --format json`
- `print_partition_digests` JSON formatting helpers
- `resign_image --force` for local key/size override workflows
- embedded test keys (`testkey_rsa*`, `testkey_mldsa*`) for offline use

`resign_image --algorithm` is required like upstream.

## Upstream reference

Based on AOSP `platform/external/avb` main-kernel checkout at commit
[`4e48849c766dcbe8ff8623509f7f8d0f5f8f04dc`](https://android.googlesource.com/platform/external/avb/+/4e48849c766dcbe8ff8623509f7f8d0f5f8f04dc)
(`avbtool 1.4.0`).

## Build

```powershell
cargo build --release
cargo test
```
