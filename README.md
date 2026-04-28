# avbtool-rs

Pure Rust avbtool

## Goals

- standalone AVB parse/info/sign/verify/footer tooling
- exact `avbtool.py`-style CLI spellings for implemented commands
- pure Rust operation on Windows without Python/WSL

## Implemented

- `version`
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
- `info_image`
- `verify_image`
- `print_partition_digests`
- `calculate_vbmeta_digest`
- `calculate_kernel_cmdline`
- `set_ab_metadata`
- `resign_image`

## CLI compatibility

Binary accepts `avbtool.py` command spellings like:

```powershell
avbtool-rs info_image --image vbmeta.img
avbtool-rs make_vbmeta_image --algorithm SHA256_RSA2048 --key testkey_rsa2048 --output vbmeta.img
avbtool-rs add_hash_footer --image boot.img --partition_size 12288 --partition_name boot --algorithm SHA256_RSA2048 --key testkey_rsa2048
```

Implemented commands accept Python-style underscore flags such as `--partition_size`, `--rollback_index_location`, `--print_required_libavb_version`.

Unsupported subcommands or unsupported advanced options fail with clear error instead of silent mismatch.

## Upstream reference

Based on AOSP `platform/external/avb` at commit [`4a4e2c8`](https://android.googlesource.com/platform/external/avb/+/4a4e2c8a6592b88cf18b10fe5406f53a2a5d26cf).

## Notes

- `signing_helper` / `signing_helper_with_files` not implemented
- ML-DSA not implemented
- ATX certificate commands are not implemented yet

## Build

```powershell
cargo build --release
cargo test
```
