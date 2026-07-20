pub mod builder;
pub mod cert;
pub mod cmdline;
pub mod crypto;
pub mod digest;
pub mod error;
pub mod fec;
pub mod footer;
pub mod image;
pub mod info;
pub mod parser;
pub mod resign;
pub mod sparse;
pub mod verify;

pub fn component_scope() -> &'static str {
    "standalone AVB parsing, signing, verification, and vbmeta tooling"
}

#[cfg(test)]
mod tests {
    use super::component_scope;

    #[test]
    fn scope_mentions_vbmeta() {
        assert!(component_scope().contains("vbmeta"));
    }
}
