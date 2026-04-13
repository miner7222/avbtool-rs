pub mod error;
pub mod image;
pub mod crypto;
pub mod builder;
pub mod digest;
pub mod footer;
pub mod info;
pub mod parser;
pub mod resign;
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
