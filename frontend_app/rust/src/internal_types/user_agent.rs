pub(crate) fn get_user_agent() -> String {
    format!(
        "RustVault-SDK/{} Standalone (Rust; reqwest; +https://rustvault.ru)",
        env!("CARGO_PKG_VERSION")
    )
}