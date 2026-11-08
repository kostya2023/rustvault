// Init - DO NOT TOUCH
#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    flutter_rust_bridge::setup_default_user_utils();
}

// Mods
pub mod types;
pub mod clients;
