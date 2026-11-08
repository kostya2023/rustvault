use backend_app::types::opaque_cipher_suite::OpaqueCipherSuite;
use base64::{Engine, engine::general_purpose::STANDARD};
use opaque_ke::{ServerSetup, rand::rngs::OsRng};
use std::fs::read;

fn main() {
    let jwt_private = read("jwt_private.pem").unwrap();
    let jwt_public = read("jwt_public.pem").unwrap();

    let mut totp_encrypt_key = [42u8; 32];
    rand::fill(&mut totp_encrypt_key);

    let mut rng = OsRng;
    let opaque_server_setup = ServerSetup::<OpaqueCipherSuite>::new(&mut rng);
    let opaque_server_setup = opaque_server_setup.serialize().to_vec();

    let jwt_private = STANDARD.encode(&jwt_private);
    let jwt_public = STANDARD.encode(&jwt_public);
    let totp_encrypt_key = STANDARD.encode(&totp_encrypt_key);
    let opaque_server_setup = STANDARD.encode(&opaque_server_setup);

    println!("JWT: {jwt_private}");
    println!("JWT_PUB: {jwt_public}");
    println!("TOTP: {totp_encrypt_key}");
    println!("OPAQUE: {opaque_server_setup}");
}
