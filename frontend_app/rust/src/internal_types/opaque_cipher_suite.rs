use opaque_ke::{Ristretto255, TripleDh, argon2::Argon2, ciphersuite::CipherSuite};
use sha2::Sha512;

pub struct OpaqueCipherSuite;

impl CipherSuite for OpaqueCipherSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = Argon2<'static>;
}
