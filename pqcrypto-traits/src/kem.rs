/// Traits for Key-Encapsulation Mechanisms
use crate::Result;

/// A public key for a KEM
pub trait PublicKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized + Clone;
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A secret key for a KEM
pub trait SecretKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized + Clone;
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// The ciphertext to be sent to the other party to decapsulate.
pub trait Ciphertext {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized + Clone + Copy;
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// The shared secret that should be agreed on.
pub trait SharedSecret {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(bytes: &[u8]) -> Result<Self>
    where
        Self: Sized + Clone + Copy;
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}
