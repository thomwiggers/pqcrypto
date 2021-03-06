//! Foreign function interfaces
//!
//! This module defines the foreign function interface for the following
//! crypto implementations from PQClean:
//!
//!  * babybear
//!  * mamabear
//!  * papabear
// This file has been generated from PQClean.
// Find the templates in pqcrypto-template
use libc::c_int;

pub const PQCLEAN_BABYBEAR_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 40;
pub const PQCLEAN_BABYBEAR_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 804;
pub const PQCLEAN_BABYBEAR_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 917;
pub const PQCLEAN_BABYBEAR_CLEAN_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_MAMABEAR_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 40;
pub const PQCLEAN_MAMABEAR_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1194;
pub const PQCLEAN_MAMABEAR_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1307;
pub const PQCLEAN_MAMABEAR_CLEAN_CRYPTO_BYTES: usize = 32;
pub const PQCLEAN_PAPABEAR_CLEAN_CRYPTO_SECRETKEYBYTES: usize = 40;
pub const PQCLEAN_PAPABEAR_CLEAN_CRYPTO_PUBLICKEYBYTES: usize = 1584;
pub const PQCLEAN_PAPABEAR_CLEAN_CRYPTO_CIPHERTEXTBYTES: usize = 1697;
pub const PQCLEAN_PAPABEAR_CLEAN_CRYPTO_BYTES: usize = 32;

#[link(name = "threebears")]
extern "C" {
    pub fn PQCLEAN_BABYBEAR_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_BABYBEAR_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_BABYBEAR_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;

    pub fn PQCLEAN_MAMABEAR_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_MAMABEAR_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_MAMABEAR_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;

    pub fn PQCLEAN_PAPABEAR_CLEAN_crypto_kem_keypair(pk: *mut u8, sk: *mut u8) -> c_int;
    pub fn PQCLEAN_PAPABEAR_CLEAN_crypto_kem_enc(ct: *mut u8, ss: *mut u8, pk: *const u8) -> c_int;
    pub fn PQCLEAN_PAPABEAR_CLEAN_crypto_kem_dec(
        ss: *mut u8,
        ct: *const u8,
        sk: *const u8,
    ) -> c_int;

}

#[cfg(test)]
mod test_babybear_clean {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = [0u8; PQCLEAN_BABYBEAR_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_BABYBEAR_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = [0u8; PQCLEAN_BABYBEAR_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = [0u8; PQCLEAN_BABYBEAR_CLEAN_CRYPTO_BYTES];
            let mut ss2 = [0u8; PQCLEAN_BABYBEAR_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_BABYBEAR_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_BABYBEAR_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_BABYBEAR_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
#[cfg(test)]
mod test_mamabear_clean {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = [0u8; PQCLEAN_MAMABEAR_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_MAMABEAR_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = [0u8; PQCLEAN_MAMABEAR_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = [0u8; PQCLEAN_MAMABEAR_CLEAN_CRYPTO_BYTES];
            let mut ss2 = [0u8; PQCLEAN_MAMABEAR_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_MAMABEAR_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_MAMABEAR_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_MAMABEAR_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
#[cfg(test)]
mod test_papabear_clean {
    use super::*;

    #[test]
    fn test_ffi() {
        unsafe {
            let mut pk = [0u8; PQCLEAN_PAPABEAR_CLEAN_CRYPTO_PUBLICKEYBYTES];
            let mut sk = [0u8; PQCLEAN_PAPABEAR_CLEAN_CRYPTO_SECRETKEYBYTES];
            let mut ct = [0u8; PQCLEAN_PAPABEAR_CLEAN_CRYPTO_CIPHERTEXTBYTES];
            let mut ss1 = [0u8; PQCLEAN_PAPABEAR_CLEAN_CRYPTO_BYTES];
            let mut ss2 = [0u8; PQCLEAN_PAPABEAR_CLEAN_CRYPTO_BYTES];

            assert_eq!(
                0,
                PQCLEAN_PAPABEAR_CLEAN_crypto_kem_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
            );
            assert_eq!(
                0,
                PQCLEAN_PAPABEAR_CLEAN_crypto_kem_enc(
                    ct.as_mut_ptr(),
                    ss1.as_mut_ptr(),
                    pk.as_ptr()
                )
            );
            assert_eq!(
                0,
                PQCLEAN_PAPABEAR_CLEAN_crypto_kem_dec(ss2.as_mut_ptr(), ct.as_ptr(), sk.as_ptr())
            );
            assert_eq!(&ss1[..], &ss2[..], "Shared secrets should be equal");
        }
    }
}
