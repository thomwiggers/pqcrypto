#![feature(test)]
extern crate test;

use test::Bencher;

mod bench_sphincsharaka128ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka128ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka128srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka128srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka128fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka128fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka128frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka128frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka192ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka192ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka192srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka192srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka192fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka192fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka192frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka192frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka256ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka256ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka256srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka256srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka256fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka256fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsharaka256frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsharaka256frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256128ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256128ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256128srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256128srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256128fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256128fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256128frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256128frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256192ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256192ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256192srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256192srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256192fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256192fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256192frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256192frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256256ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256256ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256256srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256256srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256256fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256256fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincsshake256256frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincsshake256256frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256128ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256128ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256128srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256128srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256128fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256128fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256128frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256128frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256192ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256192ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256192srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256192srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256192fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256192fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256192frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256192frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256256ssimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256256ssimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256256srobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256256srobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256256fsimple {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256256fsimple::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}

mod bench_sphincssha256256frobust {
    use super::*;

    use pqcrypto_sphincsplus::sphincssha256256frobust::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| sign(&msg, &sk));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| detached_sign(&msg, &sk));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| open(&signed_msg, &pk).unwrap());
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| verify_detached_signature(&signed_msg, &msg, &pk).unwrap());
    }
}
