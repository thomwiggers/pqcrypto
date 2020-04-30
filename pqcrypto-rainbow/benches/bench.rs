#![feature(test)]
extern crate test;

use test::Bencher;

mod bench_rainbowiiicclassic {
    use super::*;

    use pqcrypto_rainbow::rainbowiiicclassic::{
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

mod bench_rainbowiiiccyclic {
    use super::*;

    use pqcrypto_rainbow::rainbowiiiccyclic::{
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

mod bench_rainbowiiiccycliccompressed {
    use super::*;

    use pqcrypto_rainbow::rainbowiiiccycliccompressed::{
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

mod bench_rainbowiaclassic {
    use super::*;

    use pqcrypto_rainbow::rainbowiaclassic::{
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

mod bench_rainbowiacyclic {
    use super::*;

    use pqcrypto_rainbow::rainbowiacyclic::{
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

mod bench_rainbowiacycliccompressed {
    use super::*;

    use pqcrypto_rainbow::rainbowiacycliccompressed::{
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

mod bench_rainbowvcclassic {
    use super::*;

    use pqcrypto_rainbow::rainbowvcclassic::{
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

mod bench_rainbowvccyclic {
    use super::*;

    use pqcrypto_rainbow::rainbowvccyclic::{
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

mod bench_rainbowvccycliccompressed {
    use super::*;

    use pqcrypto_rainbow::rainbowvccycliccompressed::{
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
