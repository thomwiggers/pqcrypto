#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

mod bench_qteslapi {
    use super::*;

    use pqcrypto_qtesla::qteslapi::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| black_box(keypair()));
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| black_box(sign(&msg, &sk)));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| black_box(detached_sign(&msg, &sk)));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| black_box(open(&signed_msg, &pk).unwrap()));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| black_box(verify_detached_signature(&signed_msg, &msg, &pk).unwrap()));
    }
}

mod bench_qteslapiii {
    use super::*;

    use pqcrypto_qtesla::qteslapiii::{
        detached_sign, keypair, open, sign, verify_detached_signature,
    };

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| black_box(keypair()));
    }

    #[bench]
    fn bench_sign(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| black_box(sign(&msg, &sk)));
    }

    #[bench]
    fn bench_sign_detached(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (_pk, sk) = keypair();
        b.iter(|| black_box(detached_sign(&msg, &sk)));
    }

    #[bench]
    fn bench_open(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = sign(&msg, &sk);
        b.iter(|| black_box(open(&signed_msg, &pk).unwrap()));
    }

    #[bench]
    fn bench_verify(b: &mut Bencher) {
        let msg = [0u8; 100];
        let (pk, sk) = keypair();
        let signed_msg = detached_sign(&msg, &sk);
        b.iter(|| black_box(verify_detached_signature(&signed_msg, &msg, &pk).unwrap()));
    }
}
