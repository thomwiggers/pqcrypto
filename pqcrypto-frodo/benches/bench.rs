#![feature(test)]
extern crate test;

use test::Bencher;

mod bench_frodokem640shake {
    use super::*;

    use pqcrypto_frodo::frodokem640shake::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| encapsulate(&pk));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| decapsulate(&ct, &sk));
    }
}

mod bench_frodokem640aes {
    use super::*;

    use pqcrypto_frodo::frodokem640aes::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| encapsulate(&pk));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| decapsulate(&ct, &sk));
    }
}

mod bench_frodokem976aes {
    use super::*;

    use pqcrypto_frodo::frodokem976aes::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| encapsulate(&pk));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| decapsulate(&ct, &sk));
    }
}

mod bench_frodokem976shake {
    use super::*;

    use pqcrypto_frodo::frodokem976shake::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| encapsulate(&pk));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| decapsulate(&ct, &sk));
    }
}

mod bench_frodokem1344aes {
    use super::*;

    use pqcrypto_frodo::frodokem1344aes::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| encapsulate(&pk));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| decapsulate(&ct, &sk));
    }
}

mod bench_frodokem1344shake {
    use super::*;

    use pqcrypto_frodo::frodokem1344shake::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| keypair());
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| encapsulate(&pk));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| decapsulate(&ct, &sk));
    }
}
