#![feature(test)]
extern crate test;

use test::Bencher;

mod bench_hqc1281cca2 {
    use super::*;

    use pqcrypto_hqc::hqc1281cca2::{decapsulate, encapsulate, keypair};

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

mod bench_hqc1921cca2 {
    use super::*;

    use pqcrypto_hqc::hqc1921cca2::{decapsulate, encapsulate, keypair};

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

mod bench_hqc1922cca2 {
    use super::*;

    use pqcrypto_hqc::hqc1922cca2::{decapsulate, encapsulate, keypair};

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

mod bench_hqc2561cca2 {
    use super::*;

    use pqcrypto_hqc::hqc2561cca2::{decapsulate, encapsulate, keypair};

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

mod bench_hqc2562cca2 {
    use super::*;

    use pqcrypto_hqc::hqc2562cca2::{decapsulate, encapsulate, keypair};

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

mod bench_hqc2563cca2 {
    use super::*;

    use pqcrypto_hqc::hqc2563cca2::{decapsulate, encapsulate, keypair};

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
