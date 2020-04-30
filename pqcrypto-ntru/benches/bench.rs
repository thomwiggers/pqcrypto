#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

mod bench_ntruhps2048509 {
    use super::*;

    use pqcrypto_ntru::ntruhps2048509::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| black_box(keypair()));
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| black_box(encapsulate(&pk)));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| black_box(decapsulate(&ct, &sk)));
    }
}

mod bench_ntruhps2048677 {
    use super::*;

    use pqcrypto_ntru::ntruhps2048677::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| black_box(keypair()));
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| black_box(encapsulate(&pk)));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| black_box(decapsulate(&ct, &sk)));
    }
}

mod bench_ntruhps4096821 {
    use super::*;

    use pqcrypto_ntru::ntruhps4096821::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| black_box(keypair()));
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| black_box(encapsulate(&pk)));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| black_box(decapsulate(&ct, &sk)));
    }
}

mod bench_ntruhrss701 {
    use super::*;

    use pqcrypto_ntru::ntruhrss701::{decapsulate, encapsulate, keypair};

    #[bench]
    fn bench_keypair(b: &mut Bencher) {
        b.iter(|| black_box(keypair()));
    }

    #[bench]
    fn bench_encaps(b: &mut Bencher) {
        let (pk, _sk) = keypair();
        b.iter(|| black_box(encapsulate(&pk)));
    }

    #[bench]
    fn bench_decaps(b: &mut Bencher) {
        let (pk, sk) = keypair();
        let (_ss, ct) = encapsulate(&pk);
        b.iter(|| black_box(decapsulate(&ct, &sk)));
    }
}
