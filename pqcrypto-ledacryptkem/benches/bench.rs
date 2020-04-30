#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

mod bench_ledakemlt12 {
    use super::*;

    use pqcrypto_ledacryptkem::ledakemlt12::{decapsulate, encapsulate, keypair};

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

mod bench_ledakemlt32 {
    use super::*;

    use pqcrypto_ledacryptkem::ledakemlt32::{decapsulate, encapsulate, keypair};

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

mod bench_ledakemlt52 {
    use super::*;

    use pqcrypto_ledacryptkem::ledakemlt52::{decapsulate, encapsulate, keypair};

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
