#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

mod bench_babybear {
    use super::*;

    use pqcrypto_threebears::babybear::{decapsulate, encapsulate, keypair};

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

mod bench_mamabear {
    use super::*;

    use pqcrypto_threebears::mamabear::{decapsulate, encapsulate, keypair};

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

mod bench_papabear {
    use super::*;

    use pqcrypto_threebears::papabear::{decapsulate, encapsulate, keypair};

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

mod bench_papabearephem {
    use super::*;

    use pqcrypto_threebears::papabearephem::{decapsulate, encapsulate, keypair};

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

mod bench_mamabearephem {
    use super::*;

    use pqcrypto_threebears::mamabearephem::{decapsulate, encapsulate, keypair};

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

mod bench_babybearephem {
    use super::*;

    use pqcrypto_threebears::babybearephem::{decapsulate, encapsulate, keypair};

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
