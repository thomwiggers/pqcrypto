#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

mod bench_newhope1024cpa {
    use super::*;

    use pqcrypto_newhope::newhope1024cpa::{decapsulate, encapsulate, keypair};

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

mod bench_newhope1024cca {
    use super::*;

    use pqcrypto_newhope::newhope1024cca::{decapsulate, encapsulate, keypair};

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

mod bench_newhope512cpa {
    use super::*;

    use pqcrypto_newhope::newhope512cpa::{decapsulate, encapsulate, keypair};

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

mod bench_newhope512cca {
    use super::*;

    use pqcrypto_newhope::newhope512cca::{decapsulate, encapsulate, keypair};

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
