#![feature(test)]
extern crate test;

use test::Bencher;

mod bench_firesaber {
    use super::*;

    use pqcrypto_saber::firesaber::{decapsulate, encapsulate, keypair};

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

mod bench_lightsaber {
    use super::*;

    use pqcrypto_saber::lightsaber::{decapsulate, encapsulate, keypair};

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

mod bench_saber {
    use super::*;

    use pqcrypto_saber::saber::{decapsulate, encapsulate, keypair};

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
