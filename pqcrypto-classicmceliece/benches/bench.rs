#![feature(test)]
extern crate test;

use test::{black_box, Bencher};

mod bench_mceliece348864 {
    use super::*;

    use pqcrypto_classicmceliece::mceliece348864::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece348864f {
    use super::*;

    use pqcrypto_classicmceliece::mceliece348864f::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece460896 {
    use super::*;

    use pqcrypto_classicmceliece::mceliece460896::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece460896f {
    use super::*;

    use pqcrypto_classicmceliece::mceliece460896f::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece6688128 {
    use super::*;

    use pqcrypto_classicmceliece::mceliece6688128::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece6688128f {
    use super::*;

    use pqcrypto_classicmceliece::mceliece6688128f::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece6960119 {
    use super::*;

    use pqcrypto_classicmceliece::mceliece6960119::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece6960119f {
    use super::*;

    use pqcrypto_classicmceliece::mceliece6960119f::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece8192128 {
    use super::*;

    use pqcrypto_classicmceliece::mceliece8192128::{decapsulate, encapsulate, keypair};

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

mod bench_mceliece8192128f {
    use super::*;

    use pqcrypto_classicmceliece::mceliece8192128f::{decapsulate, encapsulate, keypair};

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
