use std::time::Duration;

use ark_std::test_rng;
use ark_std::UniformRand;
use bls_elgamal::{Fr, G1Affine, SecretKey};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_encrypt(c: &mut Criterion) {
    let mut rng = test_rng();
    let x = Fr::rand(&mut rng);
    let g1 = G1Affine::rand(&mut rng);

    let sk = SecretKey::new(g1, x);
    let pk = sk.public_key();

    let m = G1Affine::rand(&mut rng);
    let r = Fr::rand(&mut rng);

    c.bench_function("bench_encrypt", |bench| {
        bench.iter(|| {
            std::hint::black_box(pk.encrypt(m, r));
        })
    });
}

fn bench_decrypt(c: &mut Criterion) {
    let mut rng = test_rng();
    let x = Fr::rand(&mut rng);
    let g1 = G1Affine::rand(&mut rng);

    let sk = SecretKey::new(g1, x);
    let pk = sk.public_key();

    let m = G1Affine::rand(&mut rng);
    let r = Fr::rand(&mut rng);
    let ct = pk.encrypt(m, r);

    c.bench_function("bench_decrypt", |bench| {
        bench.iter(|| {
            std::hint::black_box({
                let _ = sk.decrypt(ct);
            });
        })
    });
}

criterion_group! {
    name = encrypt_decrypt;
    config = Criterion::default().sample_size(20).measurement_time(Duration::from_secs(5));
    targets = bench_encrypt, bench_decrypt,
}

criterion_main!(encrypt_decrypt,);
