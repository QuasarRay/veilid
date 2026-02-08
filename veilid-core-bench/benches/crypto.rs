use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::OnceLock;
use veilid_core::CRYPTO_KIND_VLD0;
use veilid_core_bench::BenchContext;

static CTX: OnceLock<BenchContext> = OnceLock::new();

fn get_ctx() -> &'static BenchContext {
    CTX.get_or_init(BenchContext::new)
}

fn bench_crypto_core(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();

    let keypair = vcrypto.generate_keypair();
    let data = b"Hello Veilid Benchmark";

    c.bench_function("sign", |b| {
        b.iter(|| {
            vcrypto
                .sign(&keypair.key(), &keypair.secret(), data)
                .unwrap()
        })
    });

    c.bench_function("generate_keypair", |b| {
        b.iter(|| vcrypto.generate_keypair())
    });

    c.bench_function("hash", |b| b.iter(|| vcrypto.generate_hash(data)));
}

fn bench_crypto_verify(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();

    let keypair = vcrypto.generate_keypair();
    let data = b"Hello Veilid Benchmark";
    let signature = vcrypto
        .sign(&keypair.key(), &keypair.secret(), data)
        .unwrap();

    c.bench_function("verify", |b| {
        b.iter(|| vcrypto.verify(&keypair.key(), data, &signature))
    });
}

fn bench_crypto_dh(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();

    let kp1 = vcrypto.generate_keypair();
    let kp2 = vcrypto.generate_keypair();

    c.bench_function("compute_dh", |b| {
        b.iter(|| vcrypto.compute_dh(&kp1.key(), &kp2.secret()).unwrap())
    });

    c.bench_function("cached_dh", |b| {
        b.iter(|| vcrypto.cached_dh(&kp1.key(), &kp2.secret()).unwrap())
    });
}

fn bench_crypto_aead(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();
    let nonce = vcrypto.random_nonce();
    let secret = vcrypto.random_shared_secret();
    for size in [64, 256, 1024, 4096, 16384] {
        let data: Vec<u8> = (0..size).map(|i| i as u8).collect();

        c.bench_function(&format!("encrypt_aead_{size}"), |b| {
            b.iter(|| vcrypto.encrypt_aead(&data, &nonce, &secret, None).unwrap())
        });

        let encrypted = vcrypto.encrypt_aead(&data, &nonce, &secret, None).unwrap();

        c.bench_function(&format!("decrypt_aead_{size}"), |b| {
            b.iter(|| {
                vcrypto
                    .decrypt_aead(&encrypted, &nonce, &secret, None)
                    .unwrap()
            })
        });
    }
}

fn bench_crypto_random(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();

    c.bench_function("random_nonce", |b| b.iter(|| vcrypto.random_nonce()));

    c.bench_function("random_shared_secret", |b| {
        b.iter(|| vcrypto.random_shared_secret())
    });

    for size in [32, 256, 1024, 4096] {
        c.bench_function(&format!("random_bytes_{size}"), |b| {
            b.iter(|| vcrypto.random_bytes(size))
        });
    }
}

fn bench_crypto_aead_in_place(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();

    let nonce = vcrypto.random_nonce();
    let secret = vcrypto.random_shared_secret();

    for size in [64, 256, 1024, 4096] {
        c.bench_function(&format!("encrypt_in_place_aead_{size}"), |b| {
            b.iter_batched(
                || (0..size).map(|i| i as u8).collect::<Vec<u8>>(),
                |mut data| {
                    vcrypto
                        .encrypt_in_place_aead(&mut data, &nonce, &secret, None)
                        .unwrap()
                },
                criterion::BatchSize::SmallInput,
            )
        });
        c.bench_function(&format!("decrypt_in_place_aead_{size}"), |b| {
            let plain: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let encrypted_template = vcrypto.encrypt_aead(&plain, &nonce, &secret, None).unwrap();
            b.iter_batched(
                || encrypted_template.clone(),
                |mut encrypted| {
                    vcrypto
                        .decrypt_in_place_aead(&mut encrypted, &nonce, &secret, None)
                        .unwrap()
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
}

fn bench_crypto_no_auth(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();
    let nonce = vcrypto.random_nonce();
    let secret = vcrypto.random_shared_secret();
    for size in [64, 256, 1024, 4096] {
        c.bench_function(&format!("crypt_no_auth_aligned_{size}"), |b| {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            b.iter(|| {
                vcrypto
                    .crypt_no_auth_aligned_8(&data, &nonce, &secret)
                    .unwrap()
            })
        });

        c.bench_function(&format!("crypt_no_auth_unaligned_{size}"), |b| {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            b.iter(|| {
                vcrypto
                    .crypt_no_auth_unaligned(&data, &nonce, &secret)
                    .unwrap()
            })
        });
    }
}

fn bench_crypto_validate(c: &mut Criterion) {
    let ctx = get_ctx();
    let crypto = ctx.veilid.crypto().unwrap();
    let vcrypto = crypto.get(CRYPTO_KIND_VLD0).unwrap();
    c.bench_function("validate_keypair", |b| {
        let kp = vcrypto.generate_keypair();
        b.iter(|| vcrypto.validate_keypair(&kp.key(), &kp.secret()).unwrap())
    });

    c.bench_function("validate_hash", |b| {
        let data = b"Hello Veilid";
        let hash = vcrypto.generate_hash(data);
        b.iter(|| vcrypto.validate_hash(data, &hash).unwrap())
    });
}

criterion_group!(
    benches,
    bench_crypto_core,
    bench_crypto_verify,
    bench_crypto_dh,
    bench_crypto_aead,
    bench_crypto_aead_in_place,
    bench_crypto_random,
    bench_crypto_no_auth,
    bench_crypto_validate
);
criterion_main!(benches);
