use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::OnceLock;
use veilid_core_bench::BenchContext;

static CTX: OnceLock<BenchContext> = OnceLock::new();

fn get_ctx() -> &'static BenchContext {
    CTX.get_or_init(BenchContext::new)
}

fn bench_protected_store_write(c: &mut Criterion) {
    let ctx = get_ctx();
    let protected_store = ctx.veilid.protected_store().unwrap();

    for size in [64, 256, 1024, 4096] {
        let value: Vec<u8> = (0..size).map(|i| i as u8).collect();

        c.bench_function(&format!("protected_write_{size}"), |b| {
            let mut i = 0u64;

            b.iter(|| {
                let key = format!("bench_key_{i}");
                i += 1;
                let v = value.clone();
                protected_store.save_user_secret(&key, &v).unwrap()
            })
        });
    }
}

fn bench_protected_store_read(c: &mut Criterion) {
    let ctx = get_ctx();
    let protected_store = ctx.veilid.protected_store().unwrap();

    for size in [64, 256, 1024, 4096] {
        let key = format!("read_key_{size}");
        let value: Vec<u8> = (0..size).map(|i| i as u8).collect();

        ctx.rt
            .block_on(async { protected_store.save_user_secret(&key, &value).unwrap() });

        c.bench_function(&format!("protected_read_{size}"), |b| {
            b.iter(|| async { protected_store.load_user_secret(&key).unwrap() })
        });
    }
}

criterion_group!(
    benches,
    bench_protected_store_write,
    bench_protected_store_read
);
criterion_main!(benches);
