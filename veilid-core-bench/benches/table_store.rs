use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::OnceLock;
use veilid_core_bench::BenchContext;

static CTX: OnceLock<BenchContext> = OnceLock::new();

fn get_ctx() -> &'static BenchContext {
    CTX.get_or_init(BenchContext::new)
}

fn bench_table_store_write(c: &mut Criterion) {
    let ctx = get_ctx();
    let table_store = ctx.veilid.table_store().unwrap();

    let db = ctx
        .rt
        .block_on(async { table_store.open("bench_write", 1).await.unwrap() });

    for size in [64, 256, 1024, 4096] {
        let value: Vec<u8> = (0..size).map(|i| i as u8).collect();

        c.bench_function(&format!("store_{size}"), |b| {
            let mut i = 0u64;
            let db = db.clone();
            b.to_async(&ctx.rt).iter(|| {
                let db = db.clone();
                let key = i.to_be_bytes();
                i += 1;
                let v = value.clone();
                async move { db.store(0, &key, &v).await.unwrap() }
            })
        });
    }
}

fn bench_table_store_read(c: &mut Criterion) {
    let ctx = get_ctx();
    let table_store = ctx.veilid.table_store().unwrap();

    let db = ctx
        .rt
        .block_on(async { table_store.open("bench_read", 1).await.unwrap() });

    for size in [64, 256, 1024, 4096] {
        let key = b"read_key";
        let value: Vec<u8> = (0..size).map(|i| i as u8).collect();

        ctx.rt
            .block_on(async { db.store(0, key, &value).await.unwrap() });

        c.bench_function(&format!("load_{size}"), |b| {
            b.to_async(&ctx.rt)
                .iter(|| async { db.load(0, key).await.unwrap() })
        });
    }
}

fn bench_table_store_delete(c: &mut Criterion) {
    let ctx = get_ctx();
    let table_store = ctx.veilid.table_store().unwrap();

    let db = ctx
        .rt
        .block_on(async { table_store.open("bench_delete", 1).await.unwrap() });

    let value = vec![0u8; 256];

    c.bench_function("delete_256", |b| {
        let mut i = 0u64;
        let db = db.clone();
        b.to_async(&ctx.rt).iter(|| {
            let key = i.to_be_bytes();
            let db = db.clone();
            i += 1;
            let v = value.clone();
            async move {
                db.store(0, &key, &v).await.unwrap();
                db.delete(0, &key).await.unwrap()
            }
        })
    });
}

fn bench_table_store_transaction(c: &mut Criterion) {
    let ctx = get_ctx();
    let table_store = ctx.veilid.table_store().unwrap();

    let db = ctx
        .rt
        .block_on(async { table_store.open("bench_tx", 1).await.unwrap() });

    for batch_size in [10, 50, 100] {
        c.bench_function(&format!("transaction_{batch_size}_ops"), |b| {
            b.to_async(&ctx.rt).iter(|| async {
                let tx = db.transact();
                for i in 0..batch_size {
                    let key = format!("tx_{i}").into_bytes();
                    tx.store(0, &key, &[0u8; 64]).await.unwrap();
                }
                tx.commit().await.unwrap()
            })
        });
    }
}

criterion_group!(
    benches,
    bench_table_store_write,
    bench_table_store_read,
    bench_table_store_delete,
    bench_table_store_transaction
);
criterion_main!(benches);
