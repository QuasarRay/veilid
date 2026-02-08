use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::OnceLock;
use veilid_core::{Sequencing, Stability, VALID_CRYPTO_KINDS};
use veilid_core_bench::BenchContext;

static CTX: OnceLock<BenchContext> = OnceLock::new();

fn get_ctx() -> &'static BenchContext {
    CTX.get_or_init(BenchContext::new)
}

fn bench_new_private_route(c: &mut Criterion) {
    let ctx = get_ctx();

    c.bench_function("new_private_route", |b| {
        b.to_async(&ctx.rt)
            .iter(|| async { ctx.veilid.new_private_route().await.unwrap() })
    });
}

fn bench_new_custom_private_route(c: &mut Criterion) {
    let ctx = get_ctx();

    c.bench_function("new_custom_private_route", |b| {
        b.to_async(&ctx.rt).iter(|| async {
            ctx.veilid
                .new_custom_private_route(
                    &VALID_CRYPTO_KINDS,
                    Stability::Reliable,
                    Sequencing::PreferOrdered,
                )
                .await
                .unwrap()
        })
    });
}

fn bench_import_remote_private_route(c: &mut Criterion) {
    let ctx = get_ctx();

    let route_blob = ctx
        .rt
        .block_on(async { ctx.veilid.new_private_route().await.unwrap() });

    c.bench_function("import_remote_private_route", |b| {
        b.iter(|| {
            ctx.veilid
                .import_remote_private_route(route_blob.blob.clone())
                .unwrap()
        })
    });
}

criterion_group!(
    benches,
    bench_new_private_route,
    bench_new_custom_private_route,
    bench_import_remote_private_route
);
criterion_main!(benches);
