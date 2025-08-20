use criterion::{black_box, criterion_group, criterion_main, Criterion};
use magicrune::jet::compute_msg_id;

fn bench_compute_msg_id_small(c: &mut Criterion) {
    let payload = b"small payload";
    
    c.bench_function("compute_msg_id_small", |b| {
        b.iter(|| {
            let _ = black_box(compute_msg_id(black_box(payload)));
        });
    });
}

fn bench_compute_msg_id_medium(c: &mut Criterion) {
    let payload = b"This is a medium-sized payload with more content to hash. It contains multiple sentences and is representative of typical message sizes.";
    
    c.bench_function("compute_msg_id_medium", |b| {
        b.iter(|| {
            let _ = black_box(compute_msg_id(black_box(payload)));
        });
    });
}

fn bench_compute_msg_id_large(c: &mut Criterion) {
    let payload = vec![b'a'; 10_000]; // 10KB payload
    
    c.bench_function("compute_msg_id_large", |b| {
        b.iter(|| {
            let _ = black_box(compute_msg_id(black_box(&payload)));
        });
    });
}

fn bench_compute_msg_id_empty(c: &mut Criterion) {
    let payload = b"";
    
    c.bench_function("compute_msg_id_empty", |b| {
        b.iter(|| {
            let _ = black_box(compute_msg_id(black_box(payload)));
        });
    });
}

criterion_group!(
    benches,
    bench_compute_msg_id_small,
    bench_compute_msg_id_medium,
    bench_compute_msg_id_large,
    bench_compute_msg_id_empty
);
criterion_main!(benches);