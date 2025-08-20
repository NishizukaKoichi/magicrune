use criterion::{black_box, criterion_group, criterion_main, Criterion};
use magicrune::sandbox::{detect_sandbox, exec_native, exec_wasm, SandboxSpec};
use tokio::runtime::Runtime;

fn bench_detect_sandbox(c: &mut Criterion) {
    c.bench_function("detect_sandbox", |b| {
        b.iter(|| {
            let _ = black_box(detect_sandbox());
        });
    });
}

fn bench_exec_native(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let spec = SandboxSpec {
        wall_sec: 1,
        cpu_ms: 100,
        memory_mb: 16,
        pids: 10,
    };

    c.bench_function("exec_native_echo", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(exec_native("echo hello", b"", &spec).await);
        });
    });

    c.bench_function("exec_native_with_stdin", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(exec_native("cat", b"test input", &spec).await);
        });
    });
}

fn bench_exec_wasm_placeholder(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let spec = SandboxSpec {
        wall_sec: 1,
        cpu_ms: 100,
        memory_mb: 16,
        pids: 10,
    };

    c.bench_function("exec_wasm_placeholder", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = black_box(exec_wasm(b"dummy", &spec).await);
        });
    });
}

criterion_group!(
    benches,
    bench_detect_sandbox,
    bench_exec_native,
    bench_exec_wasm_placeholder
);
criterion_main!(benches);