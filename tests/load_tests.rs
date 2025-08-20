//! Large-scale load tests for MagicRune
//! These tests simulate high concurrency and throughput scenarios

use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn load_test_concurrent_requests_small() {
    // Small version for CI
    let num_threads = 2;
    let requests_per_thread = 5;
    run_concurrent_load_test(num_threads, requests_per_thread);
}

#[test]
#[ignore = "Load test - run with cargo test --test load_tests -- --ignored --nocapture"]
fn load_test_concurrent_requests() {
    // Test handling of many concurrent requests
    let num_threads = 10;
    let requests_per_thread = 50;
    run_concurrent_load_test(num_threads, requests_per_thread);
}

fn run_concurrent_load_test(num_threads: usize, requests_per_thread: usize) {
    let total_requests = num_threads * requests_per_thread;

    println!(
        "Starting load test: {} threads, {} requests each",
        num_threads, requests_per_thread
    );

    let success_count = Arc::new(AtomicU64::new(0));
    let failure_count = Arc::new(AtomicU64::new(0));
    let total_duration_ms = Arc::new(AtomicU64::new(0));

    let start = Instant::now();

    let handles: Vec<_> = (0..num_threads)
        .map(|thread_id| {
            let success = success_count.clone();
            let failure = failure_count.clone();
            let duration = total_duration_ms.clone();

            thread::spawn(move || {
                for req_id in 0..requests_per_thread {
                    let request = serde_json::json!({
                        "cmd": format!("echo test_{}_{}", thread_id, req_id),
                        "stdin": "",
                        "env": {},
                        "files": [],
                        "policy_id": "default",
                        "timeout_sec": 5,
                        "allow_net": [],
                        "allow_fs": []
                    });

                    let req_path = format!("target/tmp/load_t{}_r{}.json", thread_id, req_id);
                    fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

                    let req_start = Instant::now();
                    let status = Command::new("cargo")
                        .args(["run", "--release", "--", "exec", "-f", &req_path])
                        .env("MAGICRUNE_FORCE_WASM", "1")
                        .output()
                        .expect("Failed to execute");

                    let req_duration = req_start.elapsed().as_millis() as u64;
                    duration.fetch_add(req_duration, Ordering::Relaxed);

                    if status.status.success() {
                        success.fetch_add(1, Ordering::Relaxed);
                    } else {
                        failure.fetch_add(1, Ordering::Relaxed);
                    }

                    // Clean up
                    let _ = fs::remove_file(&req_path);
                }
            })
        })
        .collect();

    // Wait for all threads
    for handle in handles {
        handle.join().expect("Thread panicked");
    }

    let total_time = start.elapsed();
    let success_total = success_count.load(Ordering::Relaxed);
    let failure_total = failure_count.load(Ordering::Relaxed);
    let avg_duration = total_duration_ms.load(Ordering::Relaxed) / (total_requests as u64);
    let throughput = (total_requests as f64) / total_time.as_secs_f64();

    println!("\n=== Load Test Results ===");
    println!("Total requests: {}", total_requests);
    println!(
        "Successful: {} ({:.1}%)",
        success_total,
        (success_total as f64 / total_requests as f64) * 100.0
    );
    println!(
        "Failed: {} ({:.1}%)",
        failure_total,
        (failure_total as f64 / total_requests as f64) * 100.0
    );
    println!("Total time: {:.2}s", total_time.as_secs_f64());
    println!("Average latency: {}ms", avg_duration);
    println!("Throughput: {:.1} req/s", throughput);

    // Performance assertions based on SPEC.md requirements
    if total_requests >= 100 {
        // Only enforce for large tests
        assert!(
            success_total as f64 / total_requests as f64 >= 0.95,
            "Success rate should be >= 95%"
        );
        assert!(throughput >= 50.0, "Throughput should be >= 50 req/s");
    } else {
        // For small tests, just ensure most succeed
        assert!(
            success_total as f64 / total_requests as f64 >= 0.8,
            "Success rate should be >= 80%"
        );
    }
}

#[test]
#[ignore = "Load test - run with cargo test --test load_tests -- --ignored --nocapture"]
fn load_test_sustained_throughput() {
    // Test sustained throughput over time
    let duration_secs = 30;
    let target_rate = 100.0; // requests per second

    println!(
        "Starting sustained throughput test: {} req/s for {}s",
        target_rate, duration_secs
    );

    let stop_flag = Arc::new(AtomicBool::new(false));
    let request_count = Arc::new(AtomicU64::new(0));
    let success_count = Arc::new(AtomicU64::new(0));
    let latencies = Arc::new(Mutex::new(Vec::new()));

    let start = Instant::now();

    // Producer thread
    let producer_stop = stop_flag.clone();
    let producer_count = request_count.clone();
    let producer = thread::spawn(move || {
        let mut req_id = 0u64;
        let interval = Duration::from_secs_f64(1.0 / target_rate);

        while !producer_stop.load(Ordering::Relaxed) {
            let request = serde_json::json!({
                "cmd": format!("echo sustained_{}", req_id),
                "stdin": "",
                "env": {},
                "files": [],
                "policy_id": "default",
                "timeout_sec": 5,
                "allow_net": [],
                "allow_fs": []
            });

            let req_path = format!("target/tmp/sustained_{}.json", req_id);
            fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

            producer_count.fetch_add(1, Ordering::Relaxed);
            req_id += 1;

            thread::sleep(interval);
        }
    });

    // Consumer threads
    let num_workers = 4;
    let workers: Vec<_> = (0..num_workers)
        .map(|_| {
            let stop = stop_flag.clone();
            let requests = request_count.clone();
            let successes = success_count.clone();
            let lats = latencies.clone();

            thread::spawn(move || {
                let mut processed = 0u64;

                while !stop.load(Ordering::Relaxed) || processed < requests.load(Ordering::Relaxed)
                {
                    let current = requests.load(Ordering::Relaxed);
                    if processed >= current {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }

                    let req_path = format!("target/tmp/sustained_{}.json", processed);
                    if fs::metadata(&req_path).is_err() {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }

                    let req_start = Instant::now();
                    let status = Command::new("cargo")
                        .args(["run", "--release", "--", "exec", "-f", &req_path])
                        .env("MAGICRUNE_FORCE_WASM", "1")
                        .output()
                        .expect("Failed to execute");

                    let latency = req_start.elapsed().as_millis() as u64;

                    if status.status.success() {
                        successes.fetch_add(1, Ordering::Relaxed);
                        lats.lock().unwrap().push(latency);
                    }

                    // Clean up
                    let _ = fs::remove_file(&req_path);
                    processed += 1;
                }
            })
        })
        .collect();

    // Run for specified duration
    thread::sleep(Duration::from_secs(duration_secs));
    stop_flag.store(true, Ordering::Relaxed);

    // Wait for all threads
    producer.join().expect("Producer thread panicked");
    for worker in workers {
        worker.join().expect("Worker thread panicked");
    }

    let total_time = start.elapsed();
    let total_requests = request_count.load(Ordering::Relaxed);
    let total_success = success_count.load(Ordering::Relaxed);
    let all_latencies = latencies.lock().unwrap();

    // Calculate percentiles
    let mut sorted_latencies = all_latencies.clone();
    sorted_latencies.sort();

    let p50 = sorted_latencies
        .get(sorted_latencies.len() / 2)
        .copied()
        .unwrap_or(0);
    let p95 = sorted_latencies
        .get(sorted_latencies.len() * 95 / 100)
        .copied()
        .unwrap_or(0);
    let p99 = sorted_latencies
        .get(sorted_latencies.len() * 99 / 100)
        .copied()
        .unwrap_or(0);

    let actual_rate = total_requests as f64 / total_time.as_secs_f64();

    println!("\n=== Sustained Throughput Results ===");
    println!("Target rate: {:.1} req/s", target_rate);
    println!("Actual rate: {:.1} req/s", actual_rate);
    println!("Total requests: {}", total_requests);
    println!(
        "Successful: {} ({:.1}%)",
        total_success,
        (total_success as f64 / total_requests as f64) * 100.0
    );
    println!("Latency P50: {}ms", p50);
    println!("Latency P95: {}ms", p95);
    println!("Latency P99: {}ms", p99);

    // Performance assertions based on SPEC.md
    assert!(p50 <= 50, "P50 latency should be <= 50ms");
    assert!(p95 <= 200, "P95 latency should be <= 200ms");
    assert!(p99 <= 500, "P99 latency should be <= 500ms");
    assert!(
        actual_rate >= target_rate * 0.9,
        "Should maintain at least 90% of target rate"
    );
}

#[test]
#[ignore = "Load test - run with cargo test --test load_tests -- --ignored --nocapture"]
fn load_test_stress_memory() {
    // Test behavior under memory pressure
    println!("Starting memory stress test");

    let num_requests = 20;
    let mut results = Vec::new();

    for i in 0..num_requests {
        // Generate request with increasing memory requirements
        let file_size_kb = 100 * (i + 1); // 100KB, 200KB, ..., 2MB
        let content = "x".repeat(file_size_kb * 1024);
        let content_b64 = base64_helper::encode(&content);

        let request = serde_json::json!({
            "cmd": "cat /tmp/bigfile.txt | wc -c",
            "stdin": "",
            "env": {},
            "files": [{
                "path": "/tmp/bigfile.txt",
                "content_b64": content_b64
            }],
            "policy_id": "default",
            "timeout_sec": 10,
            "allow_net": [],
            "allow_fs": ["/tmp/**"]
        });

        let req_path = format!("target/tmp/memory_stress_{}.json", i);
        fs::write(&req_path, serde_json::to_string(&request).unwrap()).unwrap();

        let start = Instant::now();
        let status = Command::new("cargo")
            .args(["run", "--release", "--", "exec", "-f", &req_path])
            .env("MAGICRUNE_FORCE_WASM", "1")
            .output()
            .expect("Failed to execute");

        let duration = start.elapsed();
        let success = status.status.success();

        results.push((file_size_kb, success, duration));

        // Clean up
        let _ = fs::remove_file(&req_path);

        println!(
            "Request {} ({}KB): {} in {:?}",
            i,
            file_size_kb,
            if success { "SUCCESS" } else { "FAILED" },
            duration
        );
    }

    // Analyze results
    let successful = results.iter().filter(|(_, success, _)| *success).count();
    println!("\n=== Memory Stress Results ===");
    println!("Total requests: {}", num_requests);
    println!(
        "Successful: {} ({:.1}%)",
        successful,
        (successful as f64 / num_requests as f64) * 100.0
    );

    // Should handle reasonable file sizes
    assert!(
        successful >= num_requests / 2,
        "Should handle at least 50% of requests under memory pressure"
    );
}

// Add base64 encoding helper
mod base64_helper {
    use base64::Engine;

    pub fn encode(input: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(input)
    }
}
