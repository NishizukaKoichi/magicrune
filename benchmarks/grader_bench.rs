use criterion::{black_box, criterion_group, criterion_main, Criterion};
use magicrune::grader::grade;
use magicrune::schema::{PolicyDoc, SpellRequest};

fn bench_grade_low_risk(c: &mut Criterion) {
    let req = SpellRequest {
        allow_net: None,
        allow_fs: Some(vec!["/tmp/**".to_string()]),
        ..Default::default()
    };
    let policy = PolicyDoc::default();

    c.bench_function("grade_low_risk", |b| {
        b.iter(|| {
            let _ = black_box(grade(&req, &policy));
        });
    });
}

fn bench_grade_medium_risk(c: &mut Criterion) {
    let req = SpellRequest {
        allow_net: Some(vec!["localhost".to_string()]),
        allow_fs: None,
        ..Default::default()
    };
    let policy = PolicyDoc::default();

    c.bench_function("grade_medium_risk", |b| {
        b.iter(|| {
            let _ = black_box(grade(&req, &policy));
        });
    });
}

fn bench_grade_high_risk(c: &mut Criterion) {
    let req = SpellRequest {
        allow_net: Some(vec!["0.0.0.0".to_string()]),
        allow_fs: Some(vec!["/".to_string()]),
        ..Default::default()
    };
    let policy = PolicyDoc::default();

    c.bench_function("grade_high_risk", |b| {
        b.iter(|| {
            let _ = black_box(grade(&req, &policy));
        });
    });
}

fn bench_grade_with_custom_policy(c: &mut Criterion) {
    use magicrune::schema::{GradingCfg, GradingThresholds};
    
    let req = SpellRequest {
        allow_net: Some(vec!["example.com".to_string()]),
        allow_fs: Some(vec!["/home".to_string()]),
        ..Default::default()
    };
    
    let policy = PolicyDoc {
        version: 1,
        grading: Some(GradingCfg {
            thresholds: GradingThresholds {
                green: "<=10".to_string(),
                yellow: "11..=50".to_string(),
                red: ">=51".to_string(),
            },
        }),
    };

    c.bench_function("grade_with_custom_policy", |b| {
        b.iter(|| {
            let _ = black_box(grade(&req, &policy));
        });
    });
}

criterion_group!(
    benches,
    bench_grade_low_risk,
    bench_grade_medium_risk,
    bench_grade_high_risk,
    bench_grade_with_custom_policy
);
criterion_main!(benches);