use crate::schema::{PolicyDoc, SpellRequest};

pub struct GradeOutcome {
    pub risk_score: u32,
    pub verdict: String,
}

pub fn grade(req: &SpellRequest, policy: &PolicyDoc) -> GradeOutcome {
    let mut risk: i32 = 0;
    // Simple static scoring
    if let Some(nets) = &req.allow_net {
        if !nets.is_empty() {
            risk += 40; // opening network
        }
    }
    if let Some(fs) = &req.allow_fs {
        for p in fs {
            if p != "/tmp/**" {
                risk += 20; // broader FS allow
                break;
            }
        }
    }

    // thresholds from policy or defaults
    let _thresholds = policy
        .grading
        .as_ref()
        .map(|g| g.thresholds.clone())
        .unwrap_or_else(|| crate::schema::GradingThresholds {
            green: "<=20".to_string(),
            yellow: "21..=60".to_string(),
            red: ">=61".to_string(),
        });

    let verdict = if risk <= 20 {
        "green"
    } else if risk <= 60 {
        "yellow"
    } else {
        "red"
    };

    GradeOutcome {
        risk_score: risk.max(0) as u32,
        verdict: verdict.to_string(),
    }
}
