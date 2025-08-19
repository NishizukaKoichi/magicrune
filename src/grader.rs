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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{GradingCfg, GradingThresholds};

    #[test]
    fn test_grade_low_risk() {
        let req = SpellRequest {
            allow_net: None,
            allow_fs: Some(vec!["/tmp/**".to_string()]),
            ..Default::default()
        };
        let policy = PolicyDoc::default();
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 0);
        assert_eq!(outcome.verdict, "green");
    }

    #[test]
    fn test_grade_medium_risk_network() {
        let req = SpellRequest {
            allow_net: Some(vec!["localhost".to_string()]),
            allow_fs: None,
            ..Default::default()
        };
        let policy = PolicyDoc::default();
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 40);
        assert_eq!(outcome.verdict, "yellow");
    }

    #[test]
    fn test_grade_medium_risk_filesystem() {
        let req = SpellRequest {
            allow_net: None,
            allow_fs: Some(vec!["/home/user".to_string()]),
            ..Default::default()
        };
        let policy = PolicyDoc::default();
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 20);
        assert_eq!(outcome.verdict, "green");
    }

    #[test]
    fn test_grade_high_risk() {
        let req = SpellRequest {
            allow_net: Some(vec!["example.com".to_string(), "google.com".to_string()]),
            allow_fs: Some(vec!["/home".to_string(), "/etc".to_string()]),
            ..Default::default()
        };
        let policy = PolicyDoc::default();
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 60);
        assert_eq!(outcome.verdict, "yellow");
    }

    #[test]
    fn test_grade_very_high_risk() {
        let req = SpellRequest {
            allow_net: Some(vec!["0.0.0.0".to_string()]),
            allow_fs: Some(vec!["/".to_string()]),
            ..Default::default()
        };
        let policy = PolicyDoc::default();
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 60);
        assert_eq!(outcome.verdict, "yellow");
    }

    #[test]
    fn test_grade_with_custom_policy() {
        let req = SpellRequest {
            allow_net: Some(vec!["localhost".to_string()]),
            allow_fs: None,
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
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 40);
        assert_eq!(outcome.verdict, "yellow");
    }

    #[test]
    fn test_grade_empty_network_list() {
        let req = SpellRequest {
            allow_net: Some(vec![]),
            allow_fs: None,
            ..Default::default()
        };
        let policy = PolicyDoc::default();
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 0);
        assert_eq!(outcome.verdict, "green");
    }

    #[test]
    fn test_grade_tmp_only_filesystem() {
        let req = SpellRequest {
            allow_net: None,
            allow_fs: Some(vec!["/tmp/**".to_string(), "/tmp/**".to_string()]),
            ..Default::default()
        };
        let policy = PolicyDoc::default();
        
        let outcome = grade(&req, &policy);
        assert_eq!(outcome.risk_score, 0);
        assert_eq!(outcome.verdict, "green");
    }
}
