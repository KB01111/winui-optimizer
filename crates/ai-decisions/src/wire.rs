//! Wire types for the OpenRouter Decisions API
//! (`POST https://openrouter.ai/api/alpha/decisions`).
//!
//! The request carries a `state` payload plus five required questions whose
//! answer types are `choice` (classification) and `noul` (the four boolean
//! flags). Responses may also contain `score` answers; those are parsed and
//! recorded in the evidence trail even though this crate does not ask for them.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use security_core::{DecisionCategory, DecisionResult};

use crate::error::{sanitize_message, DecisionError};
use crate::redaction::CALIBRATION_NOTE;
use crate::types::now_ms;

/// Verified Decisions API endpoint.
pub(crate) const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/alpha/decisions";

/// `noul` answers at or above this value are treated as `true`.
pub(crate) const NOUL_TRUE_THRESHOLD: f64 = 0.5;

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DecisionRequest {
    pub model: String,
    pub state: serde_json::Value,
    pub questions: Questions,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Questions {
    pub classification: QuestionSpec,
    pub requires_investigation: QuestionSpec,
    pub persistence: QuestionSpec,
    pub credential_theft: QuestionSpec,
    pub ransomware: QuestionSpec,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct QuestionSpec {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub instructions: &'static str,
    pub criteria: serde_json::Value,
}

/// The five required questions, exactly matching the contract.
pub(crate) fn build_questions() -> Questions {
    use serde_json::json;
    Questions {
        classification: QuestionSpec {
            kind: "choice",
            instructions: "Classify the security event from the structured state. Choose exactly one criterion. Use 'unknown' when the state is insufficient or contradictory.",
            criteria: json!({
                "benign": "No meaningful security concern; behavior, provenance and detections are consistent with normal software.",
                "suspicious": "Some indicators of malicious or unwanted behavior, but not enough to conclude malware.",
                "likely_malicious": "Multiple strong indicators consistent with malware or an active attack.",
                "unknown": "The state is insufficient, contradictory or outside the model's knowledge."
            }),
        },
        requires_investigation: QuestionSpec {
            kind: "noul",
            instructions: "Answer true when a human analyst should review this event before any automated outcome is applied, even if you are not certain it is malicious. Answer false when no review is needed.",
            criteria: json!("true = human review recommended; false = no review needed"),
        },
        persistence: QuestionSpec {
            kind: "noul",
            instructions: "Answer true when the observed behavior establishes a persistence mechanism (run keys, startup folder, services, scheduled tasks, WMI subscriptions).",
            criteria: json!("true = persistence mechanism observed"),
        },
        credential_theft: QuestionSpec {
            kind: "noul",
            instructions: "Answer true when the observed behavior indicates credential theft (LSASS access, browser credential stores, keylogging, token theft).",
            criteria: json!("true = credential theft indicated"),
        },
        ransomware: QuestionSpec {
            kind: "noul",
            instructions: "Answer true when the observed behavior indicates ransomware (mass file encryption, shadow copy deletion, ransom notes).",
            criteria: json!("true = ransomware indicated"),
        },
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DecisionResponse {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model_version: Option<String>,
    pub answers: BTreeMap<String, Answer>,
    #[serde(default)]
    pub usage: Option<Usage>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum Answer {
    Noul {
        #[serde(default)]
        noul: serde_json::Value,
        #[serde(default)]
        confidence: Option<f64>,
    },
    Choice {
        #[serde(default)]
        choice: Option<String>,
        #[serde(default)]
        confidence: Option<f64>,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
    },
    Score {
        #[serde(default)]
        score: Option<f64>,
        #[serde(default)]
        confidence: Option<f64>,
        #[serde(default)]
        probabilities: BTreeMap<String, f64>,
        #[serde(default)]
        legend: BTreeMap<String, String>,
    },
    /// Unknown answer types are tolerated so a newer API version cannot break
    /// parsing of the answers we do understand.
    #[serde(other)]
    Unsupported,
}

/// Parsed `noul` answer.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ParsedNoul {
    pub value: Option<bool>,
    pub raw: Option<f64>,
}

/// Interpret a `noul` JSON value: bool, 0..1 probability or numeric string.
pub(crate) fn parse_noul_value(value: &serde_json::Value) -> ParsedNoul {
    match value {
        serde_json::Value::Bool(flag) => ParsedNoul {
            value: Some(*flag),
            raw: None,
        },
        serde_json::Value::Number(number) => {
            let raw = number.as_f64();
            let value = raw.map(|raw| raw >= NOUL_TRUE_THRESHOLD);
            ParsedNoul { value, raw }
        }
        serde_json::Value::String(text) => {
            let normalized = text.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "true" | "yes" | "1" => ParsedNoul {
                    value: Some(true),
                    raw: None,
                },
                "false" | "no" | "0" => ParsedNoul {
                    value: Some(false),
                    raw: None,
                },
                _ => ParsedNoul::default(),
            }
        }
        _ => ParsedNoul::default(),
    }
}

/// Map a `choice` string onto [`DecisionCategory`]; `None` when unrecognized.
pub(crate) fn category_from_choice(choice: &str) -> Option<DecisionCategory> {
    let normalized = choice.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "benign" | "clean" | "safe" | "not_malicious" => Some(DecisionCategory::Benign),
        "suspicious" | "suspect" => Some(DecisionCategory::Suspicious),
        "likely_malicious" | "likelymalicious" | "malicious" | "malware" => {
            Some(DecisionCategory::LikelyMalicious)
        }
        "unknown" | "uncertain" | "inconclusive" => Some(DecisionCategory::Unknown),
        _ => None,
    }
}

/// Human-readable form of a category (matches the choice criteria ids).
pub(crate) fn category_str(category: DecisionCategory) -> &'static str {
    match category {
        DecisionCategory::Benign => "benign",
        DecisionCategory::Suspicious => "suspicious",
        DecisionCategory::LikelyMalicious => "likely_malicious",
        DecisionCategory::Unknown => "unknown",
    }
}

/// Build the request body exactly as specified by the contract.
pub(crate) fn build_request_body(
    model: &str,
    state: &security_core::SecurityEventState,
    allow_cloud_state: bool,
) -> serde_json::Value {
    let state_value = if allow_cloud_state {
        serde_json::to_value(state)
            .unwrap_or_else(|_| serde_json::json!({ "stateUnavailable": true }))
    } else {
        // Privacy switch: withhold the structured state but keep triage context.
        serde_json::json!({
            "stateWithheld": true,
            "reason": "cloud state sharing is disabled by user policy",
            "eventType": state.event_type,
            "deterministicScore": state.deterministic.score,
            "deterministicLevel": state.deterministic.level,
        })
    };
    let request = DecisionRequest {
        model: model.to_string(),
        state: state_value,
        questions: build_questions(),
    };
    serde_json::to_value(request).unwrap_or(serde_json::Value::Null)
}

/// Parse a Decisions API response into a [`DecisionResult`].
pub(crate) fn decision_from_response(
    body: &str,
    fallback_provider: &str,
    configured_model: &str,
    latency_ms: u64,
) -> Result<DecisionResult, DecisionError> {
    let response: DecisionResponse = serde_json::from_str(body).map_err(|error| {
        DecisionError::InvalidResponse(sanitize_message(&format!(
            "could not parse decision response: {error}"
        )))
    })?;

    let mut evidence: Vec<String> = Vec::new();
    if let Some(id) = response.id.as_deref().filter(|id| !id.trim().is_empty()) {
        evidence.push(format!("provider response id: {id}"));
    }

    let mut probabilities: BTreeMap<String, f32> = BTreeMap::new();
    let confidence: f32;
    let category =
        match response.answers.get("classification") {
            Some(Answer::Choice {
                choice,
                confidence: answer_confidence,
                probabilities: answer_probabilities,
            }) => {
                confidence = answer_confidence.unwrap_or(0.0) as f32;
                probabilities = answer_probabilities
                    .iter()
                    .map(|(name, value)| (name.clone(), *value as f32))
                    .collect();
                match choice.as_deref() {
                    Some(choice) => category_from_choice(choice).unwrap_or_else(|| {
                        evidence.push(format!(
                            "classification: unrecognized value '{choice}'; treated as unknown"
                        ));
                        DecisionCategory::Unknown
                    }),
                    None => {
                        evidence.push(
                            "classification: choice answer had no value; treated as unknown"
                                .to_string(),
                        );
                        DecisionCategory::Unknown
                    }
                }
            }
            Some(Answer::Score {
                score,
                confidence: answer_confidence,
                ..
            }) => {
                confidence = answer_confidence.unwrap_or(0.0) as f32;
                evidence.push(format!(
                "classification: model answered with a score answer (score={}); treated as unknown",
                score.map(|value| value.to_string()).unwrap_or_else(|| "none".to_string())
            ));
                DecisionCategory::Unknown
            }
            _ => {
                return Err(DecisionError::InvalidResponse(
                    "response is missing a choice answer for 'classification'".to_string(),
                ))
            }
        };

    evidence.push(format!(
        "classification: {} (confidence {:.2})",
        category_str(category),
        confidence
    ));

    let requires_investigation =
        noul_flag(&response, "requires_investigation", true, &mut evidence);
    let persistence = noul_flag(&response, "persistence", false, &mut evidence);
    let credential_theft = noul_flag(&response, "credential_theft", false, &mut evidence);
    let ransomware = noul_flag(&response, "ransomware", false, &mut evidence);
    evidence.push(format!(
        "noul answers at or above {NOUL_TRUE_THRESHOLD} are treated as true"
    ));

    for (name, answer) in &response.answers {
        if let Answer::Score {
            score,
            confidence,
            probabilities,
            legend,
        } = answer
        {
            let legend_text = if legend.is_empty() {
                String::new()
            } else {
                format!(
                    ", legend [{}]",
                    legend
                        .iter()
                        .map(|(key, label)| format!("{key}={label}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            let probabilities_text = if probabilities.is_empty() {
                String::new()
            } else {
                format!(
                    ", probabilities [{}]",
                    probabilities
                        .iter()
                        .map(|(key, value)| format!("{key}={value:.4}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            evidence.push(format!(
                "score answer '{name}': {} (confidence {}){legend_text}{probabilities_text}",
                score
                    .map(|value| format!("{value:.4}"))
                    .unwrap_or_else(|| "none".into()),
                confidence
                    .map(|value| format!("{value:.2}"))
                    .unwrap_or_else(|| "none".into()),
            ));
        } else if matches!(answer, Answer::Unsupported) {
            evidence.push(format!(
                "answer '{name}' used an unsupported type and was ignored"
            ));
        }
    }

    evidence.push(CALIBRATION_NOTE.to_string());

    let provider = response
        .provider
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback_provider.to_string());
    let model = response
        .model
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| configured_model.to_string());

    let cost_usd = response
        .usage
        .as_ref()
        .and_then(|usage| usage.cost)
        .filter(|cost| cost.is_finite());
    if let Some(usage) = &response.usage {
        evidence.push(format!(
            "usage: {} input / {} output tokens{}",
            usage
                .input_tokens
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into()),
            usage
                .output_tokens
                .map(|value| value.to_string())
                .unwrap_or_else(|| "?".into()),
            cost_usd
                .map(|cost| format!(", cost ${cost:.6}"))
                .unwrap_or_default(),
        ));
    }

    Ok(DecisionResult {
        id: security_core::new_id("dec"),
        provider,
        model,
        model_version: response.model_version.clone(),
        category,
        probabilities,
        confidence,
        requires_investigation,
        suspicious_persistence: persistence,
        credential_theft,
        ransomware,
        latency_ms,
        timestamp_ms: now_ms(),
        evidence,
        cost_usd,
        escalated: false,
    })
}

fn noul_flag(
    response: &DecisionResponse,
    name: &str,
    default_when_missing: bool,
    evidence: &mut Vec<String>,
) -> bool {
    match response.answers.get(name) {
        Some(Answer::Noul { noul, confidence }) => {
            let parsed = parse_noul_value(noul);
            match parsed.value {
                Some(value) => {
                    let raw = parsed
                        .raw
                        .map(|raw| format!("noul={raw}"))
                        .unwrap_or_else(|| "noul answer".to_string());
                    let confidence_text = confidence
                        .filter(|value| value.is_finite())
                        .map(|value| format!(", confidence {value:.2}"))
                        .unwrap_or_default();
                    evidence.push(format!("{name}: {value} ({raw}{confidence_text})"));
                    value
                }
                None => {
                    evidence.push(format!(
                        "{name}: answer value was not interpretable; treated as {default_when_missing}"
                    ));
                    default_when_missing
                }
            }
        }
        Some(_) => {
            evidence.push(format!(
                "{name}: unexpected answer type; treated as {default_when_missing}"
            ));
            default_when_missing
        }
        None => {
            evidence.push(format!(
                "{name}: answer missing; treated as {default_when_missing}"
            ));
            default_when_missing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        sample_state, RESPONSE_CHOICE_SUSPICIOUS, RESPONSE_MIXED_SCORE_AND_CHOICE,
        RESPONSE_NOUL_BOOLEAN,
    };

    #[test]
    fn request_contains_five_contract_questions() {
        let state = sample_state(80.0);
        let body = build_request_body("typesafe/jev-1.14", &state, true);
        assert_eq!(body["model"], "typesafe/jev-1.14");
        let questions = body["questions"].as_object().expect("questions object");
        assert_eq!(questions.len(), 5);
        for name in [
            "classification",
            "requires_investigation",
            "persistence",
            "credential_theft",
            "ransomware",
        ] {
            assert!(questions.contains_key(name), "missing question {name}");
        }
        assert_eq!(body["questions"]["classification"]["type"], "choice");
        assert_eq!(body["questions"]["requires_investigation"]["type"], "noul");
        assert!(body["questions"]["classification"]["criteria"]["likely_malicious"].is_string());
        assert!(body["questions"]["classification"]["instructions"].is_string());
        assert!(body["state"]["deterministic"]["score"].is_number());
    }

    #[test]
    fn request_withholds_state_when_disallowed() {
        let state = sample_state(80.0);
        let body = build_request_body("inception/mercury-decide", &state, false);
        assert_eq!(body["state"]["stateWithheld"], true);
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("commandLineRedacted"), "{serialized}");
        assert!(!serialized.contains("someuser"), "{serialized}");
        assert!(serialized.contains("deterministicScore"), "{serialized}");
    }

    #[test]
    fn parses_choice_answer() {
        let result = decision_from_response(
            RESPONSE_CHOICE_SUSPICIOUS,
            "openrouter",
            "inception/mercury-decide",
            123,
        )
        .unwrap();
        assert_eq!(result.category, DecisionCategory::Suspicious);
        assert!((result.confidence - 0.75).abs() < 1e-6);
        assert_eq!(result.probabilities.len(), 4);
        assert!(result.requires_investigation);
        assert!(!result.suspicious_persistence);
        assert!(!result.credential_theft);
        assert!(!result.ransomware);
        assert_eq!(result.provider, "Together");
        assert_eq!(result.model, "inception/mercury-decide");
        assert_eq!(result.latency_ms, 123);
        assert_eq!(result.cost_usd, Some(0.00042));
        assert!(!result.escalated);
        assert!(result
            .evidence
            .iter()
            .any(|line| line.contains("uncalibrated model probabilities")));
        assert!(result
            .evidence
            .iter()
            .any(|line| line.contains("provider response id: gen-test-1")));

        // The configured model is used when the response omits it.
        let fallback = decision_from_response(
            RESPONSE_MIXED_SCORE_AND_CHOICE,
            "openrouter",
            "fallback-model",
            0,
        )
        .unwrap();
        assert_eq!(fallback.model, "fallback-model");
    }

    #[test]
    fn parses_noul_boolean_and_numeric_answers() {
        let result = decision_from_response(
            RESPONSE_NOUL_BOOLEAN,
            "openrouter",
            "inception/mercury-decide",
            0,
        )
        .unwrap();
        assert!(result.suspicious_persistence);
        assert!(!result.credential_theft);
        assert!(result.requires_investigation);
    }

    #[test]
    fn parses_score_answers_with_legend() {
        let result = decision_from_response(
            RESPONSE_MIXED_SCORE_AND_CHOICE,
            "openrouter",
            "inception/mercury-decide",
            0,
        )
        .unwrap();
        assert_eq!(result.category, DecisionCategory::Benign);
        assert!(result
            .evidence
            .iter()
            .any(|line| line.contains("score answer 'risk_score'") && line.contains("legend")));
    }

    #[test]
    fn noul_value_interpretation() {
        assert_eq!(parse_noul_value(&serde_json::json!(0.96)).value, Some(true));
        assert_eq!(parse_noul_value(&serde_json::json!(0.1)).value, Some(false));
        assert_eq!(parse_noul_value(&serde_json::json!(true)).value, Some(true));
        assert_eq!(
            parse_noul_value(&serde_json::json!("yes")).value,
            Some(true)
        );
        assert_eq!(parse_noul_value(&serde_json::json!("nope")).value, None);
        assert_eq!(parse_noul_value(&serde_json::json!(null)).value, None);
    }

    #[test]
    fn choice_mapping_handles_aliases() {
        assert_eq!(
            category_from_choice("malicious"),
            Some(DecisionCategory::LikelyMalicious)
        );
        assert_eq!(
            category_from_choice("Likely-Malicious"),
            Some(DecisionCategory::LikelyMalicious)
        );
        assert_eq!(
            category_from_choice("clean"),
            Some(DecisionCategory::Benign)
        );
        assert_eq!(category_from_choice("weird"), None);
    }

    #[test]
    fn missing_classification_is_invalid() {
        let error = decision_from_response(
            r#"{"answers":{"requires_investigation":{"type":"noul","noul":0.1}}}"#,
            "openrouter",
            "m",
            0,
        )
        .unwrap_err();
        assert!(matches!(error, DecisionError::InvalidResponse(_)));
    }

    #[test]
    fn malformed_json_is_invalid() {
        let error = decision_from_response("{not json", "openrouter", "m", 0).unwrap_err();
        assert!(matches!(error, DecisionError::InvalidResponse(_)));
    }

    #[test]
    fn unrecognized_choice_becomes_unknown() {
        let body = r#"{"answers":{"classification":{"type":"choice","choice":"totally_new","confidence":0.4}}}"#;
        let result = decision_from_response(body, "openrouter", "m", 0).unwrap();
        assert_eq!(result.category, DecisionCategory::Unknown);
        assert!((result.confidence - 0.4).abs() < 1e-6);
    }

    #[test]
    fn score_typed_classification_is_tolerated() {
        let body = r#"{"answers":{"classification":{"type":"score","score":2.5,"confidence":0.9,"legend":{"2":"medium"}}}}"#;
        let result = decision_from_response(body, "openrouter", "m", 0).unwrap();
        assert_eq!(result.category, DecisionCategory::Unknown);
        assert!(result
            .evidence
            .iter()
            .any(|line| line.contains("answered with a score answer")));
    }
}
