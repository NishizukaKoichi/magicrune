//! Observability module for MagicRune
//! Provides structured logging, metrics, and distributed tracing

use std::time::Instant;
use tracing::{debug, error, info, instrument, warn, Span};
use tracing_subscriber::EnvFilter;

/// Initialize observability (logging + optional OpenTelemetry)
pub fn init_observability() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Base env filter (e.g., RUST_LOG=info,magicrune=debug)
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // JSON or pretty logging based on env
    let is_json = std::env::var("MAGICRUNE_LOG_JSON").ok() == Some("1".to_string());

    // Build subscriber with format layer
    if is_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_current_span(true)
            .try_init()?;
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(env_filter)
            .with_target(false)
            .try_init()?;
    }

    info!("MagicRune observability initialized");
    Ok(())
}

#[cfg(feature = "otel")]
fn init_otel_tracer(
) -> Result<opentelemetry_sdk::trace::Tracer, Box<dyn std::error::Error + Send + Sync>> {
    use opentelemetry::{global, KeyValue};
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::{runtime, Resource};

    let service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "magicrune".to_string());

    let resource = Resource::new(vec![
        KeyValue::new("service.name", service_name),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
    ]);

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")?),
        )
        .with_trace_config(opentelemetry_sdk::trace::config().with_resource(resource))
        .install_batch(runtime::Tokio)?;

    Ok(tracer)
}

/// Structured execution context with tracing
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub run_id: String,
    pub policy_id: String,
    pub start_time: Instant,
}

impl ExecutionContext {
    pub fn new(run_id: String, policy_id: String) -> Self {
        Self {
            run_id,
            policy_id,
            start_time: Instant::now(),
        }
    }

    /// Create a span for this execution
    pub fn span(&self) -> Span {
        tracing::info_span!(
            "exec",
            run_id = %self.run_id,
            policy_id = %self.policy_id,
            otel.kind = "server",
        )
    }

    /// Record execution metrics
    #[instrument(skip(self))]
    pub fn record_completion(&self, verdict: &str, risk_score: u32, exit_code: i32) {
        let duration_ms = self.start_time.elapsed().as_millis() as u64;

        info!(
            run_id = %self.run_id,
            verdict = %verdict,
            risk_score = risk_score,
            exit_code = exit_code,
            duration_ms = duration_ms,
            "Execution completed"
        );

        // Emit metrics as structured logs (can be parsed by log aggregators)
        info!(
            metric_name = "magicrune_execution_duration_ms",
            value = duration_ms,
            run_id = %self.run_id,
            verdict = %verdict,
            "metric"
        );

        info!(
            metric_name = "magicrune_risk_score",
            value = risk_score,
            run_id = %self.run_id,
            verdict = %verdict,
            "metric"
        );
    }

    /// Record policy violation
    #[instrument(skip(self))]
    pub fn record_policy_violation(&self, violation_type: &str, details: &str) {
        warn!(
            run_id = %self.run_id,
            violation_type = %violation_type,
            details = %details,
            "Policy violation"
        );

        info!(
            metric_name = "magicrune_policy_violations_total",
            value = 1,
            run_id = %self.run_id,
            violation_type = %violation_type,
            "metric"
        );
    }

    /// Record error
    #[instrument(skip(self))]
    pub fn record_error(&self, error_code: &str, message: &str) {
        error!(
            run_id = %self.run_id,
            error_code = %error_code,
            message = %message,
            "Execution error"
        );

        info!(
            metric_name = "magicrune_errors_total",
            value = 1,
            run_id = %self.run_id,
            error_code = %error_code,
            "metric"
        );
    }
}

/// Log sandbox operations
#[instrument]
pub fn log_sandbox_operation(sandbox_type: &str, operation: &str, success: bool) {
    if success {
        debug!(
            sandbox_type = %sandbox_type,
            operation = %operation,
            "Sandbox operation succeeded"
        );
    } else {
        warn!(
            sandbox_type = %sandbox_type,
            operation = %operation,
            "Sandbox operation failed"
        );
    }
}

/// Log JetStream operations
#[instrument]
pub fn log_jetstream_operation(
    operation: &str,
    subject: &str,
    msg_id: &str,
    payload_size: usize,
    success: bool,
) {
    if success {
        debug!(
            operation = %operation,
            subject = %subject,
            msg_id = %msg_id,
            payload_size = payload_size,
            "JetStream operation succeeded"
        );
    } else {
        warn!(
            operation = %operation,
            subject = %subject,
            msg_id = %msg_id,
            payload_size = payload_size,
            "JetStream operation failed"
        );
    }

    info!(
        metric_name = "magicrune_jetstream_operations_total",
        value = 1,
        operation = %operation,
        success = success,
        "metric"
    );
}

/// Shutdown observability (flush traces/metrics)
pub fn shutdown_observability() {
    #[cfg(feature = "otel")]
    {
        opentelemetry::global::shutdown_tracer_provider();
    }
    info!("MagicRune observability shutdown");
}
