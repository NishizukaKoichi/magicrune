use anyhow::Result;
use jsonrpc_core::{IoHandler, Params, Value};
use jsonrpc_derive::rpc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub command: String,
    pub working_dir: Option<String>,
    pub env: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub success: bool,
    pub output: String,
    pub verdict: String,
    pub risk_score: u32,
    pub behaviors: Vec<BehaviorSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorSummary {
    pub category: String,
    pub description: String,
    pub severity: String,
}

#[rpc]
pub trait MagicRuneRpc {
    #[rpc(name = "execute")]
    fn execute(&self, request: ExecuteRequest) -> jsonrpc_core::Result<ExecuteResponse>;
    
    #[rpc(name = "analyze")]
    fn analyze(&self, command: String) -> jsonrpc_core::Result<AnalysisResult>;
    
    #[rpc(name = "getPolicy")]
    fn get_policy(&self) -> jsonrpc_core::Result<PolicyInfo>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub is_external: bool,
    pub trust_level: String,
    pub detections: Vec<DetectionInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionInfo {
    pub source_type: String,
    pub description: String,
    pub risk_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInfo {
    pub version: u32,
    pub external_code_policy: String,
    pub network_mode: String,
}

pub struct MagicRuneService {
    policy: Arc<Mutex<magicrune_policy::PolicyConfig>>,
}

impl MagicRuneService {
    pub fn new() -> Result<Self> {
        let policy = magicrune_policy::PolicyConfig::load_from_file(
            magicrune_policy::PolicyConfig::get_policy_path()?
        )?;
        
        Ok(Self {
            policy: Arc::new(Mutex::new(policy)),
        })
    }
}

impl MagicRuneRpc for MagicRuneService {
    fn execute(&self, request: ExecuteRequest) -> jsonrpc_core::Result<ExecuteResponse> {
        // TODO: Implement actual execution logic
        Ok(ExecuteResponse {
            success: true,
            output: format!("Executed: {}", request.command),
            verdict: "Green".to_string(),
            risk_score: 0,
            behaviors: vec![],
        })
    }
    
    fn analyze(&self, command: String) -> jsonrpc_core::Result<AnalysisResult> {
        use magicrune_detector::analyze_command;
        
        let detections = analyze_command(&command)
            .map_err(|e| jsonrpc_core::Error::internal_error())?;
        
        let is_external = !detections.is_empty();
        let trust_level = if is_external { "L2" } else { "L1" };
        
        let detection_info: Vec<DetectionInfo> = detections
            .into_iter()
            .map(|d| DetectionInfo {
                source_type: format!("{:?}", d.source_type),
                description: d.description,
                risk_level: format!("{:?}", d.risk_level),
            })
            .collect();
        
        Ok(AnalysisResult {
            is_external,
            trust_level: trust_level.to_string(),
            detections: detection_info,
        })
    }
    
    fn get_policy(&self) -> jsonrpc_core::Result<PolicyInfo> {
        let policy = self.policy.blocking_lock();
        
        Ok(PolicyInfo {
            version: policy.version,
            external_code_policy: format!("{:?}", policy.default.external_code),
            network_mode: format!("{:?}", policy.default.network_mode),
        })
    }
}

pub async fn start_json_rpc_server(port: u16) -> Result<()> {
    info!("Starting JSON-RPC server on port {}", port);
    
    let service = MagicRuneService::new()?;
    let mut io = IoHandler::new();
    io.extend_with(service.to_delegate());
    
    // TODO: Implement actual server with tokio
    
    Ok(())
}