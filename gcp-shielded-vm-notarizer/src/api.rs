//! API endpoints for the GCP Shielded VM Notarizer

use std::sync::Arc;

use anyhow::{Context, bail};
use attestation::msg::SignedMessage;
use axum::{Json, extract::State, response::IntoResponse};
use chrono::Utc;
use log::info;
use serde::{Deserialize, Serialize};

use crate::attestation::{
    NotarizedShieldedVmIdentityPayload, NotarizerAttestation, NotarizerState,
};
use crate::gcp_api::get_shielded_vm_identity;
use crate::web_error::AppError;

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// The notarizer state (contains signing key and event log)
    pub notarizer_state: Arc<NotarizerState>,

    /// The notarizer's CVM attestation (generated once at startup)
    pub notarizer_attestation: NotarizerAttestation,

    /// Optional: restrict to a specific GCP project
    pub allowed_project: Option<String>,
}

// ============================================================================
// Request/Response types
// ============================================================================

/// Request to notarize a Shielded VM's identity
#[derive(Debug, Deserialize)]
pub struct NotarizeRequest {
    /// GCP project ID
    pub project: String,

    /// GCP zone (e.g., "us-central1-a")
    pub zone: String,

    /// Instance name
    pub instance: String,
}

/// Response containing the notarized identity and notarizer attestation
#[derive(Debug, Serialize)]
pub struct NotarizeResponse {
    /// The notarized Shielded VM identity
    pub notarized_identity: SignedMessage<NotarizedShieldedVmIdentityPayload>,

    /// The notarizer's CVM attestation (proves the signing key is genuine)
    pub notarizer_attestation: NotarizerAttestation,
}

/// Response for the attestation endpoint
#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    /// The notarizer's CVM attestation
    pub notarizer_attestation: NotarizerAttestation,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Health check endpoint
pub async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "gcp-shielded-vm-notarizer".to_string(),
    })
}

/// Get the notarizer's attestation document
pub async fn get_notarizer_attestation(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Return the attestation generated at startup
    Ok(Json(AttestationResponse {
        notarizer_attestation: state.notarizer_attestation.clone(),
    }))
}

/// Notarize a Shielded VM's identity
///
/// This endpoint:
/// 1. Validates the request
/// 2. Calls GCP's getShieldedVmIdentity API
/// 3. Signs the response with the notarizer's key
/// 4. Optionally logs the notarization to the TPM event log
/// 5. Returns the signed identity along with the notarizer's attestation
pub async fn notarize_shielded_vm(
    State(state): State<AppState>,
    Json(request): Json<NotarizeRequest>,
) -> Result<impl IntoResponse, AppError> {
    let result = notarize_shielded_vm_impl(state, request).await?;
    Ok(Json(result))
}

async fn notarize_shielded_vm_impl(
    state: AppState,
    request: NotarizeRequest,
) -> anyhow::Result<NotarizeResponse> {
    info!(
        "Notarizing Shielded VM: {}/{}/{}",
        request.project, request.zone, request.instance
    );

    // Check project restriction if configured
    if let Some(allowed_project) = &state.allowed_project {
        if &request.project != allowed_project {
            bail!(
                "Project '{}' is not allowed. This notarizer only serves project '{}'",
                request.project,
                allowed_project
            );
        }
    }

    // Fetch the Shielded VM identity from GCP
    let shielded_vm_identity =
        get_shielded_vm_identity(&request.project, &request.zone, &request.instance)
            .await
            .context("Failed to fetch Shielded VM identity from GCP")?;

    let notarized_at = Utc::now();
    let timestamp_str = notarized_at.to_rfc3339();

    // Create the payload to sign
    let payload = NotarizedShieldedVmIdentityPayload {
        shielded_vm_identity: shielded_vm_identity.clone(),
        notarized_at: timestamp_str.clone(),
        project: request.project.clone(),
        zone: request.zone.clone(),
        instance: request.instance.clone(),
    };

    // Get the notarizer state for signing
    let notarizer_state = state.notarizer_state;

    // Sign the payload
    let signed_message = notarizer_state
        .sign_payload(&payload)
        .context("Failed to sign payload")?;

    info!("Successfully notarized Shielded VM identity");

    // Use the attestation generated at startup
    Ok(NotarizeResponse {
        notarized_identity: signed_message,
        notarizer_attestation: state.notarizer_attestation.clone(),
    })
}
