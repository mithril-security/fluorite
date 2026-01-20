use serde::{Deserialize, Serialize};

const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata";
const VCEK_CERT_PATH: &str = "/THIM/amd/certification";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImdsAmdCertificationResponse {
    pub vcek_cert: String,
    pub tcbm: String,
    pub certificate_chain: String,
    pub cache_control: String,
}

pub async fn get_vcek_certchain() -> anyhow::Result<String> {
    let client = reqwest::Client::new();

    // The URL we're making a request to
    let url = format!("{IMDS_ENDPOINT}{VCEK_CERT_PATH}");

    // Make the GET request, passing in the URL and the headers
    let imds_response: ImdsAmdCertificationResponse = client
        .get(url)
        .header("Metadata", "true")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(imds_response.vcek_cert + &imds_response.certificate_chain)
    // todo!();
    // AttestationResult result(AttestationResult::ErrorCode::SUCCESS);
    // std::string http_response;
    // std::string url = std::string(imds_endpoint) +
    //                   std::string(vcek_cert_path);

    // HttpClient http_client;
    // if ((result = http_client.InvokeHttpImdsRequest(http_response, url, HttpClient::HttpVerb::GET)).code_ != AttestationResult::ErrorCode::SUCCESS) {
    //     CLIENT_LOG_ERROR("Failed to retrieve VCek certificate from IMDS: %s",
    //         result.description_.c_str());
    //     return result;
    // }

    // Json::Value root;
    // Json::Reader reader;
    // bool parsing_successful = reader.parse(http_response, root);
    // if (!parsing_successful) {
    //     CLIENT_LOG_ERROR("Invalid JSON reponse from IMDS");
    //     result.code_ = AttestationResult::ErrorCode::ERROR_INVALID_JSON_RESPONSE;
    //     result.description_ = std::string("Invalid JSON reponse from IMDS");
    //     return result;
    // }

    // std::string cert = root["vcekCert"].asString();
    // std::string chain = root["certificateChain"].asString();
    // if (cert.empty() ||
    //     chain.empty()) {
    //     CLIENT_LOG_ERROR("Empty VCek cert received from THIM");
    //     result.code_ = AttestationResult::ErrorCode::ERROR_EMPTY_VCEK_CERT;
    //     result.description_ = std::string("Empty VCek cert received from THIM");
    //     return result;
    // }

    // CLIENT_LOG_DEBUG("VCek cert received from IMDS successfully");
    // std::string cert_chain = cert + chain;
    // vcek_cert = attest::base64::base64_encode(cert_chain);
    // return result;
}

#[tokio::test]
async fn test_get_vcek_cert() {}
