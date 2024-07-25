pub mod proto {
    #![allow(clippy::enum_variant_names)]
    include!(concat!(env!("OUT_DIR"), "/checkin_proto.rs"));
}
use proto::*;
use reqwest::Client as Http;
use prost::Message;
use serde::{Serialize, Deserialize};
use thiserror::Error;

pub const CHECKIN_URL: &str = "https://android.clients.google.com/checkin";
pub const REGISTER_URL: &str = "https://android.clients.google.com/c2dm/register3";

impl AndroidCheckinRequest {
    pub(crate) fn new(android_id: Option<u64>, security_token: Option<u64>) -> Self {
        Self {
            user_serial_number: 0.into(),
            checkin: AndroidCheckinProto {
                r#type: 3.into(),
                chrome_build: ChromeBuildProto {
                    platform: 2.into(),
                    chrome_version: "63.0.3234.0".to_string().into(),
                    channel: 1.into(),
                }
                .into(),
                ..Default::default()
            },
            version: 3.into(),
            id: android_id.map(|id| id as i64),
            security_token,
            ..Default::default()
        }
    }
}

pub async fn check_in(
    http: &Http,
    android_id: Option<u64>,
    security_token: Option<u64>,
) -> Result<AndroidCheckinResponse, CheckInError> {
    let mut buf = Vec::new();
    AndroidCheckinRequest::new(android_id, security_token).encode(&mut buf)?;

    let response = http
        .post(CHECKIN_URL)
        .header("Content-Type", "application/x-protobuf")
        .body(buf)
        .send()
        .await?
        .error_for_status()?;

    Ok(AndroidCheckinResponse::decode(response.bytes().await?)?)
}

#[derive(Debug, Error)]
#[error("gcm check-in failed: {0}")]
pub enum CheckInError {
    Http(#[from] reqwest::Error),
    ProtoEncode(#[from] prost::EncodeError),
    ProtoDecode(#[from] prost::DecodeError),
}

#[derive(Debug, Serialize)]
pub(crate) struct RegisterForm {
    pub app: String,
    #[serde(rename = "X-subtype")]
    pub x_subtype: String,
    pub device: String,
    pub sender: String,
}

pub async fn register(
    http: &Http,
    app_id: impl AsRef<str>,
    server_key: impl AsRef<str>,
) -> Result<GcmCredentials, RegisterError> {
    let server_key = server_key.as_ref();
    let response = check_in(http, None, None).await?;
    let android_id = response.android_id().to_string();
    let security_token = response.security_token().to_string();

    let form = RegisterForm {
        app: "org.chromium.linux".into(),
        x_subtype: app_id.as_ref().into(),
        device: android_id.to_string(),
        sender: server_key.into(),
    };

    log::debug!("{form:#?}");

    let request = http
        .post(REGISTER_URL)
        .header(
            "Authorization",
            format!("AidLogin {}:{}", android_id, security_token),
        )
        .form(&form)
        .build()?;

    log::debug!("{request:#?}");

    let response = http.execute(request).await?.error_for_status()?;

    log::debug!("{response:#?}");

    let body = response.text().await?;

    Ok(GcmCredentials {
        token: body.split('=').nth(1).unwrap().into(),
        app_id: app_id.as_ref().into(),
        security_token,
        android_id,
    })
}

#[derive(Debug, Error)]
#[error("failed to register with gcm: {0}")]
pub enum RegisterError {
    CheckIn(#[from] CheckInError),
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GcmCredentials {
    pub token: String,
    pub android_id: String,
    pub security_token: String,
    pub app_id: String,
}
