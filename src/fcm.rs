use crate::credentials::Keys;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub(crate) mod endpoint {
    pub(crate) const SUBSCRIBE: &str = "https://fcm.googleapis.com/fcm/connect/subscribe";
    pub(crate) const SEND: &str = "https://fcm.googleapis.com/fcm/send";
}

#[derive(Debug, Serialize)]
struct RegisterForm {
    authorized_entity: String,
    endpoint: String,
    encryption_key: String,
    encryption_auth: String,
}

impl RegisterForm {
    fn new(
        sender_id: impl Into<String>,
        token: impl AsRef<str>,
        public_key: impl Into<String>,
        auth_secret: impl Into<String>,
    ) -> Self {
        let public_key = public_key.into();
        let auth_secret = auth_secret.into();
        let token = token.as_ref();
        let endpoint = endpoint::SEND;

        Self {
            authorized_entity: sender_id.into(),
            endpoint: format!("{endpoint}/{token}"),
            encryption_key: public_key,
            encryption_auth: auth_secret,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FcmCredentials {
    pub token: String,
    pub push_set: String,
}

#[derive(Debug)]
pub struct Registration {
    pub keys: Keys<String>,
    pub fcm: FcmCredentials,
}

pub async fn register(
    sender_id: impl Into<String>,
    token: impl AsRef<str>,
) -> Result<Registration, RegisterError> {
    let keys: Keys<String> = Keys::new()?;

    let client = reqwest::Client::new();

    let form = RegisterForm::new(
        sender_id,
        token.as_ref(),
        &keys.public_key,
        &keys.auth_secret,
    );

    log::debug!("{form:#?}");

    let response: FcmCredentials = client
        .post(endpoint::SUBSCRIBE)
        .form(&form)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(Registration {
        keys,
        fcm: response,
    })
}

#[derive(Debug, Error)]
#[error("failed to register with fcm: {0}")]
pub enum RegisterError {
    Ece(#[from] ece::Error),
    Http(#[from] reqwest::Error),
}
