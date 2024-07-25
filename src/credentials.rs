use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::fcm::FcmCredentials;
use crate::gcm::GcmCredentials;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credentials {
    pub keys: Keys<String>,
    pub gcm: GcmCredentials,
    pub fcm: FcmCredentials,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Keys<T> {
    pub private_key: T,
    pub public_key: T,
    pub auth_secret: T,
}

impl Keys<String> {
    pub fn new() -> Result<Self, ece::Error> {
        let (keypair, auth_secret) = ece::generate_keypair_and_auth_secret()?;
        let components = keypair.raw_components()?;
        let public_key = BASE64_URL_SAFE_NO_PAD.encode(components.public_key());
        let private_key = BASE64_URL_SAFE_NO_PAD.encode(components.private_key());
        let auth_secret = BASE64_URL_SAFE_NO_PAD.encode(auth_secret);

        Ok(Self {
            private_key,
            public_key,
            auth_secret,
        })
    }
}

impl<T> Keys<T>
where
    T: AsRef<[u8]>,
{
    pub(crate) fn base64_decode(&self) -> Result<Keys<Vec<u8>>, base64::DecodeError> {
        Ok(Keys {
            private_key: BASE64_URL_SAFE_NO_PAD.decode(&self.private_key)?,
            public_key: BASE64_URL_SAFE_NO_PAD.decode(&self.public_key)?,
            auth_secret: BASE64_URL_SAFE_NO_PAD.decode(&self.auth_secret)?,
        })
    }
}

