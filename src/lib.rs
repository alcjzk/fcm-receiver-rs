//! # FCM web-push receiver implementation for Rust.
//!
//! This crate is a port of [MatthieuLemoine/push-receiver](https://github.com/MatthieuLemoine/push-receiver) into Rust, made for a
//! personal project. It uses deprecated legacy endpoints and a
//! hardcoded server-key originating from the aforementioned repository. Please consider using
//! another alternative like [fcm-push-listener](https://crates.io/crates/fcm-push-listener).
//!
// https://chromium.googlesource.com/chromium/chromium/+/trunk/google_apis/gcm/
use base64::DecodeError;
use async_stream::stream;
use base64::prelude::{Engine as _, BASE64_URL_SAFE};
use ece::crypto::EcKeyComponents;
use ece::legacy::AesGcmEncryptedBlock;
use futures_util::Stream;
use mcs::{DataMessageStanza, LoginRequest, Message, MissingDataError};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::{self, Duration};
use tokio_native_tls::{native_tls::TlsConnector as RawTlsConnector, TlsConnector, TlsStream};
use uuid::Uuid;

use prost::Message as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use mcs::AsyncReadExt as _;

mod credentials;
mod fcm;
mod gcm;
mod mcs;

use gcm::GcmCredentials;

pub use credentials::{Credentials, Keys};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

use reqwest::Client as Http;

const HOST: &str = "mtalk.google.com";
// Hardcoded server-key from https://github.com/MatthieuLemoine/push-receiver
// likely not possible to properly generate keys for this endpoint via the firebase endpoint
// anymore.
const SERVER_KEY: &str =
    "BDOU99-h67HcA6JeFXHbSNMu7e2yNNu3RzoMj8TM4W88jITfq7ZmPvIM1Iv-4_l2LxQcYwhqby2xGpWwzjfAnG4";
const PORT: usize = 5228;
const MCS_VERSION: u8 = 41;

/// Client for receiving FCM push notifications.
#[derive(Debug)]
pub struct Client {
    /// Persistent IDs of received messages.
    pub persistent_ids: Vec<String>,
    auth_secret: Vec<u8>,
    ec_components: EcKeyComponents,
    gcm_credentials: GcmCredentials,
    connect_retry_timeout_max: Duration,
    http: reqwest::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Decrypt(#[from] DecryptError),
    #[error(transparent)]
    Login(#[from] LoginRequestError),
    #[error(transparent)]
    GcmCheckIn(#[from] gcm::CheckInError),
    #[error(transparent)]
    GcmRegister(#[from] gcm::RegisterError),
    #[error(transparent)]
    FcmRegister(#[from] fcm::RegisterError),
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),
    #[error("network error: {0}")]
    Network(#[from] std::io::Error),
    #[error(transparent)]
    Tls(#[from] tokio_native_tls::native_tls::Error),
}

impl Client {
    /// Constructs the client.
    pub fn new(credentials: Credentials) -> Result<Self, ClientError> {
        let keys = credentials.keys.base64_decode()?;
        let gcm_credentials = credentials.gcm;
        let ec_components = EcKeyComponents::new(keys.private_key, keys.public_key);

        Ok(Self {
            auth_secret: keys.auth_secret,
            ec_components,
            gcm_credentials,
            persistent_ids: Default::default(),
            connect_retry_timeout_max: Duration::from_secs(80),
            http: reqwest::Client::new(),
        })
    }

    /// Registers the client with FCM and returns [`Credentials`] for the [`Client`].
    pub async fn register(sender_id: impl Into<String>) -> Result<Credentials, ClientError> {
        Self::register_with(sender_id, SERVER_KEY).await
    }

    /// Registers the client with FCM and returns [`Credentials`] for the [`Client`].
    pub async fn register_with(
        sender_id: impl Into<String>,
        server_key: impl AsRef<str>,
    ) -> Result<Credentials, ClientError> {
        let http = Http::new();

        let mut uuid_buffer = Uuid::encode_buffer();
        let uuid = Uuid::new_v4()
            .as_hyphenated()
            .encode_lower(&mut uuid_buffer);

        let app_id = format!("wp:receiver.push.com#{uuid}");
        let gcm_credentials = gcm::register(&http, app_id, server_key).await?;
        let registration = fcm::register(sender_id, &gcm_credentials.token).await?;

        log::debug!("{registration:#?}");

        Ok(Credentials {
            gcm: gcm_credentials,
            keys: registration.keys,
            fcm: registration.fcm,
        })
    }

    /// Returns a stream that yields FCM notifications.
    pub fn notifications(&mut self) -> impl Stream<Item = Result<Vec<u8>, ClientError>> + '_ {
        stream! {loop {
            let mut stream = self.connect().await;
            log::info!("fcm connected");
            loop {
                match stream.read_message().await {
                    Ok(message) => {
                        log::debug!("{message:#?}");
                        match message {
                            Message::DataMessageStanza(message) => {
                                let persistent_id = message.persistent_id().to_string();
                                if !self.persistent_ids.contains(&persistent_id) {
                                    self.persistent_ids.push(message.persistent_id().to_string());
                                    yield Ok(self.decrypt(message)?);
                                }
                            },
                            Message::LoginResponse(_) => {
                                self.persistent_ids = Vec::new();
                            },
                            _ => ()
                        }
                    }
                    Err(error) => {
                        log::error!("{error:#?}");
                        break;
                    }
                }
            }
        }}
    }

    /// Repeatedly attempts to connect to FCM until succeeded, returning a raw stream.
    pub(crate) async fn connect(&mut self) -> TlsStream<TcpStream> {
        match self.try_connect().await {
            Ok(stream) => return stream,
            Err(error) => log::debug!("{error:?}"),
        }
        let mut retry_attempt = 1;
        let mut retry_timeout = Duration::from_secs(5);
        loop {
            log::warn!(
                "fcm connection failed, trying again in {} seconds (attempt {})",
                retry_timeout.as_secs(),
                retry_attempt
            );
            time::sleep(retry_timeout).await;
            match self.try_connect().await {
                Ok(stream) => return stream,
                Err(error) => log::debug!("{error:?}"),
            }
            retry_attempt += 1;
            retry_timeout = self.connect_retry_timeout_max.min(retry_timeout * 2);
        }
    }

    /// Attempts to connect to FCM, returning a raw stream.
    pub(crate) async fn try_connect(&mut self) -> Result<TlsStream<TcpStream>, ClientError> {
        self.check_in().await?;

        // Init stream
        let address = format!("{HOST}:{PORT}");
        let tcp_stream = TcpStream::connect(address).await?;
        let connector = TlsConnector::from(RawTlsConnector::new()?);
        let mut stream = connector.connect(HOST, tcp_stream).await?;
        stream.write_u8(MCS_VERSION).await?;

        // Login
        stream.write_i8(LoginRequest::TAG).await?;
        let buf = self.login_request()?.encode_length_delimited_to_vec();

        stream.write_all(&buf).await?;

        let mcs_version = stream.read_u8().await?;
        if mcs_version != MCS_VERSION {
            log::warn!("unexpected mcs version `{mcs_version}` (expected `{MCS_VERSION}`)");
        }

        Ok(stream)
    }

    fn decrypt(&self, msg: DataMessageStanza) -> Result<Vec<u8>, DecryptError> {
        let crypto_key = &msg.app_data("crypo-key")?.value[3..];
        let salt = &msg.app_data("encryption")?.value[5..];

        let auth = &self.auth_secret;
        let dh = BASE64_URL_SAFE.decode(crypto_key)?;
        let ciphertext = msg.raw_data();
        let rs = ciphertext.len() as u32;
        let salt = BASE64_URL_SAFE.decode(salt)?;

        let data = AesGcmEncryptedBlock::new(&dh, &salt, rs, ciphertext.to_vec())?;
        Ok(ece::legacy::decrypt_aesgcm(
            &self.ec_components,
            auth,
            &data,
        )?)
    }

    async fn check_in(&self) -> Result<(), ClientError> {
        let android_id = &self.gcm_credentials.android_id;
        let security_token = &self.gcm_credentials.security_token;
        let response = gcm::check_in(
            &self.http,
            android_id.parse::<u64>().ok(),
            security_token.parse::<u64>().ok(),
        )
        .await?;

        log::debug!("gcm check-in response: {response:#?}");
        Ok(())
    }

    fn login_request(&mut self) -> Result<LoginRequest, LoginRequestError> {
        let android_id = &self.gcm_credentials.android_id;
        let android_id = android_id
            .parse::<i64>()
            .map_err(|_| LoginRequestError::invalid_android_id(android_id))?;
        let device_id = format!("android-{android_id:x}");

        Ok(LoginRequest {
            adaptive_heartbeat: false.into(),
            auth_service: 2.into(),
            auth_token: self.gcm_credentials.security_token.clone(),
            id: "chrome-63.0.3234.0".into(),
            domain: "mcs.android.com".into(),
            device_id: device_id.into(),
            network_type: 1.into(),
            resource: self.gcm_credentials.android_id.clone(),
            user: self.gcm_credentials.android_id.clone(),
            use_rmq2: true.into(),
            setting: vec![mcs::Setting {
                name: "new_vc".into(),
                value: "1".into(),
            }],
            received_persistent_id: std::mem::take(&mut self.persistent_ids),
            ..Default::default()
        })
    }
}

#[derive(Debug, Error)]
#[error("failed to create login request: {0}")]
pub enum LoginRequestError {
    #[error("invalid android id: {android_id}")]
    InvalidAndroidId { android_id: String },
}

impl LoginRequestError {
    fn invalid_android_id(android_id: impl Into<String>) -> Self {
        Self::InvalidAndroidId {
            android_id: android_id.into(),
        }
    }
}

#[derive(Debug, Error)]
#[error("failed to decrypt message: {0}")]
pub enum DecryptError {
    MissingData(#[from] MissingDataError),
    Ece(#[from] ece::Error),
    Base64Decode(#[from] DecodeError),
}
