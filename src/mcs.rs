include!(concat!(env!("OUT_DIR"), "/mcs_proto.rs"));

use bytes::Buf;
use log::warn;
use prost::Message as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _};

pub type Tag = i8;

impl LoginRequest {
    pub const TAG: Tag = 2;
}

#[allow(unused)]
#[derive(Debug)]
pub enum Message {
    HeartbeatPing(HeartbeatPing),
    HeartbeatAck(HeartbeatAck),
    LoginRequest(LoginRequest),
    LoginResponse(LoginResponse),
    Close(Close),
    IqStanza(IqStanza),
    DataMessageStanza(DataMessageStanza),
}

// NOTE: some types should not be decoded as length delimited a.e. ping?
impl Message {
    pub fn decode<B: Buf>(buf: B, tag: Tag) -> Result<Self, DecodeError> {
        Ok(match tag {
            0 => Self::HeartbeatPing(HeartbeatPing::decode(buf)?),
            1 => Self::HeartbeatAck(HeartbeatAck::decode(buf)?),
            2 => Self::LoginRequest(LoginRequest::decode(buf)?),
            3 => Self::LoginResponse(LoginResponse::decode(buf)?),
            4 => Self::Close(Close::decode(buf)?),
            7 => Self::IqStanza(IqStanza::decode(buf)?),
            8 => Self::DataMessageStanza(DataMessageStanza::decode(buf)?),
            _ => return Err(DecodeError::UnknownTag { tag }),
        })
    }
}

/// Errors returned by [`Message::decode()`].
#[derive(Error, Debug)]
#[error("failed to decode mcs message: {0}")]
pub enum DecodeError {
    ProstDecode(#[from] prost::DecodeError),
    #[error("unknown tag `{tag}`")]
    UnknownTag {
        tag: Tag,
    }
}

impl DataMessageStanza {
    /// Returns the first [`AppData`] entry with the given `key`.
    pub(crate) fn app_data(&self, key: impl AsRef<str>) -> Result<&AppData, MissingDataError> {
        let key = key.as_ref();
        let mut result = None;

        for data in &self.app_data {
            if data.key == key {
                match result {
                    Some(_) => {
                        warn!("multiple app-data entries found for key `{key}`");
                        break;
                    }
                    None => result = Some(data),
                }
            }
        }

        result.ok_or(MissingDataError::new(key))
    }
}

/// Error type returned by [`DataMessageStanza::app_data()`].
#[derive(Error, Debug)]
#[error("app data not found for key `{key}`")]
pub struct MissingDataError {
    /// Key used in the lookup.
    pub key: String,
}

impl MissingDataError {
    /// Constructs the type.
    fn new(key: impl Into<String>) -> Self {
        Self { key: key.into() }
    }
}

pub(crate) trait AsyncReadExt {
    ///// Reads a VLQ (variable length quantity) value as an u32 from the underlying reader.
    async fn read_vlq_u32(&mut self) -> Result<u32, ReadError>
    where
        Self: AsyncRead + Unpin,
    {
        let mut shift = 0;
        let mut value = 0;

        for _ in 0..4 {
            let next = self.read_u8().await?;
            value |= ((next & 0b01111111) as u32) << shift;
            if next & 0b10000000 == 0 {
                return Ok(value);
            }
            shift += 7;
        }

        Err(ReadError::VlqTooLarge)
    }
    // Reads an MCS message from the underlying reader.
    async fn read_message(&mut self) -> Result<Message, ReadError>
    where
        Self: AsyncRead + Unpin,
    {
        let tag = self.read_i8().await?;
        let size = self.read_vlq_u32().await?;
        let mut data = vec![0u8; size as usize];

        self.read_exact(data.as_mut_slice()).await?;

        Ok(Message::decode(data.as_slice(), tag)?)
    }
}

impl<R: AsyncRead + ?Sized> AsyncReadExt for R {}

#[derive(Debug, Error)]
#[error("failed to read value: {0}")]
pub enum ReadError {
    TokioIo(#[from] tokio::io::Error),
    ProtoDecode(#[from] DecodeError),
    #[error("vlq value too large")]
    VlqTooLarge,
}
