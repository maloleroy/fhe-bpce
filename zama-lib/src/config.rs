use bincode::{Decode, Encode, serde::Compat};
use tfhe::{ClientKey, Config, ConfigBuilder, generate_keys};

#[derive(Clone)]
/// A server key for TFHE operations.   
pub struct ServerKey(pub(super) tfhe::ServerKey);

impl Encode for ServerKey {
    #[allow(clippy::similar_names)]
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let (skey, ksm, ck, dk, tag) = self.0.clone().into_raw_parts();

        let compat_skey = Compat(skey);
        let compat_ksm = Compat(ksm);
        let compat_ck = Compat(ck);
        let compat_dk = Compat(dk);
        let compat_tag = Compat(tag);
        compat_skey.encode(encoder)?;
        compat_ksm.encode(encoder)?;
        compat_ck.encode(encoder)?;
        compat_dk.encode(encoder)?;
        compat_tag.encode(encoder)?;

        Ok(())
    }
}

impl<Context> Decode<Context> for ServerKey {
    #[allow(clippy::similar_names)]
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let compat_skey = Compat::decode(decoder)?;
        let compat_ksm = Compat::decode(decoder)?;
        let compat_ck = Compat::decode(decoder)?;
        let compat_dk = Compat::decode(decoder)?;
        let compat_tag = Compat::decode(decoder)?;

        let skey = compat_skey.0;
        let ksm = compat_ksm.0;
        let ck = compat_ck.0;
        let dk = compat_dk.0;
        let tag = compat_tag.0;

        Ok(Self(tfhe::ServerKey::from_raw_parts(
            skey, ksm, ck, dk, tag,
        )))
    }
}

#[derive(Clone)]
/// A context for TFHE operations.
pub struct ZamaTfheContext {
    config: Config,
    server_key: Option<ServerKey>,
}

impl Default for ZamaTfheContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ZamaTfheContext {
    #[must_use]
    /// Create a new TFHE context.
    pub fn new() -> Self {
        Self {
            config: ConfigBuilder::default().build(),
            server_key: None,
        }
    }

    #[must_use]
    /// Create a TFHE scheme knowing the server key.
    pub fn from_server_key(server_key: ServerKey) -> Self {
        Self {
            config: ConfigBuilder::default().build(),
            server_key: Some(server_key),
        }
    }

    #[must_use]
    #[inline]
    /// Get the server key.
    ///
    /// # Panics
    ///
    /// Panics if the server key is not set (the configuration is new).
    pub const fn server_key(&self) -> Option<&ServerKey> {
        self.server_key.as_ref()
    }

    #[must_use]
    #[inline]
    /// Generate a set of secret, public and relinearization keys.
    pub fn generate_keys(&self) -> (Option<ClientKey>, ServerKey) {
        self.server_key.as_ref().map_or_else(
            || {
                let (client_key, server_key) = generate_keys(self.config);
                (Some(client_key), ServerKey(server_key))
            },
            |server_key| (None, server_key.clone()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::ZamaTfheContext;

    const CONFIG: bincode::config::Configuration = bincode::config::standard();

    #[test]
    fn test_skey_serde() {
        let ctx = ZamaTfheContext::new();
        let (_ck, skey) = ctx.generate_keys();

        let encoded = bincode::encode_to_vec(&skey, CONFIG).unwrap();
        let (_decoded, _): (super::ServerKey, _) =
            bincode::decode_from_slice(&encoded, CONFIG).unwrap();
    }
}
