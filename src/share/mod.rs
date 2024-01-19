mod base62;

use std::fmt::Display;
use serde::{Deserialize, Serialize};
use base62::{decode, encode};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum SharedSecretType {
    /// The contained secret is the secret
    Secret,
    /// The contained secret is another ShareWrapper, serialized
    SubShareWrapper,
}

impl Display for SharedSecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SharedSecretType::Secret => write!(f, "SecretKey"),
            SharedSecretType::SubShareWrapper => write!(f, "SubShareWrapper"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Share {
    index: u8,
    data: Vec<u8>,
    pub(crate) shared_secret_type: SharedSecretType,
}

impl Share {
    pub(crate) fn from_string(share: &str, shared_secret_type: SharedSecretType) -> Result<Self, ()> {
        // Adapt to ssss format
        let split_str = share.split(':').collect::<Vec<&str>>();
        if split_str.len() == 2 {
            let idx_bytes = decode(split_str[0])?;
            let idx = u8::from_be_bytes((&idx_bytes[..]).try_into().map_err(|_| ())?);
            let share = decode(split_str[1])?;
            Ok(Self {
                index: idx,
                data: share,
                shared_secret_type
            })
        } else {
            Err(())
        }
    }

    pub(crate) fn to_string(&self) -> String {
        // Adapt to ssss format
        let idx = u8::from(self.index);
        let idx_enc = encode(&idx.to_be_bytes());
        let share_enc = encode(&self.data);
        format!("{idx_enc}:{share_enc}")
    }
}

impl Display for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share(index: {}, type: {})", self.index, self.shared_secret_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share() {
        const INIT_SHARE_STR: &'static str = "TcYXL5utmLIu1B:us4f1ZVCj5sT8h1jYGYZdRR51T7djc8F3iXYXxxS8i8QSvFlyxzqKkN4FOismWHZke8FFAUZeHbbCHrPW3hMQQdo5UoO5gp03rq5";
        let share1 = Share::from_string(INIT_SHARE_STR, SharedSecretType::Secret).unwrap();
        let share1_str = share1.to_string();
        let share2 = Share::from_string(&share1_str, SharedSecretType::Secret).unwrap();
        assert_eq!(share1, share2);
    }
}
