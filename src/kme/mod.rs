use std::collections::BTreeSet;
use std::sync::Arc;
use itertools::Itertools;
use ssss::SsssConfig;
use crate::share::{Share, SharedSecretType};
use crate::share_wrapper::ShareWrapper;
use tracing::{error, info, warn};

pub struct Kme {
    pub id: i64,
    secret: Option<Vec<u8>>,
    share_wrappers: Vec<ShareWrapper>,
}

impl Kme {
    pub fn new(id: i64) -> Self {
        Self {
            id,
            secret: None,
            share_wrappers: Vec::new(),
        }
    }

    /// Set initial secret to the first KME
    /// # Arguments
    /// * `secret` - The secret to be spread across the KMEs
    pub fn set_secret(&mut self, secret: &[u8]) {
        info!("KME{}: setting secret", self.id);
        self.secret = Some(secret.to_vec());
    }

    /// Receive a serialized share wrapper from another KME
    /// The share wrapper is normally supposed to be encrypted using the QKD key
    /// # Arguments
    /// * `serial_share_wrapper` - The postman serialized share wrapper
    pub(crate) fn receive_qkd_encrypted_share_wrapper(&mut self, serial_share_wrapper: &[u8]) {
        // For this example we skip the QKD encryption
        let share_wrapper: ShareWrapper = postcard::from_bytes(serial_share_wrapper).unwrap();
        info!("KME{}: adding share wrapper {}", self.id, share_wrapper);
        self.share_wrappers.push(share_wrapper);
    }

    pub fn spread_secrets(&mut self, dest_kmes: &mut [&mut Kme]) {
        let nb_shares = dest_kmes.len() as u8;
        let threshold = nb_shares / 2 + 1;

        let mut shamir_config = SsssConfig::default();
        shamir_config.set_num_shares(nb_shares);
        shamir_config.set_threshold(threshold);

        if self.secret.is_some() {
            let mut shares_str = ssss::gen_shares(&shamir_config, &self.secret.as_ref().unwrap()).unwrap();
            for (_, kme) in dest_kmes.iter_mut().enumerate() {
                let share_str = shares_str.remove(0);
                let share = Share::from_string(&share_str, SharedSecretType::Secret).unwrap();
                let share_wrapper = ShareWrapper::new(self.id, threshold, share);
                let serial_share_wrapper = postcard::to_allocvec(&share_wrapper).unwrap();
                info!("KME{}: sending {} to KME {}", self.id, share_wrapper, kme.id);
                kme.receive_qkd_encrypted_share_wrapper(&serial_share_wrapper);
            }
        }
        self.secret = None;

        while let Some(stored_share_wrapper) = self.share_wrappers.pop() {
            let serial_stored_share_wrapper = postcard::to_allocvec(&stored_share_wrapper).unwrap();
            if dest_kmes.len() == 1 {
                // Only 1 destination, no need to split the share
                info!("KME{}: sending directly {} to KME {}", self.id, stored_share_wrapper, dest_kmes[0].id);
                dest_kmes[0].receive_qkd_encrypted_share_wrapper(&serial_stored_share_wrapper);
            } else {
                let mut shares_str = ssss::gen_shares(&shamir_config, &serial_stored_share_wrapper).unwrap();
                for (_, kme) in dest_kmes.iter_mut().enumerate() {
                    let share_str = shares_str.remove(0);
                    let share = Share::from_string(&share_str, SharedSecretType::SubShareWrapper).unwrap();
                    let share_wrapper = ShareWrapper::new(self.id, threshold, share);
                    let serial_share_wrapper = postcard::to_allocvec(&share_wrapper).unwrap();
                    info!("KME{}: sending {} to KME {}", self.id, share_wrapper, kme.id);
                    kme.receive_qkd_encrypted_share_wrapper(&serial_share_wrapper);
                }
            }
        }
    }

    /// Try to retrieve the secret from the shares we have
    /// # Returns
    /// Some(secret) if we have enough shares to retrieve the secret
    /// None otherwise
    pub fn try_retrieve_secret(&self) -> Option<Vec<u8>> {
        if self.secret.is_some() {
            info!("KME{}: secret already known", self.id);
            return self.secret.clone();
        }

        // Automatically sorted shares, by origin KME id
        let mut share_wrapper_btree = BTreeSet::from_iter(self.share_wrappers.iter().map(|wrapper| Arc::new(wrapper.clone())));
        while share_wrapper_btree.len() > 0 {
            let mut newly_discovered_share_wrappers = Vec::new();
            for (_, kme_generated_shares) in share_wrapper_btree.iter().group_by(|share_wrapper| share_wrapper.generator_kme_id).into_iter() {
                let mut threshold: u8 = 0;
                let mut nb_elements: u8 = 0;
                let mut shares_underlying_type = SharedSecretType::Secret;
                let shares_str = kme_generated_shares.map(|share_wrapper| {
                    threshold = share_wrapper.threshold;
                    shares_underlying_type = share_wrapper.share.shared_secret_type;
                    nb_elements += 1;
                    share_wrapper.share.to_string()
                }).collect::<Vec<_>>();
                if nb_elements < threshold {
                    warn!("KME{}: not enough shares to retrieve secret", self.id);
                    continue;
                }
                let decrypted_shared_secret = match ssss::unlock(&shares_str) {
                    Ok(decrypted_shared_secret) => decrypted_shared_secret,
                    Err(_) => {
                        error!("Error decrypting secret");
                        continue;
                    }
                };
                if shares_underlying_type == SharedSecretType::Secret {
                    info!("KME{}: retrieved secret {:?}", self.id, decrypted_shared_secret);
                    return Some(decrypted_shared_secret);
                } else {
                    let discovered_underlying_share_wrapper: ShareWrapper = match postcard::from_bytes(&decrypted_shared_secret) {
                        Ok(share_wrapper) => share_wrapper,
                        Err(_) => {
                            error!("KME{}: Error deserializing share wrapper, likely we received fake information", self.id);
                            continue;
                        }
                    };
                    info!("KME{}: retrieved sub share wrapper {:?}", self.id, discovered_underlying_share_wrapper);
                    newly_discovered_share_wrappers.push(discovered_underlying_share_wrapper);
                }
            }
            share_wrapper_btree.clear();
            // Insert newly discovered share wrappers from the current iteration
            for wrapper in newly_discovered_share_wrappers {
                let wrapper = Arc::new(wrapper);
                share_wrapper_btree.insert(wrapper);
            }
        }
        warn!("KME{}: could not retrieve secret", self.id);
        None
    }
}