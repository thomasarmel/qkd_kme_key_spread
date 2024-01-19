use std::cmp::Ordering;
use std::fmt::Display;
use serde::{Deserialize, Serialize};
use crate::share::Share;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ShareWrapper {
    /// KME id of the generator of the share
    pub(crate) generator_kme_id: i64,
    /// Shamir threshold of the underlying secret share
    pub(crate) threshold: u8,
    /// The actual secret share
    pub(crate) share: Share,
}

impl ShareWrapper {
    pub(crate) fn new(generator_kme_id: i64, threshold: u8, share: Share) -> Self {
        Self {
            generator_kme_id,
            threshold,
            share,
        }
    }
}

impl Display for ShareWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ShareWrapper(generator_kme_id: {}, threshold: {}, share: {})", self.generator_kme_id, self.threshold, self.share)
    }
}

impl PartialOrd<Self> for ShareWrapper {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        if self.generator_kme_id == other.generator_kme_id {
            None
        } else if self.generator_kme_id < other.generator_kme_id {
            Some(Ordering::Greater)
        } else {
            Some(Ordering::Less)
        }
    }
}

impl Ord for ShareWrapper {
    fn cmp(&self, other: &Self) -> Ordering {
        // We only care about the generator KME ID, if it's the same, we return Less in order to avoid being equal
        self.partial_cmp(other).unwrap_or_else(|| Ordering::Less)
    }
}