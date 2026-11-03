use super::*;

use crate::RegisteredComponents;
use rcgen::{CertificateParams, KeyPair, SignatureAlgorithm};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

impl_veilid_log_facility!("net");

const CERT_CLOCK_SKEW_BACKDATE: TimestampDuration = TimestampDuration::new_secs(60 * 60);

const CERT_TABLE_COLUMN_COUNT: u32 = 1;
pub(in crate::network_manager) const CERT_PAIR_KEY: &[u8] = b"certificate_pair";

pub(in crate::network_manager) struct CertificateProfile {
    pub table_name: &'static str,
    pub subject_alt_name: &'static str,
    pub key_algorithm: &'static SignatureAlgorithm,
    pub validity: TimestampDuration,
    pub sliding_window: TimestampDuration,
}

pub(in crate::network_manager) struct CertificateMaintenanceOutcome {
    pub served_certificate_changed: bool,
    pub current_hashes_changed: bool,
}

/// The certificate hashes peers pin, and the instant the serving window behind them ends.
#[derive(Clone, Default)]
pub(in crate::network_manager) struct CertificateAdvertisement {
    pub cert_hashes: Vec<[u8; 32]>,
    pub expiration: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::network_manager) enum CertificateLoad {
    ColdStart,
    Restored,
    Corrupt,
}

#[derive(Clone, Serialize, Deserialize)]
pub(in crate::network_manager) struct ManagedCertificate {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
    pub hash: [u8; 32],
    pub not_before: Timestamp,
    pub not_after: Timestamp,
}

impl fmt::Debug for ManagedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManagedCertificate")
            .field("hash", &hex::encode(self.hash))
            .field("not_before", &self.not_before)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl ManagedCertificate {
    pub(in crate::network_manager) fn is_valid_at(&self, now: Timestamp) -> bool {
        now >= self.not_before && now < self.not_after
    }
}

#[derive(Serialize, Deserialize)]
struct StoredCertificatePair {
    current: Option<ManagedCertificate>,
    next: Option<ManagedCertificate>,
}

#[derive(Default)]
struct CertificateManagerInner {
    current: Option<ManagedCertificate>,
    next: Option<ManagedCertificate>,
}

impl CertificateManagerInner {
    /// The serving rule: the current slot is served until it expires, even when a forward clock
    /// skew leaves its `not_before` ahead of now.
    fn unexpired_current(&self, now: Timestamp) -> Option<&ManagedCertificate> {
        self.current.as_ref().filter(|c| now < c.not_after)
    }

    /// The advertising rule: the staged successor is served only inside its full validity window.
    fn valid_next(&self, now: Timestamp) -> Option<&ManagedCertificate> {
        self.next.as_ref().filter(|n| n.is_valid_at(now))
    }

    fn drop_expired_slots(&mut self, now: Timestamp) {
        if self.current.as_ref().is_some_and(|c| now >= c.not_after) {
            self.current = None;
        }
        if self.next.as_ref().is_some_and(|n| now >= n.not_after) {
            self.next = None;
        }
    }
}

pub(in crate::network_manager) struct CertificateManager {
    registry: VeilidComponentRegistry,
    profile: CertificateProfile,
    inner: Mutex<CertificateManagerInner>,
}

impl_veilid_component_accessors!(CertificateManager);

impl fmt::Debug for CertificateManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertificateManager")
            .field("validity", &self.profile.validity)
            .field("sliding_window", &self.profile.sliding_window)
            .finish_non_exhaustive()
    }
}

impl CertificateManager {
    pub(in crate::network_manager) fn new(
        registry: VeilidComponentRegistry,
        profile: CertificateProfile,
    ) -> Self {
        // PANIC-CENSUS: infallible the only profiles in the tree are compile-time constants whose sliding window is shorter than their validity
        assert!(
            profile.sliding_window < profile.validity,
            "a certificate profile's sliding window must be strictly shorter than its validity"
        );
        Self {
            registry,
            profile,
            inner: Mutex::new(CertificateManagerInner::default()),
        }
    }

    pub(in crate::network_manager) fn generate_certificate(
        profile: &CertificateProfile,
        not_before: Timestamp,
    ) -> VeilidAPIResult<ManagedCertificate> {
        let key_pair = KeyPair::generate_for(profile.key_algorithm)
            .map_err(|e| VeilidAPIError::internal(format!("rcgen keypair: {e}")))?;

        let mut params = CertificateParams::new(vec![profile.subject_alt_name.to_string()])
            .map_err(|e| VeilidAPIError::internal(format!("rcgen params: {e}")))?;
        let not_after = not_before.later(profile.validity);
        params.not_before = timestamp_to_offset_date_time(not_before)?;
        params.not_after = timestamp_to_offset_date_time(not_after)?;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| VeilidAPIError::internal(format!("rcgen self_signed: {e}")))?;

        let certificate_der = cert.der().to_vec();
        let private_key_der = key_pair.serialize_der();
        let hash = sha256(&certificate_der);

        Ok(ManagedCertificate {
            certificate_der,
            private_key_der,
            hash,
            not_before,
            not_after,
        })
    }

    pub(in crate::network_manager) fn update(&self, now: Timestamp) -> VeilidAPIResult<()> {
        let mut inner = self.inner.lock();
        Self::advance_state(&mut inner, now, &self.profile)
    }

    fn advance_state(
        inner: &mut CertificateManagerInner,
        now: Timestamp,
        profile: &CertificateProfile,
    ) -> VeilidAPIResult<()> {
        inner.drop_expired_slots(now);

        if Self::promotion_due(inner, now) {
            inner.current = inner.next.take();
        }

        if inner.current.is_none() {
            inner.current = Some(Self::mint_current(profile, now)?);
        }

        if inner.next.is_none() {
            if let Some(current) = &inner.current {
                inner.next = Some(Self::mint_next(profile, current)?);
            }
        }

        Ok(())
    }

    fn promotion_due(inner: &CertificateManagerInner, now: Timestamp) -> bool {
        match (&inner.current, &inner.next) {
            (Some(current), Some(next)) => Self::switch_due(current, next, now),
            (None, Some(next)) => next.is_valid_at(now),
            _ => false,
        }
    }

    fn switch_due(current: &ManagedCertificate, next: &ManagedCertificate, now: Timestamp) -> bool {
        now >= Self::switch_point(current, next)
    }

    fn mint_current(
        profile: &CertificateProfile,
        now: Timestamp,
    ) -> VeilidAPIResult<ManagedCertificate> {
        let anchor = Timestamp::new(
            now.as_u64()
                .saturating_sub(CERT_CLOCK_SKEW_BACKDATE.as_u64()),
        );
        Self::generate_certificate(profile, anchor)
    }

    fn mint_next(
        profile: &CertificateProfile,
        current: &ManagedCertificate,
    ) -> VeilidAPIResult<ManagedCertificate> {
        Self::generate_certificate(profile, current.not_before.later(profile.sliding_window))
    }

    fn switch_point(current: &ManagedCertificate, next: &ManagedCertificate) -> Timestamp {
        let lo = next.not_before.as_u64();
        let hi = current.not_after.as_u64();
        Timestamp::new(lo + (hi - lo) / 2)
    }

    pub(in crate::network_manager) fn current_certificate(
        &self,
        now: Timestamp,
    ) -> Option<ManagedCertificate> {
        let inner = self.inner.lock();
        inner
            .unexpired_current(now)
            .or_else(|| inner.valid_next(now))
            .cloned()
    }

    pub(in crate::network_manager) fn current_advertisement(&self) -> CertificateAdvertisement {
        let state = self.inner.lock();
        CertificateAdvertisement {
            cert_hashes: Self::current_hashes_of(&state),
            expiration: Self::current_expiration_of(&state),
        }
    }

    fn current_expiration_of(state: &CertificateManagerInner) -> Option<Timestamp> {
        state
            .current
            .as_ref()
            .or(state.next.as_ref())
            .map(|c| c.not_after)
    }

    fn current_hashes_of(state: &CertificateManagerInner) -> Vec<[u8; 32]> {
        let mut hashes = Vec::with_capacity(2);
        if let Some(current) = &state.current {
            hashes.push(current.hash);
        }
        if let Some(next) = &state.next {
            if !hashes.contains(&next.hash) {
                hashes.push(next.hash);
            }
        }
        hashes
    }

    pub(in crate::network_manager) async fn load_or_generate(
        &self,
        now: Timestamp,
    ) -> VeilidAPIResult<()> {
        match self.load_from_storage().await? {
            CertificateLoad::Restored => {}
            CertificateLoad::ColdStart => {
                veilid_log!(self debug "no persisted certificates; minting a fresh rolling pair")
            }
            CertificateLoad::Corrupt => {
                veilid_log!(self debug "no usable persisted certificate slot; minting a fresh rolling pair")
            }
        }
        self.update(now)?;
        self.save_to_storage().await?;
        Ok(())
    }

    pub(in crate::network_manager) async fn maintain(
        &self,
        now: Timestamp,
    ) -> VeilidAPIResult<CertificateMaintenanceOutcome> {
        let mut advanced = {
            let inner = self.inner.lock();
            CertificateManagerInner {
                current: inner.current.clone(),
                next: inner.next.clone(),
            }
        };

        let prev_served = advanced.current.as_ref().map(|c| c.hash);
        let prev_hashes = Self::current_hashes_of(&advanced);

        Self::advance_state(&mut advanced, now, &self.profile)?;

        let new_served = advanced.current.as_ref().map(|c| c.hash);
        let new_hashes = Self::current_hashes_of(&advanced);
        let served_changed = new_served != prev_served;
        let hashes_changed = new_hashes != prev_hashes;

        if served_changed || hashes_changed {
            self.save_then_commit(advanced).await?;
        }

        Ok(CertificateMaintenanceOutcome {
            served_certificate_changed: served_changed,
            current_hashes_changed: hashes_changed,
        })
    }

    async fn save_then_commit(&self, advanced: CertificateManagerInner) -> VeilidAPIResult<()> {
        match self.save_pair(&advanced.current, &advanced.next).await {
            Ok(()) => {
                *self.inner.lock() = advanced;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    async fn save_to_storage(&self) -> VeilidAPIResult<()> {
        let (current, next) = {
            let inner = self.inner.lock();
            (inner.current.clone(), inner.next.clone())
        };
        self.save_pair(&current, &next).await
    }

    async fn save_pair(
        &self,
        current: &Option<ManagedCertificate>,
        next: &Option<ManagedCertificate>,
    ) -> VeilidAPIResult<()> {
        let pair = StoredCertificatePair {
            current: current.clone(),
            next: next.clone(),
        };
        let db = self
            .table_store()
            .open(self.profile.table_name, CERT_TABLE_COLUMN_COUNT)
            .await?;
        db.store_serialized(
            0,
            Bytes::from_static(CERT_PAIR_KEY),
            serialize_table_value(&pair),
        )
        .await
    }

    pub(in crate::network_manager) async fn load_from_storage(
        &self,
    ) -> VeilidAPIResult<CertificateLoad> {
        let db = self
            .table_store()
            .open(self.profile.table_name, CERT_TABLE_COLUMN_COUNT)
            .await?;
        let Some(serialized_pair) = db
            .load_serialized(0, Bytes::from_static(CERT_PAIR_KEY))
            .await?
        else {
            return Ok(CertificateLoad::ColdStart);
        };
        let pair: StoredCertificatePair = self.table_store().try_deserialize(&serialized_pair)?;

        let current = self.restore_slot("current", pair.current);
        let mut next = self.restore_slot("next", pair.next);
        if let (Some(c), Some(n)) = (&current, &next) {
            if n.not_before > c.not_after {
                veilid_log!(self debug "dropping certificate slot 'next': persisted window begins after the current slot expires");
                next = None;
            }
        }
        let loaded = if current.is_some() || next.is_some() {
            CertificateLoad::Restored
        } else {
            CertificateLoad::Corrupt
        };

        let mut inner = self.inner.lock();
        inner.current = current;
        inner.next = next;
        Ok(loaded)
    }

    fn restore_slot(
        &self,
        slot_name: &str,
        cert: Option<ManagedCertificate>,
    ) -> Option<ManagedCertificate> {
        let cert = cert?;
        if sha256(&cert.certificate_der) != cert.hash {
            veilid_log!(self debug "dropping certificate slot '{}': persisted certificate DER does not match its stored hash (bitrot)", slot_name);
            return None;
        }
        if cert.not_before >= cert.not_after {
            veilid_log!(self debug "dropping certificate slot '{}': persisted validity window is empty or inverted", slot_name);
            return None;
        }
        Some(cert)
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

fn timestamp_to_offset_date_time(ts: Timestamp) -> VeilidAPIResult<OffsetDateTime> {
    let nanos = (ts.as_u64() as i128) * 1000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|e| VeilidAPIError::internal(format!("invalid certificate timestamp: {e}")))
}
