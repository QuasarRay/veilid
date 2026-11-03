//! The certificate profile WebTransport hands to the rolling certificate manager.
//!
//! WebTransport over HTTP/3 lets a browser connect to a peer by IP using a self-signed
//! certificate pinned by SHA-256 hash (`serverCertificateHashes`). The spec constrains those
//! certificates: ECDSA P-256 (no RSA), validity under two weeks, and a SHA-256 hash. The short
//! validity is what forces the rolling rotation in [`super::certificate_manager`].

use super::*;

use super::certificate_manager::CertificateProfile;
use rcgen::PKCS_ECDSA_P256_SHA256;

/// The browser reject threshold: the WebTransport spec has browsers reject a self-signed
/// certificate whose validity is two weeks or more.
pub(in crate::network_manager) const WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY: TimestampDuration =
    TimestampDuration::new_days(14);

pub(in crate::network_manager) const WEBTRANSPORT_CERT_MAX_VALIDITY: TimestampDuration =
    WEBTRANSPORT_CERT_BROWSER_MAX_VALIDITY.saturating_sub(TimestampDuration::new_hours(1));

pub(in crate::network_manager) const WEBTRANSPORT_CERT_DEFAULT_VALIDITY: TimestampDuration =
    TimestampDuration::new_days(13);

pub(in crate::network_manager) const WEBTRANSPORT_CERT_HANDOFF_OVERLAP: TimestampDuration =
    TimestampDuration::new_days(1);

/// Subject alternative name placed on the self-signed certificate. WebTransport
/// validates the certificate by hash, not by name, so the value is cosmetic.
const WEBTRANSPORT_CERT_SAN: &str = "veilid.invalid";

pub(in crate::network_manager) const WEBTRANSPORT_CERT_TABLE_NAME: &str = "webtransport_certs";

pub(in crate::network_manager) fn webtransport_certificate_profile(
    validity: TimestampDuration,
) -> CertificateProfile {
    let validity = core::cmp::min(validity, WEBTRANSPORT_CERT_MAX_VALIDITY);
    let sliding_window = TimestampDuration::new(
        validity
            .as_u64()
            .saturating_sub(WEBTRANSPORT_CERT_HANDOFF_OVERLAP.as_u64()),
    );
    CertificateProfile {
        table_name: WEBTRANSPORT_CERT_TABLE_NAME,
        subject_alt_name: WEBTRANSPORT_CERT_SAN,
        key_algorithm: &PKCS_ECDSA_P256_SHA256,
        validity,
        sliding_window,
    }
}
