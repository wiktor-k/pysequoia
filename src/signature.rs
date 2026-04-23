use std::borrow::Cow;

use anyhow::anyhow;
use pyo3::prelude::*;
use sequoia_openpgp::{
    Packet, armor,
    packet::Signature as SqSignature,
    parse::{PacketParser, PacketParserResult, Parse as _},
};

use crate::types::{HashAlgorithm, PublicKeyAlgorithm, SignatureType};

/// A detached OpenPGP signature.
#[pyclass]
pub struct Sig {
    sig: SqSignature,
}

impl Sig {
    /// Wraps a raw Sequoia [`SqSignature`] packet.
    pub fn new(sig: SqSignature) -> Self {
        Self { sig }
    }

    /// Extracts the first signature packet from a [`PacketParserResult`].
    ///
    /// Returns an error if the parser result is empty or the first packet is not a signature.
    pub fn from_packets(ppr: PacketParserResult<'_>) -> Result<Self, anyhow::Error> {
        if let PacketParserResult::Some(pp) = ppr {
            let (packet, _next_ppr) = pp.recurse()?;
            if let Packet::Signature(sig) = packet {
                return Ok(sig.into());
            }
        }
        Err(anyhow!("Not a signature"))
    }
}

impl From<SqSignature> for Sig {
    fn from(sig: SqSignature) -> Self {
        Self { sig }
    }
}

#[pymethods]
impl Sig {
    /// Loads a signature from a file on disk.
    ///
    /// The file may be binary or ASCII-armored.
    #[staticmethod]
    pub fn from_file(path: String) -> PyResult<Self> {
        Ok(Self::from_packets(PacketParser::from_file(path)?)?)
    }

    /// Loads a signature from a byte string.
    ///
    /// The bytes may be binary or ASCII-armored.
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        Ok(Self::from_packets(PacketParser::from_bytes(bytes)?)?)
    }

    /// Returns the raw binary encoding of the signature packet.
    pub fn __bytes__(&self) -> PyResult<Cow<'_, [u8]>> {
        Ok(crate::serialize(self.sig.clone().into(), None)?.into())
    }

    /// DEPRECATED: The fingerprint of the key that made this signature, as a lowercase hex string.
    ///
    /// Alias for `issuer_fingerprint`. Prefer `issuer_fingerprint` going forwards.
    ///
    /// Returns `None` if the signature does not carry an issuer fingerprint subpacket.
    /// Prefer this over `issuer_key_id` when available, as fingerprints are collision-resistant.
    #[getter]
    #[pyo3(warn(
        message = "Prefer Sig.issuer_fingerprint",
        category = pyo3::exceptions::PyDeprecationWarning
    ))]
    pub fn issuer_fpr(&self) -> Option<String> {
        self.issuer_fingerprint()
    }

    /// The fingerprint of the key that made this signature, as a lowercase hex string.
    ///
    /// Returns `None` if the signature does not carry an issuer fingerprint subpacket.
    #[getter]
    pub fn issuer_fingerprint(&self) -> Option<String> {
        self.sig
            .issuer_fingerprints()
            .next()
            .map(|issuer| format!("{issuer:x}"))
    }

    /// The short key ID of the key that made this signature, as a lowercase hex string.
    ///
    /// Returns `None` if the signature does not carry an issuer key ID subpacket.
    /// Prefer `issuer_fingerprint` over this where possible, as key IDs are not collision-resistant.
    #[getter]
    pub fn issuer_key_id(&self) -> Option<String> {
        self.sig.issuers().next().map(|id| format!("{id:x}"))
    }

    /// The User ID of the signer, as declared in the signature's Signer's User ID subpacket.
    ///
    /// Returns `None` if the signature does not carry a Signer's User ID subpacket.
    /// Note that this value is self-reported by the signer and is not verified against any cert.
    #[getter]
    pub fn signers_user_id(&self) -> Option<String> {
        self.sig
            .signers_user_id()
            .map(|uid| String::from_utf8_lossy(uid).into_owned())
    }

    /// The time at which this signature was created.
    ///
    /// Returns `None` if the signature does not carry a creation time subpacket.
    #[getter]
    pub fn created(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.sig.signature_creation_time().map(Into::into)
    }

    /// The time at which this signature expires, or `None` if it does not expire.
    ///
    /// Returns `None` if either subpacket is absent.
    #[getter]
    pub fn expiration(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.sig.signature_expiration_time().map(Into::into)
    }

    /// The version of this signature packet (e.g. 4 or 6).
    #[getter]
    pub fn version(&self) -> u8 {
        self.sig.version()
    }

    /// The signature type (e.g. `SignatureType.SubkeyBinding`).
    #[getter]
    pub fn signature_type(&self) -> PyResult<SignatureType> {
        Ok(self.sig.typ().try_into()?)
    }

    /// The hash algorithm used by this signature.
    #[getter]
    pub fn hash_algorithm(&self) -> PyResult<HashAlgorithm> {
        Ok(self.sig.hash_algo().try_into()?)
    }

    /// The public key algorithm used by this signature.
    #[getter]
    pub fn key_algorithm(&self) -> PyResult<PublicKeyAlgorithm> {
        Ok(self.sig.pk_algo().try_into()?)
    }

    /// The key validity period as a timedelta from key creation.
    ///
    /// This is the duration after the key's creation time at which the key expires.
    /// Found in Subkey Binding and Direct Key signatures.
    /// Returns `None` if the subpacket is not present.
    #[getter]
    pub fn key_validity_period(&self) -> Option<chrono::TimeDelta> {
        self.sig
            .key_validity_period()
            .and_then(|d| chrono::TimeDelta::from_std(d).ok())
    }

    /// Return the ASCII-armored representation of the signature.
    pub fn __str__(&self) -> PyResult<String> {
        let bytes = crate::serialize(self.sig.clone().into(), armor::Kind::Signature)?;
        Ok(String::from_utf8(bytes)?)
    }

    pub fn __repr__(&self) -> String {
        format!(
            "<Sig issuer_fingerprint={}>",
            self.issuer_fingerprint().unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reading_sig() {
        Sig::from_packets(PacketParser::from_file("tests/fixtures/sig.pgp").unwrap()).unwrap();
    }
}
