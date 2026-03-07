use std::borrow::Cow;

use pyo3::prelude::*;
use sequoia_openpgp::{Packet, PacketPile as SqPacketPile, parse::Parse, serialize::Marshal};

use crate::notation::Notation;
use crate::types::{DataFormat, HashAlgorithm, KeyFlags, PublicKeyAlgorithm, SignatureType, Tag};

/// A parsed collection of OpenPGP packets.
///
/// Wraps Sequoia's `PacketPile` to provide iteration over the individual
/// packets contained in an OpenPGP message, key block, or signature.
#[pyclass]
pub struct PacketPile {
    packets: Vec<PyPacket>,
}

#[pymethods]
impl PacketPile {
    /// Parse packets from a byte string.
    ///
    /// The input may be binary or ASCII-armored.
    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let pile = SqPacketPile::from_bytes(bytes)?;
        let packets = pile
            .descendants()
            .cloned()
            .map(|p| PyPacket { packet: p })
            .collect();
        Ok(Self { packets })
    }

    /// Parse packets from a file on disk.
    ///
    /// The file may be binary or ASCII-armored.
    #[staticmethod]
    pub fn from_file(path: String) -> PyResult<Self> {
        let pile = SqPacketPile::from_file(path)?;
        let packets = pile
            .descendants()
            .cloned()
            .map(|p| PyPacket { packet: p })
            .collect();
        Ok(Self { packets })
    }

    fn __iter__(slf: PyRef<'_, Self>) -> PacketIter {
        PacketIter {
            inner: slf.packets.clone().into_iter(),
        }
    }

    fn __len__(&self) -> usize {
        self.packets.len()
    }

    fn __repr__(&self) -> String {
        format!("<PacketPile len={}>", self.packets.len())
    }
}

#[pyclass]
struct PacketIter {
    inner: std::vec::IntoIter<PyPacket>,
}

#[pymethods]
impl PacketIter {
    fn __iter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    fn __next__(&mut self) -> Option<PyPacket> {
        self.inner.next()
    }
}

/// A single OpenPGP packet.
///
/// Provides the packet tag and type-specific accessors for extracting
/// data from different packet types (keys, signatures, user IDs, etc.).
/// Accessors return `None` when called on the wrong packet type.
#[pyclass(name = "Packet", skip_from_py_object)]
#[derive(Clone)]
pub struct PyPacket {
    packet: Packet,
}

#[pymethods]
impl PyPacket {
    /// The packet tag identifying the type of this packet (e.g. `Tag.Signature`).
    #[getter]
    pub fn tag(&self) -> PyResult<Tag> {
        Ok(self.packet.tag().try_into()?)
    }

    /// The raw body bytes of this packet (without the tag and length header).
    #[getter]
    pub fn body(&self) -> PyResult<Cow<'_, [u8]>> {
        let mut buf = Vec::new();
        Marshal::serialize(&self.packet, &mut buf)?;
        Ok(buf.into())
    }

    /// The fingerprint of a key packet, as a lowercase hex string.
    ///
    /// Returns `None` for non-key packets.
    #[getter]
    pub fn fingerprint(&self) -> Option<String> {
        match &self.packet {
            Packet::PublicKey(k) => Some(format!("{:x}", k.fingerprint())),
            Packet::PublicSubkey(k) => Some(format!("{:x}", k.fingerprint())),
            Packet::SecretKey(k) => Some(format!("{:x}", k.fingerprint())),
            Packet::SecretSubkey(k) => Some(format!("{:x}", k.fingerprint())),
            _ => None,
        }
    }

    /// The short key ID of a key packet, as a lowercase hex string.
    ///
    /// Returns `None` for non-key packets.
    #[getter]
    pub fn key_id(&self) -> Option<String> {
        match &self.packet {
            Packet::PublicKey(k) => Some(format!("{:x}", k.keyid())),
            Packet::PublicSubkey(k) => Some(format!("{:x}", k.keyid())),
            Packet::SecretKey(k) => Some(format!("{:x}", k.keyid())),
            Packet::SecretSubkey(k) => Some(format!("{:x}", k.keyid())),
            _ => None,
        }
    }

    /// The creation time of a key packet.
    ///
    /// Returns `None` for non-key packets.
    #[getter]
    pub fn key_created(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.packet {
            Packet::PublicKey(k) => Some(k.creation_time().into()),
            Packet::PublicSubkey(k) => Some(k.creation_time().into()),
            Packet::SecretKey(k) => Some(k.creation_time().into()),
            Packet::SecretSubkey(k) => Some(k.creation_time().into()),
            _ => None,
        }
    }

    /// The public key algorithm of a key packet.
    ///
    /// Returns `None` for non-key packets.
    #[getter]
    pub fn key_algorithm(&self) -> PyResult<Option<PublicKeyAlgorithm>> {
        match &self.packet {
            Packet::PublicKey(k) => Ok(Some(k.pk_algo().try_into()?)),
            Packet::PublicSubkey(k) => Ok(Some(k.pk_algo().try_into()?)),
            Packet::SecretKey(k) => Ok(Some(k.pk_algo().try_into()?)),
            Packet::SecretSubkey(k) => Ok(Some(k.pk_algo().try_into()?)),
            _ => Ok(None),
        }
    }

    // -- User ID packet accessors --

    /// The User ID string.
    ///
    /// Returns `None` for non-User ID packets.
    #[getter]
    pub fn user_id(&self) -> Option<String> {
        match &self.packet {
            Packet::UserID(uid) => Some(String::from_utf8_lossy(uid.value()).into_owned()),
            _ => None,
        }
    }

    /// The name component of a User ID.
    ///
    /// For example, from `"Alice <alice@example.com>"` this returns `"Alice"`.
    /// Returns `None` for non-User ID packets, or if parsing fails or no name is present.
    #[getter]
    pub fn user_id_name(&self) -> Option<String> {
        match &self.packet {
            Packet::UserID(uid) => uid.name().ok().flatten().map(|s| s.to_string()),
            _ => None,
        }
    }

    /// The email component of a User ID.
    ///
    /// For example, from `"Alice <alice@example.com>"` this returns `"alice@example.com"`.
    /// Returns `None` for non-User ID packets, or if parsing fails or no email is present.
    #[getter]
    pub fn user_id_email(&self) -> Option<String> {
        match &self.packet {
            Packet::UserID(uid) => uid.email().ok().flatten().map(|s| s.to_string()),
            _ => None,
        }
    }

    /// The comment component of a User ID.
    ///
    /// For example, from `"Alice (work) <alice@example.com>"` this returns `"work"`.
    /// Returns `None` for non-User ID packets, or if parsing fails or no comment is present.
    #[getter]
    pub fn user_id_comment(&self) -> Option<String> {
        match &self.packet {
            Packet::UserID(uid) => uid.comment().ok().flatten().map(|s| s.to_string()),
            _ => None,
        }
    }

    // -- Signature packet accessors --

    /// The signature type (e.g. `SignatureType.SubkeyBinding`).
    ///
    /// Returns `None` for non-Signature packets.
    #[getter]
    pub fn signature_type(&self) -> PyResult<Option<SignatureType>> {
        match &self.packet {
            Packet::Signature(sig) => Ok(Some(sig.typ().try_into()?)),
            _ => Ok(None),
        }
    }

    /// The signature creation time.
    ///
    /// Returns `None` for non-Signature packets or if absent.
    #[getter]
    pub fn signature_created(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.packet {
            Packet::Signature(sig) => sig.signature_creation_time().map(Into::into),
            _ => None,
        }
    }

    /// The signature validity period as a timedelta from creation time.
    ///
    /// Returns `None` for non-Signature packets or if the signature does not expire.
    #[getter]
    pub fn signature_validity_period(&self) -> Option<chrono::TimeDelta> {
        match &self.packet {
            Packet::Signature(sig) => sig
                .signature_validity_period()
                .and_then(|d| chrono::TimeDelta::from_std(d).ok()),
            _ => None,
        }
    }

    /// The signature expiration time.
    ///
    /// Returns `None` for non-Signature packets or if the signature does not expire.
    #[getter]
    pub fn signature_expiration_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.packet {
            Packet::Signature(sig) => sig.signature_expiration_time().map(Into::into),
            _ => None,
        }
    }

    /// The key validity period as a timedelta from key creation.
    ///
    /// Returns `None` for non-Signature packets or if not present.
    #[getter]
    pub fn key_validity_period(&self) -> Option<chrono::TimeDelta> {
        match &self.packet {
            Packet::Signature(sig) => sig
                .key_validity_period()
                .and_then(|d| chrono::TimeDelta::from_std(d).ok()),
            _ => None,
        }
    }

    /// The issuer key ID from a signature, as a lowercase hex string.
    ///
    /// Returns `None` for non-Signature packets or if not present.
    #[getter]
    pub fn issuer_key_id(&self) -> Option<String> {
        match &self.packet {
            Packet::Signature(sig) => sig.issuers().next().map(|id| format!("{id:x}")),
            _ => None,
        }
    }

    /// The issuer fingerprint from a signature, as a lowercase hex string.
    ///
    /// Returns `None` for non-Signature packets or if not present.
    #[getter]
    pub fn issuer_fingerprint(&self) -> Option<String> {
        match &self.packet {
            Packet::Signature(sig) => sig
                .issuer_fingerprints()
                .next()
                .map(|fpr| format!("{fpr:x}")),
            _ => None,
        }
    }

    /// The signer's User ID from a signature.
    ///
    /// Returns `None` for non-Signature packets or if not present.
    #[getter]
    pub fn signers_user_id(&self) -> Option<String> {
        match &self.packet {
            Packet::Signature(sig) => sig
                .signers_user_id()
                .map(|uid| String::from_utf8_lossy(uid).into_owned()),
            _ => None,
        }
    }

    /// The hash algorithm used by a signature.
    ///
    /// Returns `None` for non-Signature packets.
    #[getter]
    pub fn hash_algorithm(&self) -> PyResult<Option<HashAlgorithm>> {
        match &self.packet {
            Packet::Signature(sig) => Ok(Some(sig.hash_algo().try_into()?)),
            _ => Ok(None),
        }
    }

    /// The key usage flags from a signature.
    ///
    /// Indicates what operations the key is authorized to perform
    /// (certification, signing, encryption, authentication).
    /// Returns `None` for non-Signature packets or if not present.
    #[getter]
    pub fn key_flags(&self) -> Option<KeyFlags> {
        match &self.packet {
            Packet::Signature(sig) => sig.key_flags().map(Into::into),
            _ => None,
        }
    }

    /// The notation data from a signature, as a list of `Notation` objects.
    ///
    /// Returns `None` for non-Signature packets.
    #[getter]
    pub fn notations(&self) -> Option<Vec<Notation>> {
        match &self.packet {
            Packet::Signature(sig) => {
                let notations = sig.notation_data().map(Notation::from).collect();
                Some(notations)
            }
            _ => None,
        }
    }

    /// Whether the signature marks its User ID as the primary one.
    ///
    /// Returns `None` for non-Signature packets or if the subpacket is absent.
    #[getter]
    pub fn primary_userid(&self) -> Option<bool> {
        match &self.packet {
            Packet::Signature(sig) => sig.primary_userid(),
            _ => None,
        }
    }

    /// Whether the signature is exportable.
    ///
    /// Returns `None` for non-Signature packets or if the subpacket is absent.
    /// Most signatures are exportable by default.
    #[getter]
    pub fn exportable(&self) -> Option<bool> {
        match &self.packet {
            Packet::Signature(sig) => sig.exportable_certification(),
            _ => None,
        }
    }

    // -- One-Pass Signature packet accessors --

    /// The issuer key ID from a One-Pass Signature packet, as a lowercase hex string.
    ///
    /// Returns `None` for non-One-Pass Signature packets.
    #[getter]
    pub fn ops_issuer(&self) -> Option<String> {
        match &self.packet {
            Packet::OnePassSig(ops) => Some(format!("{:x}", ops.issuer())),
            _ => None,
        }
    }

    /// The signature type from a One-Pass Signature packet.
    ///
    /// Returns `None` for non-One-Pass Signature packets.
    #[getter]
    pub fn ops_signature_type(&self) -> PyResult<Option<SignatureType>> {
        match &self.packet {
            Packet::OnePassSig(ops) => Ok(Some(ops.typ().try_into()?)),
            _ => Ok(None),
        }
    }

    // -- Literal Data packet accessors --

    /// The payload content of a Literal Data packet (without format/filename/date header).
    ///
    /// Returns `None` for non-Literal Data packets.
    #[getter]
    pub fn literal_data(&self) -> Option<Cow<'_, [u8]>> {
        match &self.packet {
            Packet::Literal(lit) => Some(Cow::Borrowed(lit.body())),
            _ => None,
        }
    }

    /// The filename hint from a Literal Data packet.
    ///
    /// Returns `None` for non-Literal Data packets or if no filename is set.
    #[getter]
    pub fn literal_filename(&self) -> Option<String> {
        match &self.packet {
            Packet::Literal(lit) => lit
                .filename()
                .map(|f| String::from_utf8_lossy(f).into_owned()),
            _ => None,
        }
    }

    /// The date embedded in a Literal Data packet.
    ///
    /// Returns `None` for non-Literal Data packets or if no date is set.
    #[getter]
    pub fn literal_date(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.packet {
            Packet::Literal(lit) => lit.date().map(Into::into),
            _ => None,
        }
    }

    /// The data format of a Literal Data packet (Binary, Unicode, or Text).
    ///
    /// Returns `None` for non-Literal Data packets.
    #[getter]
    pub fn literal_format(&self) -> PyResult<Option<DataFormat>> {
        match &self.packet {
            Packet::Literal(lit) => Ok(Some(lit.format().try_into()?)),
            _ => Ok(None),
        }
    }

    pub fn __repr__(&self) -> String {
        match Tag::try_from(self.packet.tag()) {
            Ok(tag) => format!("<Packet tag=Tag.{tag:?}>"),
            Err(_) => format!("<Packet tag=Unknown({})>", u8::from(self.packet.tag())),
        }
    }
}
