#![allow(deprecated)]

use anyhow::anyhow;
use pyo3::prelude::*;
use sequoia_openpgp::packet::Tag as SqTag;
use sequoia_openpgp::types::{
    DataFormat as SqDataFormat, HashAlgorithm as SqHashAlgorithm, KeyFlags as SqKeyFlags,
    PublicKeyAlgorithm as SqPublicKeyAlgorithm, SignatureType as SqSignatureType,
};

/// The type of an OpenPGP signature, as defined in RFC 4880 / 9580.
#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignatureType {
    /// Signature over a binary document
    Binary,
    /// Signature over a canonical text document
    Text,
    /// Standalone signature
    Standalone,
    /// Generic certification of a User ID and Public-Key packet
    GenericCertification,
    /// Persona certification of a User ID and Public-Key packet
    PersonaCertification,
    /// Casual certification of a User ID and Public-Key packet
    CasualCertification,
    /// Positive certification of a User ID and Public-Key packet
    PositiveCertification,
    /// Certification Approval Key Signature (experimental)
    CertificationApproval,
    /// Subkey Binding Signature
    SubkeyBinding,
    /// Primary Key Binding Signature
    PrimaryKeyBinding,
    /// Signature directly on a key
    DirectKey,
    /// Key revocation signature
    KeyRevocation,
    /// Subkey revocation signature
    SubkeyRevocation,
    /// Certification revocation signature
    CertificationRevocation,
    /// Timestamp signature
    Timestamp,
    /// Third-Party Confirmation signature
    Confirmation,
}

impl TryFrom<SqSignatureType> for SignatureType {
    type Error = anyhow::Error;

    fn try_from(st: SqSignatureType) -> Result<Self, Self::Error> {
        match st {
            SqSignatureType::Binary => Ok(Self::Binary),
            SqSignatureType::Text => Ok(Self::Text),
            SqSignatureType::Standalone => Ok(Self::Standalone),
            SqSignatureType::GenericCertification => Ok(Self::GenericCertification),
            SqSignatureType::PersonaCertification => Ok(Self::PersonaCertification),
            SqSignatureType::CasualCertification => Ok(Self::CasualCertification),
            SqSignatureType::PositiveCertification => Ok(Self::PositiveCertification),
            SqSignatureType::CertificationApproval => Ok(Self::CertificationApproval),
            SqSignatureType::SubkeyBinding => Ok(Self::SubkeyBinding),
            SqSignatureType::PrimaryKeyBinding => Ok(Self::PrimaryKeyBinding),
            SqSignatureType::DirectKey => Ok(Self::DirectKey),
            SqSignatureType::KeyRevocation => Ok(Self::KeyRevocation),
            SqSignatureType::SubkeyRevocation => Ok(Self::SubkeyRevocation),
            SqSignatureType::CertificationRevocation => Ok(Self::CertificationRevocation),
            SqSignatureType::Timestamp => Ok(Self::Timestamp),
            SqSignatureType::Confirmation => Ok(Self::Confirmation),
            SqSignatureType::Unknown(u) => Err(anyhow!("Unknown signature type: {u:#x}")),
            _ => Err(anyhow!("Unrecognized signature type: {:#x}", u8::from(st))),
        }
    }
}

/// The public key algorithm used by an OpenPGP key.
#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyAlgorithm {
    /// RSA (Encrypt or Sign)
    RSAEncryptSign,
    /// RSA Encrypt-Only, deprecated
    RSAEncrypt,
    /// RSA Sign-Only, deprecated
    RSASign,
    /// ElGamal Encrypt-Only, deprecated
    ElGamalEncrypt,
    /// DSA
    DSA,
    /// Elliptic Curve Diffie-Hellman
    ECDH,
    /// Elliptic Curve DSA
    ECDSA,
    /// ElGamal Encrypt or Sign, deprecated
    ElGamalEncryptSign,
    /// "Twisted" Edwards Curve DSA
    EdDSA,
    /// X25519
    X25519,
    /// X448
    X448,
    /// Ed25519
    Ed25519,
    /// Ed448
    Ed448,
}

impl TryFrom<SqPublicKeyAlgorithm> for PublicKeyAlgorithm {
    type Error = anyhow::Error;

    fn try_from(algo: SqPublicKeyAlgorithm) -> Result<Self, Self::Error> {
        match algo {
            SqPublicKeyAlgorithm::RSAEncryptSign => Ok(Self::RSAEncryptSign),
            SqPublicKeyAlgorithm::RSAEncrypt => Ok(Self::RSAEncrypt),
            SqPublicKeyAlgorithm::RSASign => Ok(Self::RSASign),
            SqPublicKeyAlgorithm::ElGamalEncrypt => Ok(Self::ElGamalEncrypt),
            SqPublicKeyAlgorithm::DSA => Ok(Self::DSA),
            SqPublicKeyAlgorithm::ECDH => Ok(Self::ECDH),
            SqPublicKeyAlgorithm::ECDSA => Ok(Self::ECDSA),
            SqPublicKeyAlgorithm::ElGamalEncryptSign => Ok(Self::ElGamalEncryptSign),
            SqPublicKeyAlgorithm::EdDSA => Ok(Self::EdDSA),
            SqPublicKeyAlgorithm::X25519 => Ok(Self::X25519),
            SqPublicKeyAlgorithm::X448 => Ok(Self::X448),
            SqPublicKeyAlgorithm::Ed25519 => Ok(Self::Ed25519),
            SqPublicKeyAlgorithm::Ed448 => Ok(Self::Ed448),
            SqPublicKeyAlgorithm::Private(u) => Err(anyhow!("Private public key algorithm: {u}")),
            SqPublicKeyAlgorithm::Unknown(u) => Err(anyhow!("Unknown public key algorithm: {u}")),
            _ => Err(anyhow!(
                "Unrecognized public key algorithm: {}",
                u8::from(algo)
            )),
        }
    }
}

/// The hash algorithm used by an OpenPGP signature.
#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// MD5
    MD5,
    /// SHA-1
    SHA1,
    /// RIPEMD-160
    RipeMD,
    /// SHA-256
    SHA256,
    /// SHA-384
    SHA384,
    /// SHA-512
    SHA512,
    /// SHA-224
    SHA224,
    /// SHA3-256
    SHA3_256,
    /// SHA3-512
    SHA3_512,
}

impl TryFrom<SqHashAlgorithm> for HashAlgorithm {
    type Error = anyhow::Error;

    fn try_from(algo: SqHashAlgorithm) -> Result<Self, Self::Error> {
        match algo {
            SqHashAlgorithm::MD5 => Ok(Self::MD5),
            SqHashAlgorithm::SHA1 => Ok(Self::SHA1),
            SqHashAlgorithm::RipeMD => Ok(Self::RipeMD),
            SqHashAlgorithm::SHA256 => Ok(Self::SHA256),
            SqHashAlgorithm::SHA384 => Ok(Self::SHA384),
            SqHashAlgorithm::SHA512 => Ok(Self::SHA512),
            SqHashAlgorithm::SHA224 => Ok(Self::SHA224),
            SqHashAlgorithm::SHA3_256 => Ok(Self::SHA3_256),
            SqHashAlgorithm::SHA3_512 => Ok(Self::SHA3_512),
            SqHashAlgorithm::Private(u) => Err(anyhow!("Private hash algorithm: {u}")),
            SqHashAlgorithm::Unknown(u) => Err(anyhow!("Unknown hash algorithm: {u}")),
            _ => Err(anyhow!("Unrecognized hash algorithm: {}", u8::from(algo))),
        }
    }
}

/// The data format of a Literal Data packet.
#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataFormat {
    /// Binary data
    Binary,
    /// UTF-8 text data
    Unicode,
    /// Text data, encoding unspecified. Deprecated.
    Text,
}

impl TryFrom<SqDataFormat> for DataFormat {
    type Error = anyhow::Error;

    #[allow(deprecated)]
    fn try_from(fmt: SqDataFormat) -> Result<Self, Self::Error> {
        match fmt {
            SqDataFormat::Binary => Ok(Self::Binary),
            SqDataFormat::Unicode => Ok(Self::Unicode),
            SqDataFormat::Text => Ok(Self::Text),
            SqDataFormat::Unknown(u) => Err(anyhow!("Unknown data format: {u:#x}")),
            _ => Err(anyhow!("Unrecognized data format: {:#x}", u8::from(fmt))),
        }
    }
}

/// The OpenPGP packet tag, identifying the type of a packet.
#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    /// Reserved
    Reserved,
    /// Public-Key Encrypted Session Key Packet
    PKESK,
    /// Signature Packet
    Signature,
    /// Symmetric-Key Encrypted Session Key Packet
    SKESK,
    /// One-Pass Signature Packet
    OnePassSig,
    /// Secret-Key Packet
    SecretKey,
    /// Public-Key Packet
    PublicKey,
    /// Secret-Subkey Packet
    SecretSubkey,
    /// Compressed Data Packet
    CompressedData,
    /// Symmetrically Encrypted Data Packet
    SED,
    /// Marker Packet
    Marker,
    /// Literal Data Packet
    Literal,
    /// Trust Packet
    Trust,
    /// User ID Packet
    UserID,
    /// Public-Subkey Packet
    PublicSubkey,
    /// User Attribute Packet
    UserAttribute,
    /// Symmetrically Encrypted and Integrity Protected Data Packet
    SEIP,
    /// Modification Detection Code Packet
    MDC,
    /// AEAD Encrypted Data Packet
    AED,
    /// Padding Packet
    Padding,
}

impl TryFrom<SqTag> for Tag {
    type Error = anyhow::Error;

    fn try_from(tag: SqTag) -> Result<Self, Self::Error> {
        match tag {
            SqTag::Reserved => Ok(Self::Reserved),
            SqTag::PKESK => Ok(Self::PKESK),
            SqTag::Signature => Ok(Self::Signature),
            SqTag::SKESK => Ok(Self::SKESK),
            SqTag::OnePassSig => Ok(Self::OnePassSig),
            SqTag::SecretKey => Ok(Self::SecretKey),
            SqTag::PublicKey => Ok(Self::PublicKey),
            SqTag::SecretSubkey => Ok(Self::SecretSubkey),
            SqTag::CompressedData => Ok(Self::CompressedData),
            SqTag::SED => Ok(Self::SED),
            SqTag::Marker => Ok(Self::Marker),
            SqTag::Literal => Ok(Self::Literal),
            SqTag::Trust => Ok(Self::Trust),
            SqTag::UserID => Ok(Self::UserID),
            SqTag::PublicSubkey => Ok(Self::PublicSubkey),
            SqTag::UserAttribute => Ok(Self::UserAttribute),
            SqTag::SEIP => Ok(Self::SEIP),
            SqTag::MDC => Ok(Self::MDC),
            SqTag::AED => Ok(Self::AED),
            SqTag::Padding => Ok(Self::Padding),
            SqTag::Private(u) => Err(anyhow!("Private packet tag: {u}")),
            SqTag::Unknown(u) => Err(anyhow!("Unknown packet tag: {u}")),
            _ => Err(anyhow!("Unrecognized packet tag: {}", u8::from(tag))),
        }
    }
}

/// The key usage flags from an OpenPGP signature.
///
/// Indicates what operations a key is authorized to perform.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct KeyFlags {
    flags: SqKeyFlags,
}

impl From<SqKeyFlags> for KeyFlags {
    fn from(flags: SqKeyFlags) -> Self {
        Self { flags }
    }
}

#[pymethods]
impl KeyFlags {
    /// Whether the key may be used to certify other keys.
    #[getter]
    pub fn certification(&self) -> bool {
        self.flags.for_certification()
    }

    /// Whether the key may be used to sign data.
    #[getter]
    pub fn signing(&self) -> bool {
        self.flags.for_signing()
    }

    /// Whether the key may be used to encrypt communications.
    #[getter]
    pub fn transport_encryption(&self) -> bool {
        self.flags.for_transport_encryption()
    }

    /// Whether the key may be used to encrypt storage.
    #[getter]
    pub fn storage_encryption(&self) -> bool {
        self.flags.for_storage_encryption()
    }

    /// Whether the key may be used for authentication.
    #[getter]
    pub fn authentication(&self) -> bool {
        self.flags.for_authentication()
    }

    pub fn __repr__(&self) -> String {
        let mut parts = vec![];
        if self.certification() {
            parts.push("certification");
        }
        if self.signing() {
            parts.push("signing");
        }
        if self.transport_encryption() {
            parts.push("transport_encryption");
        }
        if self.storage_encryption() {
            parts.push("storage_encryption");
        }
        if self.authentication() {
            parts.push("authentication");
        }
        format!("<KeyFlags {}>", parts.join(", "))
    }
}
