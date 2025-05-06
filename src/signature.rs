use std::borrow::Cow;

use anyhow::anyhow;
use pyo3::prelude::*;
use sequoia_openpgp::{
    armor,
    packet::Signature as SqSignature,
    parse::{PacketParser, PacketParserResult, Parse as _},
    Packet,
};

#[pyclass]
pub struct Sig {
    sig: SqSignature,
}

impl Sig {
    pub fn new(sig: SqSignature) -> Self {
        Self { sig }
    }

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
    #[staticmethod]
    pub fn from_file(path: String) -> PyResult<Self> {
        Ok(Self::from_packets(PacketParser::from_file(path)?)?)
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        Ok(Self::from_packets(PacketParser::from_bytes(bytes)?)?)
    }

    pub fn __bytes__(&self) -> PyResult<Cow<[u8]>> {
        Ok(crate::serialize(self.sig.clone().into(), None)?.into())
    }

    #[getter]
    pub fn issuer_fpr(&self) -> Option<String> {
        self.sig
            .issuer_fingerprints()
            .next()
            .map(|issuer| format!("{issuer:x}"))
    }

    #[getter]
    pub fn created(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.sig.signature_creation_time().map(Into::into)
    }

    pub fn __str__(&self) -> PyResult<String> {
        let bytes = crate::serialize(self.sig.clone().into(), armor::Kind::Signature)?;
        Ok(String::from_utf8(bytes)?)
    }

    pub fn __repr__(&self) -> String {
        format!("<Sig issuer_fpr={}>", self.issuer_fpr().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reading_sig() {
        Sig::from_packets(PacketParser::from_file("sig.pgp").unwrap()).unwrap();
    }
}
