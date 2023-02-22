use std::path::PathBuf;

use openpgp::serialize::SerializeInto;
use openpgp_cert_d::CertD;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::cert::Cert;

#[pyclass]
pub struct Store {
    cert_d: CertD,
    loc: PathBuf,
}

#[pymethods]
impl Store {
    #[new]
    pub fn new(loc: PathBuf) -> anyhow::Result<Self> {
        Ok(Self {
            cert_d: CertD::with_base_dir(&loc)?,
            loc,
        })
    }

    pub fn get(&self, id: String) -> anyhow::Result<Option<Cert>> {
        use openpgp::parse::Parse;
        if let Some((_tag, data)) = self.cert_d.get(&id)? {
            Ok(Some(openpgp::cert::Cert::from_bytes(&data)?.into()))
        } else {
            Ok(None)
        }
    }

    pub fn put(&mut self, cert: &Cert) -> anyhow::Result<Cert> {
        use openpgp::parse::Parse;
        use openpgp_cert_d::Data;
        let f = |new: Data, old: Option<Data>| {
            let merged = match old {
                Some(old) => {
                    let old = openpgp::cert::Cert::from_bytes(&old)?;
                    let new = openpgp::cert::Cert::from_bytes(&new)?;
                    old.merge_public(new)?.to_vec()?.into_boxed_slice()
                }
                None => new,
            };
            Ok(merged)
        };
        let (_tag, data) = self
            .cert_d
            .insert(cert.cert().to_vec()?.into_boxed_slice(), f)?;
        Ok(openpgp::cert::Cert::from_bytes(&data)?.into())
    }

    pub fn __repr__(&self) -> String {
        format!("<Store base={}>", self.loc.display())
    }
}
