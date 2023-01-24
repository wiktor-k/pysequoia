use pyo3::prelude::*;

use anyhow::Context as AnyhowContext;

use std::io::Write;

use sequoia_openpgp as openpgp;

use openpgp::policy::{Policy, StandardPolicy};
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::serialize::{
    stream::{Armorer, Signer},
    SerializeInto,
};
use openpgp::types::KeyFlags;

#[pyclass]
pub struct Cert {
    cert: openpgp::cert::Cert,
}

#[pymethods]
impl Cert {
    #[staticmethod]
    pub fn from_file(path: String) -> PyResult<Self> {
        use openpgp::parse::Parse;
        Ok(Self {
            cert: openpgp::cert::Cert::from_file(path)?,
        })
    }

    #[staticmethod]
    pub fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        use openpgp::parse::Parse;
        Ok(Self {
            cert: openpgp::cert::Cert::from_bytes(bytes)?,
        })
    }

    pub fn merge(&self, new_cert: &Cert) -> PyResult<Cert> {
        Ok(merge_certs(self, new_cert)?)
    }

    pub fn __str__(&self) -> PyResult<String> {
        let armored = self.cert.armored();
        Ok(String::from_utf8(armored.to_vec()?)?)
    }
}

#[pyclass]
struct Context {
    policy: Box<dyn Policy + 'static>,
}

#[pymethods]
impl Context {
    #[staticmethod]
    pub fn standard() -> Self {
        Self {
            policy: Box::new(StandardPolicy::new()),
        }
    }

    fn encrypt(
        &self,
        signing_cert: &Cert,
        recipient_certs: &Cert,
        content: String,
    ) -> PyResult<String> {
        encrypt_for(signing_cert, recipient_certs, content, &*self.policy).map_err(|e| e.into())
    }

    fn minimize(&self, cert: &Cert) -> PyResult<Cert> {
        Ok(minimize_cert(cert, &*self.policy)?)
    }
}

#[pymodule]
fn pysequoia(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Cert>()?;
    m.add_class::<Context>()?;
    Ok(())
}

pub fn encrypt_for<U>(
    signing_cert: &Cert,
    recipient_certs: &Cert,
    content: U,
    policy: &dyn Policy,
) -> openpgp::Result<String>
where
    U: AsRef<[u8]> + Send + Sync,
{
    let mode = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let signing_cert = signing_cert
        .cert
        .keys()
        .unencrypted_secret()
        .with_policy(policy, None)
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .unwrap()
        .key()
        .clone()
        .into_keypair()?;

    let mut recipients = vec![];
    for cert in vec![&recipient_certs.cert].iter() {
        let mut found_one = false;
        for key in cert
            .keys()
            .with_policy(&*policy, None)
            .supported()
            .alive()
            .revoked(false)
            .key_flags(&mode)
        {
            recipients.push(key);
            found_one = true;
        }

        if !found_one {
            for key in cert
                .keys()
                .with_policy(&*policy, None)
                .supported()
                .revoked(false)
                .key_flags(&mode)
            {
                recipients.push(key);
                found_one = true;
            }
        }

        if !found_one {
            return Err(anyhow::anyhow!(
                "No suitable encryption subkey for {}",
                cert
            ));
        }
    }

    let mut sink = vec![];

    let message = Message::new(&mut sink);

    let message = Armorer::new(message).build()?;

    let message = Encryptor::for_recipients(message, recipients)
        .build()
        .context("Failed to create encryptor")?;

    let message = Signer::new(message, signing_cert).build()?;

    let mut message = LiteralWriter::new(message)
        .build()
        .context("Failed to create literal writer")?;

    message.write_all(content.as_ref())?;

    message.finalize()?;

    Ok(String::from_utf8(sink)?)
}

pub fn merge_certs(existing_cert: &Cert, new_cert: &Cert) -> openpgp::Result<Cert> {
    let merged_cert = existing_cert
        .cert
        .clone()
        .merge_public(new_cert.cert.clone())?;
    Ok(Cert { cert: merged_cert })
}

pub fn minimize_cert(cert: &Cert, policy: &dyn Policy) -> openpgp::Result<Cert> {
    let cert = cert.cert.with_policy(&*policy, None)?;

    let mut acc = Vec::new();

    let c = cert.primary_key();
    acc.push(c.key().clone().into());

    for s in c.self_signatures() {
        acc.push(s.clone().into())
    }
    for s in c.self_revocations() {
        acc.push(s.clone().into())
    }

    for c in cert.userids() {
        acc.push(c.userid().clone().into());
        for s in c.self_signatures().take(1) {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
    }

    let flags = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let mut encryption_keys = cert
        .keys()
        .subkeys()
        .key_flags(&flags)
        .alive()
        .revoked(false)
        .collect::<Vec<_>>();

    if encryption_keys.is_empty() {
        encryption_keys = cert
            .keys()
            .subkeys()
            .key_flags(&flags)
            .revoked(false)
            .collect::<Vec<_>>();
    }

    for c in encryption_keys {
        acc.push(c.key().clone().into());
        for s in c.self_signatures().take(1) {
            acc.push(s.clone().into())
        }
        for s in c.self_revocations() {
            acc.push(s.clone().into())
        }
    }

    Ok(Cert {
        cert: openpgp::cert::Cert::try_from(acc)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openpgp::cert::prelude::*;
    use sequoia_openpgp as openpgp;
    use testresult::TestResult;

    #[test]
    fn test_armoring() -> TestResult {
        let cert = CertBuilder::general_purpose(None, Some("test@example.com"))
            .generate()
            .unwrap()
            .0;
        assert!(cert.armored().to_vec().is_ok());
        Ok(())
    }
}
