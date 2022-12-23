use pyo3::prelude::*;

/// Formats the sum of two numbers as string.
#[pyfunction]
fn encrypt(signing_cert: String, recipient_certs: String, content: String) -> PyResult<String> {
    //Ok((a + b).to_string())
    let policy = Box::new(openpgp::policy::StandardPolicy::new());
    encrypt_for(signing_cert, recipient_certs, content, policy).map_err(|e| e.into())
}

#[pyfunction]
fn merge(existing_cert: String, new_cert: String) -> PyResult<String> {
    Ok(merge_certs(existing_cert, new_cert)?)
}

#[pyfunction]
fn minimize(cert: String) -> PyResult<String> {
    Ok(minimize_cert(cert, Box::new(StandardPolicy::new()))?)
}

/// A Python module implemented in Rust.
#[pymodule]
fn pysequoia(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(merge, m)?)?;
    m.add_function(wrap_pyfunction!(minimize, m)?)?;
    Ok(())
}

use sequoia_openpgp as openpgp;

use openpgp::parse::Parse;
use openpgp::policy::{Policy, StandardPolicy};
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::KeyFlags;
use openpgp::{
    serialize::{
        stream::{Armorer, Signer},
        SerializeInto,
    },
    Cert,
};

use anyhow::Context;

use std::io::Write;

pub fn encrypt_for<S, T, U>(
    signing_cert: S,
    recipient_certs: T,
    content: U,
    policy: Box<dyn Policy>,
) -> openpgp::Result<String>
where
    S: AsRef<[u8]> + Send + Sync,
    T: AsRef<[u8]> + Send + Sync,
    U: AsRef<[u8]> + Send + Sync,
{
    let mode = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let signing_cert = Cert::from_bytes(&signing_cert)?
        .keys()
        .unencrypted_secret()
        .with_policy(&*policy, None)
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .unwrap()
        .key()
        .clone()
        .into_keypair()?;

    let parser = openpgp::cert::CertParser::from_bytes(&recipient_certs)?;
    let certs = parser
        .into_iter()
        .filter_map(|c| c.ok())
        .collect::<Vec<_>>();

    let mut recipients = Vec::new();
    for cert in certs.iter() {
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

pub fn merge_certs<S, T>(existing_cert: S, new_cert: T) -> openpgp::Result<String>
where
    S: AsRef<[u8]> + Send + Sync,
    T: AsRef<[u8]> + Send + Sync,
{
    let existing_cert = Cert::from_bytes(&existing_cert)?;
    let new_cert = Cert::from_bytes(&new_cert)?;

    let merged_cert = existing_cert.merge_public(new_cert)?;

    let armored = merged_cert.armored();
    Ok(String::from_utf8(armored.to_vec()?)?)
}

pub fn minimize_cert<S>(cert: S, policy: Box<dyn Policy>) -> openpgp::Result<String>
where
    S: AsRef<[u8]> + Sync + Send,
{
    let cert = Cert::from_bytes(&cert)?;
    let cert = cert.with_policy(&*policy, None)?;

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

    let armored = Cert::try_from(acc)?;
    let armored = armored.armored();
    Ok(String::from_utf8(armored.to_vec()?)?)
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
