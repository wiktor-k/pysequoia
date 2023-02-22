use std::io::Write;

use anyhow::Context;
use openpgp::policy::Policy;
use openpgp::serialize::stream::{Armorer, Signer};
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::KeyFlags;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::cert::Cert;
use crate::signer::PySigner;

#[pyfunction]
pub fn sign(signer: PySigner, data: String) -> PyResult<String> {
    use openpgp::serialize::stream::Signer;

    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);

        let message = Armorer::new(message)
            .kind(openpgp::armor::Kind::Signature)
            .build()?;
        let message = Signer::new(message, signer).build()?;

        let mut message = LiteralWriter::new(message).build()?;

        message.write_all(data.as_bytes())?;

        message.finalize()?;
    }

    Ok(String::from_utf8_lossy(&sink).into())
}

#[pyfunction]
pub fn minimize(cert: &Cert) -> PyResult<Cert> {
    Ok(minimize_cert(cert, cert.policy())?)
}

pub fn minimize_cert(cert: &Cert, policy: &dyn Policy) -> openpgp::Result<Cert> {
    let cert = cert.cert().with_policy(policy, None)?;

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

    Ok(openpgp::cert::Cert::try_from(acc)?.into())
}

#[pyfunction]
pub fn encrypt(
    signer: PySigner,
    recipients: Vec<PyRef<Cert>>,
    content: String,
) -> PyResult<String> {
    let mode = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let mut recipient_keys = vec![];
    for cert in recipients.iter() {
        let mut found_one = false;
        for key in cert
            .cert()
            .keys()
            .with_policy(cert.policy(), None)
            .supported()
            .alive()
            .revoked(false)
            .key_flags(&mode)
        {
            recipient_keys.push(key);
            found_one = true;
        }

        if !found_one {
            for key in cert
                .cert()
                .keys()
                .with_policy(cert.policy(), None)
                .supported()
                .revoked(false)
                .key_flags(&mode)
            {
                recipient_keys.push(key);
                found_one = true;
            }
        }

        if !found_one {
            return Err(
                anyhow::anyhow!("No suitable encryption subkey for {}", cert.cert()).into(),
            );
        }
    }

    let mut sink = vec![];

    let message = Message::new(&mut sink);

    let message = Armorer::new(message).build()?;

    let message = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .context("Failed to create encryptor")?;

    let message = Signer::new(message, signer).build()?;

    let mut message = LiteralWriter::new(message)
        .build()
        .context("Failed to create literal writer")?;

    message.write_all(content.as_ref())?;

    message.finalize()?;

    Ok(String::from_utf8(sink)?)
}
