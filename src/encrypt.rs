use std::io::Write;

use anyhow::Context;
use openpgp::serialize::stream::{Armorer, Signer};
use openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use openpgp::types::KeyFlags;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::cert::Cert;
use crate::signer::PySigner;

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
