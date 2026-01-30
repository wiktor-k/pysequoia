use std::borrow::Cow;
use std::io::Write;

use anyhow::Context;
use pyo3::prelude::*;
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::cert::Preferences;
use sequoia_openpgp::serialize::stream::Recipient;
use sequoia_openpgp::serialize::stream::{Armorer, Signer};
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use sequoia_openpgp::types::KeyFlags;

use crate::cert::Cert;
use crate::signer::PySigner;

#[pyfunction]
#[pyo3(signature = (recipients, bytes, signer=None, *, armor=true))]
pub fn encrypt(
    recipients: Vec<PyRef<Cert>>,
    bytes: &[u8],
    signer: Option<PySigner>,
    armor: bool,
) -> PyResult<Cow<'static, [u8]>> {
    let mode = KeyFlags::empty()
        .set_storage_encryption()
        .set_transport_encryption();

    let mut recipient_keys = vec![];
    for cert in recipients.iter() {
        let mut found_one = false;
        let policy = cert.policy();

        for key in cert
            .cert()
            .keys()
            .with_policy(&**policy, None)
            .supported()
            .alive()
            .revoked(false)
            .key_flags(&mode)
        {
            recipient_keys.push((key.valid_cert().features(), key.key().clone()));
            found_one = true;
        }

        if !found_one {
            for key in cert
                .cert()
                .keys()
                .with_policy(&**policy, None)
                .supported()
                .revoked(false)
                .key_flags(&mode)
            {
                recipient_keys.push((key.valid_cert().features().clone(), key.key().clone()));
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

    let message = if armor {
        Armorer::new(message).build()?
    } else {
        message
    };

    let mut message = Encryptor::for_recipients(
        message,
        recipient_keys
            .iter()
            .map(|(features, key)| Recipient::new(features.clone(), key.key_handle(), key)),
    )
    .build()
    .context("Failed to create encryptor")?;

    if let Some(signer) = signer {
        message = Signer::new(message, signer)?.build()?;
    }
    let mut message = LiteralWriter::new(message)
        .build()
        .context("Failed to create literal writer")?;

    message.write_all(bytes.as_ref())?;

    message.finalize()?;

    Ok(sink.into())
}
