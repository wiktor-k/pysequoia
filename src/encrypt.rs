use std::borrow::Cow;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use pyo3::prelude::*;
use sequoia_openpgp::cert::Preferences;
use sequoia_openpgp::cert::amalgamation::ValidAmalgamation;
use sequoia_openpgp::serialize::stream::Recipient;
use sequoia_openpgp::serialize::stream::{Armorer, Signer};
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use sequoia_openpgp::types::KeyFlags;

use crate::cert::Cert;
use crate::signer::PySigner;

type RecipientKey = (
    Option<sequoia_openpgp::types::Features>,
    sequoia_openpgp::packet::Key<
        sequoia_openpgp::packet::key::PublicParts,
        sequoia_openpgp::packet::key::UnspecifiedRole,
    >,
);

fn resolve_recipient_keys(recipients: &[PyRef<Cert>]) -> PyResult<Vec<RecipientKey>> {
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
    Ok(recipient_keys)
}

#[pyfunction]
#[pyo3(signature = (bytes, recipients=vec![], signer=None, passwords=vec![], *, armor=true))]
pub fn encrypt(
    bytes: &[u8],
    recipients: Vec<PyRef<Cert>>,
    signer: Option<PySigner>,
    passwords: Vec<String>,
    armor: bool,
) -> PyResult<Cow<'static, [u8]>> {
    if recipients.is_empty() && passwords.is_empty() {
        return Err(anyhow::anyhow!(
            "Either `recipients` or `passwords` parameter should be given and non-empty."
        )
        .into());
    }

    let recipient_keys = resolve_recipient_keys(&recipients)?;

    let mut sink = vec![];

    let message = Message::new(&mut sink);

    let message = if armor {
        Armorer::new(message).build()?
    } else {
        message
    };

    let encryptor = Encryptor::for_recipients(
        message,
        recipient_keys
            .iter()
            .map(|(features, key)| Recipient::new(features.clone(), key.key_handle(), key)),
    )
    .add_passwords(passwords);

    let mut message = encryptor.build().context("Failed to create encryptor")?;

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

#[pyfunction]
#[pyo3(signature = (input, output, recipients=vec![], signer=None, passwords=vec![], *, armor=true))]
pub fn encrypt_file(
    input: PathBuf,
    output: PathBuf,
    recipients: Vec<PyRef<Cert>>,
    signer: Option<PySigner>,
    passwords: Vec<String>,
    armor: bool,
) -> PyResult<()> {
    if recipients.is_empty() && passwords.is_empty() {
        return Err(anyhow::anyhow!(
            "Either `recipients` or `passwords` parameter should be given and non-empty."
        )
        .into());
    }
    let recipient_keys = resolve_recipient_keys(&recipients)?;

    let mut sink = File::create(&output).context("Failed to create output file")?;

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
    .add_passwords(passwords)
    .build()
    .context("Failed to create encryptor")?;

    if let Some(signer) = signer {
        message = Signer::new(message, signer)?.build()?;
    }
    let mut message = LiteralWriter::new(message)
        .build()
        .context("Failed to create literal writer")?;

    let mut input_file = File::open(&input).context("Failed to open input file")?;
    std::io::copy(&mut input_file, &mut message)?;

    message.finalize()?;

    Ok(())
}
