use std::borrow::Cow;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use pyo3::prelude::*;
use sequoia_openpgp::armor;
use sequoia_openpgp::serialize::stream::Armorer;
use sequoia_openpgp::serialize::stream::{LiteralWriter, Message};

use crate::signer::PySigner;

/// The mode of signature to produce.
#[pyclass(eq, eq_int)]
#[derive(PartialEq)]
pub enum SignatureMode {
    #[pyo3(name = "INLINE")]
    Inline,
    #[pyo3(name = "DETACHED")]
    Detached,
    #[pyo3(name = "CLEAR")]
    Clear,
}

/// Sign data with the given signer.
///
/// The `mode` controls whether the signature is inline (the default), detached, or cleartext.
/// Set `armor=False` to produce binary output instead of ASCII-armored.
#[pyfunction]
#[pyo3(signature = (signer, bytes, *, mode=&SignatureMode::Inline, armor=true))]
pub fn sign(
    signer: PySigner,
    bytes: &[u8],
    mode: &SignatureMode,
    armor: bool,
) -> PyResult<Cow<'static, [u8]>> {
    use sequoia_openpgp::serialize::stream::Signer;

    let mut sink = vec![];
    {
        let message = Message::new(&mut sink);
        let message = if mode == &SignatureMode::Inline && armor {
            Armorer::new(message).kind(armor::Kind::Message).build()?
        } else if mode == &SignatureMode::Detached && armor {
            Armorer::new(message).kind(armor::Kind::Signature).build()?
        } else {
            message
        };
        let message = Signer::new(message, signer)?;
        let mut message = if mode == &SignatureMode::Inline {
            LiteralWriter::new(message.build()?).build()?
        } else if mode == &SignatureMode::Detached {
            message.detached().build()?
        } else {
            message.cleartext().build()?
        };
        message.write_all(bytes)?;
        message.finalize()?;
    }

    Ok(sink.into())
}

/// Sign a file with the given signer, writing the result to an output file.
///
/// The `mode` controls whether the signature is inline (the default), detached, or cleartext.
/// Set `armor=False` to produce binary output instead of ASCII-armored.
#[pyfunction]
#[pyo3(signature = (signer, input, output, *, mode=&SignatureMode::Inline, armor=true))]
pub fn sign_file(
    signer: PySigner,
    input: PathBuf,
    output: PathBuf,
    mode: &SignatureMode,
    armor: bool,
) -> PyResult<()> {
    use sequoia_openpgp::serialize::stream::Signer;

    let mut sink = std::fs::File::create(&output).context("Failed to create output file")?;
    {
        let message = Message::new(&mut sink);
        let message = if mode == &SignatureMode::Inline && armor {
            Armorer::new(message).kind(armor::Kind::Message).build()?
        } else if mode == &SignatureMode::Detached && armor {
            Armorer::new(message).kind(armor::Kind::Signature).build()?
        } else {
            message
        };
        let message = Signer::new(message, signer)?;
        let mut message = if mode == &SignatureMode::Inline {
            LiteralWriter::new(message.build()?).build()?
        } else if mode == &SignatureMode::Detached {
            message.detached().build()?
        } else {
            message.cleartext().build()?
        };
        let mut input_file = std::fs::File::open(&input).context("Failed to open input file")?;
        std::io::copy(&mut input_file, &mut message)?;
        message.finalize()?;
    }

    Ok(())
}
