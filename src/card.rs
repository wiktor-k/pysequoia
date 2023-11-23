use card_backend_pcsc::PcscBackend;
use openpgp_card_sequoia::state::Open;
use openpgp_card_sequoia::types::{Fingerprint, KeyType};
use openpgp_card_sequoia::Card as CCard;
use pyo3::prelude::*;
use sequoia_openpgp as openpgp;

use crate::decrypt;
use crate::signer::PySigner;

#[pyclass]
pub struct Card {
    open: CCard<Open>,
}

#[pymethods]
impl Card {
    #[staticmethod]
    pub fn open(ident: &str) -> anyhow::Result<Self> {
        let cards = PcscBackend::card_backends(None)?;
        Ok(Self {
            open: CCard::<Open>::open_by_ident(cards, ident)?,
        })
    }

    #[getter]
    pub fn cardholder(&mut self) -> anyhow::Result<Option<String>> {
        let mut transaction = self.open.transaction()?;
        Ok(transaction
            .cardholder_related_data()?
            .name()
            .map(|name| String::from_utf8_lossy(name).into()))
    }

    #[getter]
    pub fn cert_url(&mut self) -> anyhow::Result<String> {
        let mut transaction = self.open.transaction()?;
        Ok(transaction.url()?)
    }

    #[getter]
    pub fn ident(&mut self) -> anyhow::Result<String> {
        let transaction = self.open.transaction()?;
        Ok(transaction.application_identifier()?.ident())
    }

    #[staticmethod]
    pub fn all() -> anyhow::Result<Vec<Card>> {
        // Need to suppress errors here to handle the case of
        // no-readers being connected.  This should be handled by the
        // backend.
        //
        // See: https://gitlab.com/openpgp-card/openpgp-card/-/issues/6
        if let Ok(cards) = PcscBackend::cards(None) {
            Ok(cards
                .into_iter()
                .filter_map(|card| card.ok())
                .filter_map(|card| CCard::<Open>::new(card).ok())
                .map(|open| Self { open })
                .collect())
        } else {
            Ok(Vec::new())
        }
    }

    pub fn signer(&mut self, pin: String) -> anyhow::Result<PySigner> {
        use sequoia_openpgp::crypto::Signer;

        struct CardSigner {
            public: openpgp::packet::Key<
                openpgp::packet::key::PublicParts,
                openpgp::packet::key::UnspecifiedRole,
            >,
            ident: String,
            pin: String,
        }

        impl openpgp::crypto::Signer for CardSigner {
            fn public(
                &self,
            ) -> &openpgp::packet::Key<
                openpgp::packet::key::PublicParts,
                openpgp::packet::key::UnspecifiedRole,
            > {
                &self.public
            }

            fn sign(
                &mut self,
                hash_algo: openpgp::types::HashAlgorithm,
                digest: &[u8],
            ) -> openpgp::Result<openpgp::crypto::mpi::Signature> {
                let cards = PcscBackend::card_backends(None)?;
                let mut card = CCard::<Open>::open_by_ident(cards, &self.ident)?;
                let mut transaction = card.transaction()?;

                let mut user = transaction
                    .to_signing_card(Some(self.pin.as_bytes()))
                    .expect("This should not fail");

                let mut signer = user.signer(&|| {})?;
                signer.sign(hash_algo, digest)
            }
        }

        let public = {
            let mut transaction = self.open.transaction()?;

            let mut user = transaction
                .to_signing_card(Some(pin.as_bytes()))
                .expect("This should not fail");

            let signer = user.signer(&|| {})?;
            signer.public().clone()
        };
        Ok(PySigner::new(Box::new(CardSigner {
            public,
            ident: self.ident()?,
            pin,
        })))
    }

    pub fn decryptor(&mut self, pin: String) -> anyhow::Result<decrypt::PyDecryptor> {
        use sequoia_openpgp::crypto::Decryptor;

        struct CardDecryptor {
            public: openpgp::packet::Key<
                openpgp::packet::key::PublicParts,
                openpgp::packet::key::UnspecifiedRole,
            >,
            ident: String,
            pin: String,
        }

        impl openpgp::crypto::Decryptor for CardDecryptor {
            fn public(
                &self,
            ) -> &openpgp::packet::Key<
                openpgp::packet::key::PublicParts,
                openpgp::packet::key::UnspecifiedRole,
            > {
                &self.public
            }
            fn decrypt(
                &mut self,
                ciphertext: &openpgp::crypto::mpi::Ciphertext,
                plaintext_len: Option<usize>,
            ) -> openpgp::Result<openpgp::crypto::SessionKey> {
                let cards = PcscBackend::card_backends(None)?;
                let mut card = CCard::<Open>::open_by_ident(cards, &self.ident)?;
                let mut transaction = card.transaction()?;

                let mut user = transaction
                    .to_user_card(Some(self.pin.as_bytes()))
                    .expect("user_card should not fail");

                let mut decryptor = user.decryptor(&|| {})?;
                decryptor.decrypt(ciphertext, plaintext_len)
            }
        }

        let public = {
            let mut transaction = self.open.transaction()?;

            let mut user = transaction
                .to_user_card(Some(pin.as_bytes()))
                .expect("user_card should not fail");

            let decryptor = user.decryptor(&|| {})?;
            decryptor.public().clone()
        };
        Ok(decrypt::PyDecryptor::new(Box::new(CardDecryptor {
            public,
            ident: self.ident()?,
            pin,
        })))
    }

    pub fn __repr__(&mut self) -> anyhow::Result<String> {
        Ok(format!(
            "<Card ident={} cardholder='{:?}' cert_url='{}'>",
            self.ident()?,
            self.cardholder()?,
            self.cert_url()?
        ))
    }

    #[getter]
    pub fn keys(&mut self) -> anyhow::Result<Vec<CardKey>> {
        let transaction = self.open.transaction()?;
        let card_keys = transaction.fingerprints()?;
        let mut keys = Vec::with_capacity(3);
        let mut append_key = |key: Option<&Fingerprint>, key_type: KeyType| {
            if let Some(key) = key {
                let usage = match key_type {
                    KeyType::Signing => Some("sign"),
                    KeyType::Decryption => Some("decrypt"),
                    KeyType::Authentication => Some("authenticate"),
                    _ => None,
                }
                .map(Into::into)
                .into_iter()
                .collect();
                keys.push(CardKey {
                    fingerprint: hex::encode(key.as_bytes()),
                    usage,
                    touch_required: transaction
                        .user_interaction_flag(key_type)
                        .unwrap_or_default()
                        .map(|uif| uif.touch_policy().touch_required())
                        .unwrap_or_default(),
                })
            }
        };
        append_key(card_keys.signature(), KeyType::Signing);
        append_key(card_keys.decryption(), KeyType::Decryption);
        append_key(card_keys.authentication(), KeyType::Authentication);
        Ok(keys)
    }
}

#[pyclass]
pub struct CardKey {
    fingerprint: String,
    usage: Vec<String>,
    touch_required: bool,
}

#[pymethods]
impl CardKey {
    #[getter]
    fn fingerprint(&self) -> &String {
        &self.fingerprint
    }

    #[getter]
    fn usage(&self) -> Vec<String> {
        self.usage.clone()
    }

    #[getter]
    fn touch_required(&self) -> bool {
        self.touch_required
    }

    pub fn __repr__(&self) -> String {
        format!(
            "<Key fingerprint={} usage={:?} touch_required={}>",
            self.fingerprint, self.usage, self.touch_required
        )
    }
}
