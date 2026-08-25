import os
import tempfile
from datetime import datetime

import pytest

from pysequoia import (
    ArmorKind,
    Cert,
    CipherSuite,
    EncryptionAlgorithm,
    Notation,
    Profile,
    Sig,
    SignatureMode,
    SigningAlgorithm,
    Tsk,
    armor,
    decrypt,
    decrypt_file,
    encrypt,
    encrypt_file,
    sign,
    sign_file,
    verify,
)
from pysequoia.packet import PacketPile, PublicKeyAlgorithm, Tag

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(name):
    return os.path.join(FIXTURES, name)


@pytest.fixture
def signing_key():
    return Cert.from_file(fixture_path("signing-key.asc"))


@pytest.fixture
def signing_tsk():
    return Tsk.from_file(fixture_path("signing-key.asc"))


@pytest.fixture
def wiktor_key():
    return Cert.from_file(fixture_path("wiktor.asc"))


@pytest.fixture
def wiktor_fresh_key():
    return Cert.from_file(fixture_path("wiktor-fresh.asc"))


class TestSign:
    def test_inline(self, signing_tsk):
        signed = sign(signing_tsk.signer(), b"data to be signed")
        assert "PGP MESSAGE" in str(signed)

    def test_detached(self, signing_tsk):
        detached = sign(
            signing_tsk.signer(),
            b"data to be signed",
            mode=SignatureMode.DETACHED,
        )
        assert "PGP SIGNATURE" in str(detached)

    def test_clear(self, signing_tsk):
        clear = sign(
            signing_tsk.signer(),
            b"data to be signed",
            mode=SignatureMode.CLEAR,
        )
        assert "PGP SIGNED MESSAGE" in str(clear)


class TestSignFile:
    def test_inline_file(self, signing_tsk):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"data to be signed")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
            output_path = out.name

        try:
            sign_file(signing_tsk.signer(), input_path, output_path)
            assert b"PGP MESSAGE" in open(output_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_detached_file(self, signing_tsk):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"data to be signed")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as out:
            detached_path = out.name

        try:
            sign_file(
                signing_tsk.signer(),
                input_path,
                detached_path,
                mode=SignatureMode.DETACHED,
            )
            assert b"PGP SIGNATURE" in open(detached_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(detached_path)


SIGNING_KEY_FPR = "afcf5405e8f49dbcd5dc548a86375b854b86acf9"


class TestVerify:
    def _store(self, signing_key):
        def get_certs(key_ids):
            return [signing_key]

        return get_certs

    def test_inline_verify(self, signing_key, signing_tsk):
        signed = sign(signing_tsk.signer(), b"data to be signed")
        result = verify(signed, self._store(signing_key))
        assert result.bytes.decode("utf8") == "data to be signed"
        assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
        assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR

    def test_detached_verify_bytes(self, signing_key, signing_tsk):
        data = b"data to be signed"
        detached = sign(signing_tsk.signer(), data, mode=SignatureMode.DETACHED)
        signature = Sig.from_bytes(detached)
        result = verify(bytes=data, store=self._store(signing_key), signature=signature)
        assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
        assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR

    def test_detached_verify_file(self, signing_key, signing_tsk):
        data = b"data to be signed"
        detached = sign(signing_tsk.signer(), data, mode=SignatureMode.DETACHED)
        signature = Sig.from_bytes(detached)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp.close()

            try:
                result = verify(
                    file=tmp.name,
                    store=self._store(signing_key),
                    signature=signature,
                )
                assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
                assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR
            finally:
                os.unlink(tmp.name)

    def test_verify_compressed_signature(self):
        pubkey = Cert.from_file(fixture_path("compressed-pubkey.pgp"))
        sig_bytes = open(fixture_path("compressed-sig.pgp"), "rb").read()

        def store(key_ids):
            return [pubkey]

        verify(bytes=sig_bytes, store=store)

    def test_verify_inline_armored_message(self):
        signing_key = Cert.from_file(fixture_path("signing-key.asc"))
        message = (
            b"-----BEGIN PGP MESSAGE-----\n"
            b"\n"
            b"xA0DAAoWhjdbhUuGrPkByxdiAAAAAABkYXRhIHRvIGJlIHNpZ25lZMK9BAAWCgBv\n"
            b"BYJp6ftzCRCGN1uFS4as+UcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lh\n"
            b"LXBncC5vcmc3UxaVh0GrzpGDSqwKe1nVnBGmDiTYQC/rYRhi3yQ/2BYhBK/PVAXo\n"
            b"9J281dxUioY3W4VLhqz5AAD9hAEA1HX+UXFdqAwgRXH0g3+qN85spOnG1aiuML1N\n"
            b"lXgKeTwBAO2QVu2VLjpFnFu8zZ12V0iRqA1xLUxkZyqburTeTlMM\n"
            b"=y77Y\n"
            b"-----END PGP MESSAGE-----\n"
        )

        def store(key_ids):
            return [signing_key]

        result = verify(bytes=message, store=store)
        assert result.bytes.decode("utf8") == "data to be signed"


class TestEncryptDecrypt:
    def test_encrypt_decrypt_no_signature(self):
        sender = Tsk.generate("Sender <sender@example.com>")
        receiver = Tsk.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            recipients=[receiver.extract_certificate()], bytes=content.encode("utf8")
        )
        decrypted = decrypt(decryptor=receiver.decryptor(), bytes=encrypted)

        assert decrypted.bytes.decode("utf8") == content
        assert len(decrypted.valid_sigs) == 0

    def test_encrypt_decrypt_with_signature(self):
        sender = Tsk.generate("Sender <sender@example.com>")
        receiver = Tsk.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            signer=sender.signer(),
            recipients=[receiver.extract_certificate()],
            bytes=content.encode("utf8"),
        )

        def store(key_ids):
            return [sender.extract_certificate()]

        decrypted = decrypt(
            decryptor=receiver.decryptor(),
            bytes=encrypted,
            store=store,
        )

        assert decrypted.bytes.decode("utf8") == content
        assert (
            decrypted.valid_sigs[0].certificate
            == sender.extract_certificate().fingerprint
        )

    def test_symmetric_encrypt_decrypt(self):
        content = "content to encrypt"
        encrypted = encrypt(passwords=["sekrit"], bytes=content.encode("utf8"))
        decrypted = decrypt(passwords=["sekrit"], bytes=encrypted)
        assert decrypted.bytes.decode("utf8") == content


class TestEncryptDecryptFile:
    def test_encrypt_file(self):
        sender = Tsk.generate("Sender <sender@example.com>")
        receiver = Tsk.generate("Receiver <receiver@example.com>")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"content to encrypt")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
            output_path = out.name

        try:
            encrypt_file(
                signer=sender.signer(),
                recipients=[receiver.extract_certificate()],
                input=input_path,
                output=output_path,
            )
            assert b"PGP MESSAGE" in open(output_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_decrypt_file_no_signature(self):
        receiver = Tsk.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            recipients=[receiver.extract_certificate()], bytes=content.encode("utf8")
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
            inp.write(encrypted)
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
            output_path = out.name

        try:
            decrypted = decrypt_file(
                decryptor=receiver.decryptor(),
                input=input_path,
                output=output_path,
            )
            assert decrypted.bytes is None
            assert open(output_path, "rb").read().decode("utf8") == content
            assert len(decrypted.valid_sigs) == 0
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_decrypt_file_with_signature(self):
        sender = Tsk.generate("Sender <sender@example.com>")
        receiver = Tsk.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            signer=sender.signer(),
            recipients=[receiver.extract_certificate()],
            bytes=content.encode("utf8"),
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
            inp.write(encrypted)
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
            output_path = out.name

        def store(key_ids):
            return [sender.extract_certificate()]

        try:
            decrypted = decrypt_file(
                decryptor=receiver.decryptor(),
                input=input_path,
                output=output_path,
                store=store,
            )
            assert open(output_path, "rb").read().decode("utf8") == content
            assert (
                decrypted.valid_sigs[0].certificate
                == sender.extract_certificate().fingerprint
            )
        finally:
            os.unlink(input_path)
            os.unlink(output_path)


class TestTsk:
    def test_generate_and_export(self):
        tsk = Tsk.generate("Test <test@example.com>")
        assert len(str(tsk)) > 0
        assert len(bytes(tsk)) > 0

    def test_generate_multiple_user_ids(self):
        tsk = Tsk.generate(user_ids=["First", "Second", "Third"])
        cert = tsk.extract_certificate()
        assert len(cert.user_ids) == 3

    def test_generate_rfc9580(self):
        tsk = Tsk.generate("Modern <modern@example.com>", profile=Profile.RFC9580)
        cert = tsk.extract_certificate()
        assert len(cert.fingerprint) > 0

    def test_expiration_with_validity(self):
        tsk = Tsk.generate(user_id="test", validity_seconds=3600)
        cert = tsk.extract_certificate()
        assert cert.expiration is not None

    def test_from_bytes_roundtrip(self):
        tsk = Tsk.generate("Test <test@example.com>")
        parsed = Tsk.from_bytes(bytes(tsk))
        assert (
            tsk.extract_certificate().fingerprint
            == parsed.extract_certificate().fingerprint
        )
        assert (
            str(parsed.extract_certificate().user_ids[0]) == "Test <test@example.com>"
        )

    def test_from_file(self, tmp_path):
        tsk = Tsk.generate("Test <test@example.com>")
        keyfile = tmp_path / "key.pgp"
        keyfile.write_bytes(bytes(tsk))
        loaded = Tsk.from_file(str(keyfile))
        assert (
            tsk.extract_certificate().fingerprint
            == loaded.extract_certificate().fingerprint
        )

    def test_from_file_fixture(self):
        tsk = Tsk.from_file(fixture_path("signing-key.asc"))
        assert len(str(tsk)) > 0

    def test_from_packets(self):
        tsk = Tsk.generate("Test <test@example.com>")
        packets = list(PacketPile.from_bytes(bytes(tsk)))
        rebuilt = Tsk.from_packets(packets)
        assert (
            tsk.extract_certificate().fingerprint
            == rebuilt.extract_certificate().fingerprint
        )

    def test_signer(self):
        tsk = Tsk.generate("Test <test@example.com>")
        signed = sign(tsk.signer(), b"hello")
        assert "PGP MESSAGE" in str(signed)

    def test_certifier(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        updated = cert.add_user_id(
            value="Test <test@other.com>",
            certifier=tsk.certifier(),
        )
        assert len(updated.user_ids) == 2

    def test_decryptor(self):
        tsk = Tsk.generate("Test <test@example.com>")
        content = b"secret data"
        encrypted = encrypt(recipients=[tsk.extract_certificate()], bytes=content)
        decrypted = decrypt(decryptor=tsk.decryptor(), bytes=encrypted)
        assert decrypted.bytes == content

    def test_repr(self):
        tsk = Tsk.generate("Test <test@example.com>")
        assert repr(tsk).startswith("<Tsk fingerprint=")


class TestCert:
    def test_parse_roundtrip(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        parsed = Cert.from_bytes(bytes(cert))
        assert str(parsed.user_ids[0]) == "Test <test@example.com>"

    def test_fingerprint(self):
        tsk = Tsk.generate("Test <test@example.com>")
        assert len(tsk.extract_certificate().fingerprint) > 0

    def test_user_ids(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        assert len(cert.user_ids) == 1
        assert str(cert.user_ids[0]) == "Test <test@example.com>"

    def test_expiration_none(self):
        tsk = Tsk.generate(user_id="test", validity_seconds=None)
        cert = tsk.extract_certificate()
        assert cert.expiration is None

    def test_default_does_not_have_expiration(self):
        tsk = Tsk.generate("test")
        cert = tsk.extract_certificate()
        assert cert.expiration is None

    def test_is_revoked(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        assert not cert.is_revoked

    def test_split_file(self, tmp_path):
        certs = [Tsk.generate(f"Test {i}").extract_certificate() for i in range(3)]
        keyring = tmp_path / "keyring.pgp"
        keyring.write_bytes(b"".join(bytes(c) for c in certs))
        split = Cert.split_file(str(keyring))
        assert len(split) == 3

    def test_split_bytes(self):
        certs = [Tsk.generate(f"Test {i}").extract_certificate() for i in range(3)]
        combined = b"".join(bytes(c) for c in certs)
        split = Cert.split_bytes(combined)
        assert len(split) == 3

    def test_merge(self, wiktor_key, wiktor_fresh_key):
        merged = wiktor_key.merge(wiktor_fresh_key)
        assert merged is not None

    def test_user_id_listing(self, wiktor_key):
        assert str(wiktor_key.user_ids[0]).startswith("Wiktor Kwapisiewicz")

    def test_add_user_id(self):
        tsk = Tsk.generate("Alice <alice@example.com>")
        cert = tsk.extract_certificate()
        assert len(cert.user_ids) == 1
        cert = cert.add_user_id(
            value="Alice <alice@company.invalid>",
            certifier=tsk.certifier(),
        )
        assert len(cert.user_ids) == 2

    def test_revoke_user_id(self):
        tsk = Tsk.generate("Bob <bob@example.com>")
        cert = tsk.extract_certificate()
        cert = cert.add_user_id(
            value="Bob <bob@company.invalid>",
            certifier=tsk.certifier(),
        )
        assert len(cert.user_ids) == 2

        revocation = cert.revoke_user_id(
            user_id=cert.user_ids[1], certifier=tsk.certifier()
        )
        cert = Cert.from_bytes(bytes(cert) + bytes(revocation))
        assert len(cert.user_ids) == 1


class TestNotations:
    def test_read_notation(self, wiktor_key):
        notation = wiktor_key.user_ids[0].notations[0]
        assert notation.key == "proof@metacode.biz"
        assert notation.value == "dns:metacode.biz?type=TXT"

    def test_add_notation(self, signing_key, signing_tsk):
        assert len(signing_key.user_ids[0].notations) == 0
        cert = signing_key.set_notations(
            signing_tsk.certifier(),
            [Notation("proof@metacode.biz", "dns:metacode.biz")],
        )
        assert len(cert.user_ids[0].notations) == 1
        notation = cert.user_ids[0].notations[0]
        assert notation.key == "proof@metacode.biz"
        assert notation.value == "dns:metacode.biz"


class TestKeyExpiration:
    def test_no_expiration(self, signing_key):
        assert signing_key.expiration is None

    def test_has_expiration(self, wiktor_key):
        assert str(wiktor_key.expiration) == "2022-12-31 12:00:02+00:00"

    def test_set_expiration(self, signing_key, signing_tsk):
        assert signing_key.expiration is None
        expiration = datetime.fromisoformat("2021-11-04T00:05:23+00:00")
        updated = signing_key.set_expiration(
            expiration=expiration, certifier=signing_tsk.certifier()
        )
        assert str(updated.expiration) == "2021-11-04 00:05:23+00:00"


class TestKeyRevocation:
    def test_revoke(self):
        tsk = Tsk.generate("Test Revocation <revoke@example.com>")
        cert = tsk.extract_certificate()
        revocation = cert.revoke(certifier=tsk.certifier())
        assert not cert.is_revoked

        revoked = Cert.from_bytes(bytes(cert) + bytes(revocation))
        assert revoked.is_revoked


class TestSig:
    def test_parse_from_file(self):
        sig = Sig.from_file(fixture_path("sig.pgp"))
        assert sig.issuer_fingerprint == "e8f23996f23218640cb44cbe75cf5ac418b8e74c"
        assert sig.issuer_key_id == "75cf5ac418b8e74c"
        assert sig.created == datetime.fromisoformat("2023-07-19T18:14:01+00:00")
        assert sig.expiration is None
        assert sig.signers_user_id is None
        assert sig.version == 4


class TestRFC9580:
    def test_sign_verify_roundtrip(self):
        tsk = Tsk.generate("V6 <v6@example.com>", profile=Profile.RFC9580)
        data = b"v6 signed data"
        signed = sign(tsk.signer(), data)

        def store(key_ids):
            return [tsk.extract_certificate()]

        result = verify(signed, store)
        assert result.bytes == data

    def test_detached_signature(self):
        tsk = Tsk.generate("V6 <v6@example.com>", profile=Profile.RFC9580)
        detached = sign(tsk.signer(), b"data", mode=SignatureMode.DETACHED)
        sig = Sig.from_bytes(detached)
        assert sig.version == 6

    def test_encrypt_decrypt_roundtrip(self):
        sender = Tsk.generate("V6 Sender <s@example.com>", profile=Profile.RFC9580)
        receiver = Tsk.generate("V6 Receiver <r@example.com>", profile=Profile.RFC9580)
        content = b"v6 encrypted data"

        encrypted = encrypt(
            signer=sender.signer(),
            recipients=[receiver.extract_certificate()],
            bytes=content,
        )
        decrypted = decrypt(decryptor=receiver.decryptor(), bytes=encrypted)
        assert decrypted.bytes == content


class TestPQC:
    def test_generate_pqc_cert(self):
        tsk = Tsk.generate(
            "PQC <pqc@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA65_Ed25519,
        )
        cert = tsk.extract_certificate()
        assert len(cert.fingerprint) > 0
        assert str(cert.user_ids[0]) == "PQC <pqc@example.com>"

    def test_pqc_sign_verify_roundtrip(self):
        tsk = Tsk.generate(
            "PQC <pqc@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA65_Ed25519,
        )
        data = b"post-quantum signed data"
        signed = sign(tsk.signer(), data)

        def store(key_ids):
            return [tsk.extract_certificate()]

        result = verify(signed, store)
        assert result.bytes == data

    def test_pqc_encrypt_decrypt_roundtrip(self):
        sender = Tsk.generate(
            "PQC Sender <s@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA65_Ed25519,
        )
        receiver = Tsk.generate(
            "PQC Receiver <r@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA65_Ed25519,
        )
        content = b"post-quantum encrypted data"

        encrypted = encrypt(
            signer=sender.signer(),
            recipients=[receiver.extract_certificate()],
            bytes=content,
        )

        def store(key_ids):
            return [sender.extract_certificate()]

        decrypted = decrypt(
            decryptor=receiver.decryptor(),
            bytes=encrypted,
            store=store,
        )
        assert decrypted.bytes == content
        assert decrypted.valid_sigs[0].certificate == sender.extract_certificate().fingerprint

    def test_pqc_detached_signature(self):
        tsk = Tsk.generate(
            "PQC <pqc@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA65_Ed25519,
        )
        detached = sign(tsk.signer(), b"data", mode=SignatureMode.DETACHED)
        sig = Sig.from_bytes(detached)
        assert sig.version == 6

    def test_pqc_requires_rfc9580(self):
        with pytest.raises(Exception):
            Tsk.generate(
                "PQC <pqc@example.com>",
                cipher_suite=CipherSuite.MLDSA65_Ed25519,
            )

    def test_pqc_key_algorithm_introspection(self):
        tsk = Tsk.generate(
            "PQC <pqc@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA65_Ed25519,
        )
        pile = PacketPile.from_bytes(bytes(tsk.extract_certificate()))
        key_algorithms = [
            p.key_algorithm
            for p in pile
            if p.tag in (Tag.PublicKey, Tag.PublicSubkey)
        ]
        assert PublicKeyAlgorithm.MLDSA65_Ed25519 in key_algorithms
        assert PublicKeyAlgorithm.MLKEM768_X25519 in key_algorithms

    def test_pqc_mldsa87_ed448(self):
        tsk = Tsk.generate(
            "PQC87 <pqc87@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA87_Ed448,
        )
        data = b"higher security PQC"
        signed = sign(tsk.signer(), data)

        def store(key_ids):
            return [tsk.extract_certificate()]

        result = verify(signed, store)
        assert result.bytes == data

    def test_pqc_cross_encrypt_classical_to_pqc(self):
        classical = Tsk.generate(
            "Classical <classical@example.com>",
            profile=Profile.RFC9580,
        )
        pqc = Tsk.generate(
            "PQC <pqc@example.com>",
            profile=Profile.RFC9580,
            cipher_suite=CipherSuite.MLDSA65_Ed25519,
        )
        content = b"cross-algorithm message"

        encrypted = encrypt(
            signer=classical.signer(),
            recipients=[pqc.extract_certificate()],
            bytes=content,
        )

        def store(key_ids):
            return [classical.extract_certificate()]

        decrypted = decrypt(
            decryptor=pqc.decryptor(),
            bytes=encrypted,
            store=store,
        )
        assert decrypted.bytes == content


class TestAlgorithmSelection:
    def test_slhdsa_signing(self):
        tsk = Tsk.generate(
            "SLH <slh@example.com>",
            profile=Profile.RFC9580,
            signing_algorithm=SigningAlgorithm.SLHDSA128f,
        )
        data = b"slh-dsa signed data"
        signed = sign(tsk.signer(), data)

        def store(key_ids):
            return [tsk.extract_certificate()]

        result = verify(signed, store)
        assert result.bytes == data

    def test_mixed_pqc_encryption_classical_signing(self):
        tsk = Tsk.generate(
            "Mixed <mixed@example.com>",
            profile=Profile.RFC9580,
            encryption_algorithm=EncryptionAlgorithm.MLKEM768_X25519,
        )
        data = b"mixed algorithm message"
        signed = sign(tsk.signer(), data)

        def store(key_ids):
            return [tsk.extract_certificate()]

        result = verify(signed, store)
        assert result.bytes == data

        encrypted = encrypt(recipients=[tsk.extract_certificate()], bytes=data)
        decrypted = decrypt(decryptor=tsk.decryptor(), bytes=encrypted)
        assert decrypted.bytes == data

    def test_slhdsa_with_default_encryption(self):
        tsk = Tsk.generate(
            "SLH <slh@example.com>",
            profile=Profile.RFC9580,
            signing_algorithm=SigningAlgorithm.SLHDSA128s,
        )
        pile = PacketPile.from_bytes(bytes(tsk.extract_certificate()))
        key_algorithms = [
            p.key_algorithm
            for p in pile
            if p.tag in (Tag.PublicKey, Tag.PublicSubkey)
        ]
        assert PublicKeyAlgorithm.SLHDSA128s in key_algorithms
        assert PublicKeyAlgorithm.X25519 in key_algorithms

    def test_slhdsa_detached_sig_version(self):
        tsk = Tsk.generate(
            "SLH <slh@example.com>",
            profile=Profile.RFC9580,
            signing_algorithm=SigningAlgorithm.SLHDSA128f,
        )
        detached = sign(tsk.signer(), b"data", mode=SignatureMode.DETACHED)
        sig = Sig.from_bytes(detached)
        assert sig.version == 6

    def test_signing_algorithm_variants_exist(self):
        assert SigningAlgorithm.MLDSA65_Ed25519 is not None
        assert SigningAlgorithm.MLDSA87_Ed448 is not None
        assert SigningAlgorithm.SLHDSA128s is not None
        assert SigningAlgorithm.SLHDSA128f is not None
        assert SigningAlgorithm.SLHDSA256s is not None
        assert SigningAlgorithm.Ed25519 is not None
        assert SigningAlgorithm.Ed448 is not None

    def test_encryption_algorithm_variants_exist(self):
        assert EncryptionAlgorithm.MLKEM768_X25519 is not None
        assert EncryptionAlgorithm.MLKEM1024_X448 is not None
        assert EncryptionAlgorithm.X25519 is not None
        assert EncryptionAlgorithm.X448 is not None


class TestCipherSuite:
    def test_generate_rsa4k(self):
        tsk = Tsk.generate("RSA <rsa@example.com>", cipher_suite=CipherSuite.RSA4k)
        cert = tsk.extract_certificate()
        assert len(cert.fingerprint) > 0

    def test_generate_default_cipher_suite(self):
        tsk = Tsk.generate("Default <default@example.com>")
        cert = tsk.extract_certificate()
        assert len(cert.fingerprint) > 0

    def test_all_cipher_suite_variants_exist(self):
        assert CipherSuite.Cv25519 is not None
        assert CipherSuite.Cv448 is not None
        assert CipherSuite.RSA2k is not None
        assert CipherSuite.RSA3k is not None
        assert CipherSuite.RSA4k is not None
        assert CipherSuite.P256 is not None
        assert CipherSuite.P384 is not None
        assert CipherSuite.P521 is not None
        assert CipherSuite.MLDSA65_Ed25519 is not None
        assert CipherSuite.MLDSA87_Ed448 is not None


class TestPacketPile:
    def test_iterate_public_packets(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        pile = PacketPile.from_bytes(bytes(cert))
        tags = [p.tag for p in pile]
        assert Tag.PublicKey in tags
        assert Tag.UserID in tags
        assert Tag.Signature in tags

    def test_iterate_secret_packets(self):
        tsk = Tsk.generate("Test <test@example.com>")
        pile = PacketPile.from_bytes(bytes(tsk))
        tags = [p.tag for p in pile]
        assert Tag.SecretKey in tags
        assert Tag.SecretSubkey in tags
        assert Tag.UserID in tags
        assert Tag.Signature in tags

    def test_packet_body(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        packet = list(PacketPile.from_bytes(bytes(cert)))[0]
        assert packet.tag == Tag.PublicKey
        body = packet.body
        assert len(body) > 0
        assert body[0] in (4, 6)

    def test_packet_body_excludes_header(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        for packet in PacketPile.from_bytes(bytes(cert)):
            body = packet.body
            full = bytes(packet)
            assert len(full) > len(body)
            assert full[-len(body) :] == body

    def test_packet_bytes_roundtrip(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        packets = list(PacketPile.from_bytes(bytes(cert)))
        reassembled = b"".join(bytes(p) for p in packets)
        reparsed = Cert.from_bytes(reassembled)
        assert reparsed.fingerprint == cert.fingerprint


class TestArmor:
    def test_armor_public_key(self):
        tsk = Tsk.generate("Test <test@example.com>")
        cert = tsk.extract_certificate()
        armored = armor(bytes(cert), ArmorKind.PublicKey)
        assert "-----BEGIN PGP PUBLIC KEY BLOCK-----" in armored
        assert "-----END PGP PUBLIC KEY BLOCK-----" in armored

    def test_armor_message(self):
        armored = armor(b"dummy data", ArmorKind.Message)
        assert "BEGIN PGP MESSAGE" in armored

    def test_armor_signature(self):
        armored = armor(b"dummy data", ArmorKind.Signature)
        assert "BEGIN PGP SIGNATURE" in armored


class TestPasswordProtectedKeys:
    def test_sign_with_password(self):
        tsk = Tsk.generate("PW <pw@example.com>")
        signed = sign(tsk.signer(), b"hello")
        assert "PGP MESSAGE" in str(signed)

    def test_encrypt_decrypt_with_password(self):
        sender = Tsk.generate("Sender <s@example.com>")
        receiver = Tsk.generate("Receiver <r@example.com>")
        content = b"secret message"

        encrypted = encrypt(
            signer=sender.signer(),
            recipients=[receiver.extract_certificate()],
            bytes=content,
        )
        decrypted = decrypt(decryptor=receiver.decryptor(), bytes=encrypted)
        assert decrypted.bytes == content

    def test_decrypt_wrong_password_fails(self):
        content = b"secret"
        encrypted = encrypt(passwords=["correct"], bytes=content)
        with pytest.raises(Exception):
            decrypt(passwords=["wrong"], bytes=encrypted)

    def test_decrypt_wrong_key_fails(self):
        alice = Tsk.generate("Alice <alice@example.com>")
        bob = Tsk.generate("Bob <bob@example.com>")
        encrypted = encrypt(
            recipients=[alice.extract_certificate()], bytes=b"for alice only"
        )
        with pytest.raises(Exception):
            decrypt(decryptor=bob.decryptor(), bytes=encrypted)


class TestPublicKeyAlgorithm:
    def test_pqc_algorithm_variants_exist(self):
        assert PublicKeyAlgorithm.MLDSA65_Ed25519 is not None
        assert PublicKeyAlgorithm.MLDSA87_Ed448 is not None
        assert PublicKeyAlgorithm.SLHDSA128s is not None
        assert PublicKeyAlgorithm.SLHDSA128f is not None
        assert PublicKeyAlgorithm.SLHDSA256s is not None
        assert PublicKeyAlgorithm.MLKEM768_X25519 is not None
        assert PublicKeyAlgorithm.MLKEM1024_X448 is not None

    def test_pqc_and_classical_are_distinct(self):
        assert PublicKeyAlgorithm.MLDSA65_Ed25519 != PublicKeyAlgorithm.Ed25519
        assert PublicKeyAlgorithm.MLKEM768_X25519 != PublicKeyAlgorithm.X25519

    def test_pqc_repr(self):
        assert "MLDSA65_Ed25519" in repr(PublicKeyAlgorithm.MLDSA65_Ed25519)
        assert "MLKEM768_X25519" in repr(PublicKeyAlgorithm.MLKEM768_X25519)


class TestErrorCases:
    def test_verify_with_wrong_key(self, signing_tsk):
        wrong_key = Tsk.generate("Wrong <wrong@example.com>")
        signed = sign(signing_tsk.signer(), b"data")

        def store(key_ids):
            return [wrong_key.extract_certificate()]

        with pytest.raises(Exception):
            verify(signed, store)

    def test_verify_missing_store(self):
        with pytest.raises(Exception):
            verify(bytes=b"not a real message")

    def test_verify_bytes_and_file_mutually_exclusive(self, signing_tsk, tmp_path):
        data = b"data"
        signed = sign(signing_tsk.signer(), data, mode=SignatureMode.DETACHED)
        signature = Sig.from_bytes(signed)
        f = tmp_path / "data.bin"
        f.write_bytes(data)

        def store(key_ids):
            return [signing_tsk.extract_certificate()]

        with pytest.raises(Exception):
            verify(bytes=data, file=str(f), store=store, signature=signature)

    def test_verify_no_bytes_or_file(self):
        def store(key_ids):
            return []

        with pytest.raises(Exception):
            verify(store=store)
