import os
import tempfile
from datetime import datetime

import pytest

from pysequoia import (
    ArmorKind,
    Cert,
    Notation,
    Profile,
    Sig,
    SignatureMode,
    armor,
    decrypt,
    decrypt_file,
    encrypt,
    encrypt_file,
    sign,
    sign_file,
    verify,
)
from pysequoia.packet import PacketPile, Tag

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(name):
    return os.path.join(FIXTURES, name)


@pytest.fixture
def signing_key():
    return Cert.from_file(fixture_path("signing-key.asc"))


@pytest.fixture
def wiktor_key():
    return Cert.from_file(fixture_path("wiktor.asc"))


@pytest.fixture
def wiktor_fresh_key():
    return Cert.from_file(fixture_path("wiktor-fresh.asc"))


class TestSign:
    def test_inline(self, signing_key):
        signed = sign(signing_key.secrets.signer(), b"data to be signed")
        assert "PGP MESSAGE" in str(signed)

    def test_detached(self, signing_key):
        detached = sign(
            signing_key.secrets.signer(),
            b"data to be signed",
            mode=SignatureMode.DETACHED,
        )
        assert "PGP SIGNATURE" in str(detached)

    def test_clear(self, signing_key):
        clear = sign(
            signing_key.secrets.signer(),
            b"data to be signed",
            mode=SignatureMode.CLEAR,
        )
        assert "PGP SIGNED MESSAGE" in str(clear)


class TestSignFile:
    def test_inline_file(self, signing_key):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"data to be signed")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
            output_path = out.name

        try:
            sign_file(signing_key.secrets.signer(), input_path, output_path)
            assert b"PGP MESSAGE" in open(output_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_detached_file(self, signing_key):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"data to be signed")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig") as out:
            detached_path = out.name

        try:
            sign_file(
                signing_key.secrets.signer(),
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

    def test_inline_verify(self, signing_key):
        signed = sign(signing_key.secrets.signer(), b"data to be signed")
        result = verify(signed, self._store(signing_key))
        assert result.bytes.decode("utf8") == "data to be signed"
        assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
        assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR

    def test_detached_verify_bytes(self, signing_key):
        data = b"data to be signed"
        detached = sign(signing_key.secrets.signer(), data, mode=SignatureMode.DETACHED)
        signature = Sig.from_bytes(detached)
        result = verify(bytes=data, store=self._store(signing_key), signature=signature)
        assert result.valid_sigs[0].certificate == SIGNING_KEY_FPR
        assert result.valid_sigs[0].signing_key == SIGNING_KEY_FPR

    def test_detached_verify_file(self, signing_key):
        data = b"data to be signed"
        detached = sign(signing_key.secrets.signer(), data, mode=SignatureMode.DETACHED)
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
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(recipients=[receiver], bytes=content.encode("utf8"))
        decrypted = decrypt(decryptor=receiver.secrets.decryptor(), bytes=encrypted)

        assert decrypted.bytes.decode("utf8") == content
        assert len(decrypted.valid_sigs) == 0

    def test_encrypt_decrypt_with_signature(self):
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            signer=sender.secrets.signer(),
            recipients=[receiver],
            bytes=content.encode("utf8"),
        )

        def store(key_ids):
            return [sender]

        decrypted = decrypt(
            decryptor=receiver.secrets.decryptor(),
            bytes=encrypted,
            store=store,
        )

        assert decrypted.bytes.decode("utf8") == content
        assert decrypted.valid_sigs[0].certificate == sender.fingerprint

    def test_symmetric_encrypt_decrypt(self):
        content = "content to encrypt"
        encrypted = encrypt(passwords=["sekrit"], bytes=content.encode("utf8"))
        decrypted = decrypt(passwords=["sekrit"], bytes=encrypted)
        assert decrypted.bytes.decode("utf8") == content


class TestEncryptDecryptFile:
    def test_encrypt_file(self):
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as inp:
            inp.write(b"content to encrypt")
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as out:
            output_path = out.name

        try:
            encrypt_file(
                signer=sender.secrets.signer(),
                recipients=[receiver],
                input=input_path,
                output=output_path,
            )
            assert b"PGP MESSAGE" in open(output_path, "rb").read()
        finally:
            os.unlink(input_path)
            os.unlink(output_path)

    def test_decrypt_file_no_signature(self):
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(recipients=[receiver], bytes=content.encode("utf8"))

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
            inp.write(encrypted)
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
            output_path = out.name

        try:
            decrypted = decrypt_file(
                decryptor=receiver.secrets.decryptor(),
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
        sender = Cert.generate("Sender <sender@example.com>")
        receiver = Cert.generate("Receiver <receiver@example.com>")
        content = "Red Green Blue"

        encrypted = encrypt(
            signer=sender.secrets.signer(),
            recipients=[receiver],
            bytes=content.encode("utf8"),
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pgp") as inp:
            inp.write(encrypted)
            input_path = inp.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as out:
            output_path = out.name

        def store(key_ids):
            return [sender]

        try:
            decrypted = decrypt_file(
                decryptor=receiver.secrets.decryptor(),
                input=input_path,
                output=output_path,
                store=store,
            )
            assert open(output_path, "rb").read().decode("utf8") == content
            assert decrypted.valid_sigs[0].certificate == sender.fingerprint
        finally:
            os.unlink(input_path)
            os.unlink(output_path)


class TestCert:
    def test_generate_and_export(self):
        cert = Cert.generate("Test <test@example.com>")
        assert len(str(cert)) > 0
        assert len(bytes(cert)) > 0

    def test_secrets_export(self):
        cert = Cert.generate("Test <test@example.com>")
        assert cert.secrets is not None
        assert len(str(cert.secrets)) > 0
        assert len(bytes(cert.secrets)) > 0

    def test_parse_roundtrip(self):
        cert = Cert.generate("Test <test@example.com>")
        parsed = Cert.from_bytes(bytes(cert))
        assert str(parsed.user_ids[0]) == "Test <test@example.com>"

    def test_split_bytes(self):
        certs = [Cert.generate(f"Test {i}") for i in range(3)]
        combined = b"".join(bytes(c) for c in certs)
        split = Cert.split_bytes(combined)
        assert len(split) == 3

    def test_generate_multiple_user_ids(self):
        cert = Cert.generate(user_ids=["First", "Second", "Third"])
        assert len(cert.user_ids) == 3

    def test_generate_rfc9580(self):
        cert = Cert.generate("Modern <modern@example.com>", profile=Profile.RFC9580)
        assert len(cert.fingerprint) > 0

    def test_expiration_with_validity(self):
        cert = Cert.generate(user_id="test", validity_seconds=3600)
        assert cert.expiration is not None

    def test_expiration_none(self):
        cert = Cert.generate(user_id="test", validity_seconds=None)
        assert cert.expiration is None

    def test_default_has_expiration(self):
        cert = Cert.generate("test")
        assert cert.expiration is not None

    def test_merge(self, wiktor_key, wiktor_fresh_key):
        merged = wiktor_key.merge(wiktor_fresh_key)
        assert merged is not None

    def test_user_id_listing(self, wiktor_key):
        assert str(wiktor_key.user_ids[0]).startswith("Wiktor Kwapisiewicz")

    def test_add_user_id(self):
        cert = Cert.generate("Alice <alice@example.com>")
        assert len(cert.user_ids) == 1
        cert = cert.add_user_id(
            value="Alice <alice@company.invalid>",
            certifier=cert.secrets.certifier(),
        )
        assert len(cert.user_ids) == 2

    def test_revoke_user_id(self):
        cert = Cert.generate("Bob <bob@example.com>")
        cert = cert.add_user_id(
            value="Bob <bob@company.invalid>",
            certifier=cert.secrets.certifier(),
        )
        assert len(cert.user_ids) == 2

        revocation = cert.revoke_user_id(
            user_id=cert.user_ids[1], certifier=cert.secrets.certifier()
        )
        cert = Cert.from_bytes(bytes(cert) + bytes(revocation))
        assert len(cert.user_ids) == 1

    def test_split_file(self, tmp_path):
        certs = [Cert.generate(f"Test {i}") for i in range(3)]
        keyring = tmp_path / "keyring.pgp"
        keyring.write_bytes(b"".join(bytes(c) for c in certs))
        split = Cert.split_file(str(keyring))
        assert len(split) == 3

    def test_has_secret_keys(self):
        c = Cert.generate("Testing key <test@example.com>")
        assert c.has_secret_keys

        public_parts = Cert.from_bytes(f"{c}".encode("utf8"))
        assert not public_parts.has_secret_keys
        assert public_parts.secrets is None

        private_parts = Cert.from_bytes(f"{c.secrets}".encode("utf8"))
        assert private_parts.has_secret_keys


class TestNotations:
    def test_read_notation(self, wiktor_key):
        notation = wiktor_key.user_ids[0].notations[0]
        assert notation.key == "proof@metacode.biz"
        assert notation.value == "dns:metacode.biz?type=TXT"

    def test_add_notation(self, signing_key):
        assert len(signing_key.user_ids[0].notations) == 0
        cert = signing_key.set_notations(
            signing_key.secrets.certifier(),
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

    def test_set_expiration(self, signing_key):
        assert signing_key.expiration is None
        expiration = datetime.fromisoformat("2021-11-04T00:05:23+00:00")
        updated = signing_key.set_expiration(
            expiration=expiration, certifier=signing_key.secrets.certifier()
        )
        assert str(updated.expiration) == "2021-11-04 00:05:23+00:00"


class TestKeyRevocation:
    def test_revoke(self):
        cert = Cert.generate("Test Revocation <revoke@example.com>")
        revocation = cert.revoke(certifier=cert.secrets.certifier())
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
        cert = Cert.generate("V6 <v6@example.com>", profile=Profile.RFC9580)
        data = b"v6 signed data"
        signed = sign(cert.secrets.signer(), data)

        def store(key_ids):
            return [cert]

        result = verify(signed, store)
        assert result.bytes == data

    def test_detached_signature(self):
        cert = Cert.generate("V6 <v6@example.com>", profile=Profile.RFC9580)
        detached = sign(cert.secrets.signer(), b"data", mode=SignatureMode.DETACHED)
        sig = Sig.from_bytes(detached)
        assert sig.version == 6

    def test_encrypt_decrypt_roundtrip(self):
        sender = Cert.generate("V6 Sender <s@example.com>", profile=Profile.RFC9580)
        receiver = Cert.generate("V6 Receiver <r@example.com>", profile=Profile.RFC9580)
        content = b"v6 encrypted data"

        encrypted = encrypt(
            signer=sender.secrets.signer(),
            recipients=[receiver],
            bytes=content,
        )
        decrypted = decrypt(decryptor=receiver.secrets.decryptor(), bytes=encrypted)
        assert decrypted.bytes == content


class TestPacketPile:
    def test_iterate_packets(self):
        cert = Cert.generate("Test <test@example.com>")
        pile = PacketPile.from_bytes(bytes(cert))
        tags = [p.tag for p in pile]
        assert Tag.PublicKey in tags
        assert Tag.UserID in tags
        assert Tag.Signature in tags

    def test_packet_body(self):
        cert = Cert.generate("Test <test@example.com>")
        packet = list(PacketPile.from_bytes(bytes(cert)))[0]
        assert packet.tag == Tag.PublicKey
        assert len(packet.body) > 0


class TestArmor:
    def test_armor_public_key(self):
        cert = Cert.generate("Test <test@example.com>")
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
    @pytest.fixture
    def protected_key(self):
        cert = Cert.generate("Protected <protected@example.com>")
        tsk_bytes = f"{cert.secrets}".encode("utf8")
        return Cert.from_bytes(tsk_bytes)

    def test_sign_with_password(self):
        cert = Cert.generate("PW <pw@example.com>")
        signed = sign(cert.secrets.signer(), b"hello")
        assert "PGP MESSAGE" in str(signed)

    def test_encrypt_decrypt_with_password(self):
        sender = Cert.generate("Sender <s@example.com>")
        receiver = Cert.generate("Receiver <r@example.com>")
        content = b"secret message"

        encrypted = encrypt(
            signer=sender.secrets.signer(),
            recipients=[receiver],
            bytes=content,
        )
        decrypted = decrypt(decryptor=receiver.secrets.decryptor(), bytes=encrypted)
        assert decrypted.bytes == content

    def test_decrypt_wrong_password_fails(self):
        receiver = Cert.generate("Receiver <r@example.com>")
        content = b"secret"
        encrypted = encrypt(passwords=["correct"], bytes=content)
        with pytest.raises(Exception):
            decrypt(passwords=["wrong"], bytes=encrypted)

    def test_decrypt_wrong_key_fails(self):
        alice = Cert.generate("Alice <alice@example.com>")
        bob = Cert.generate("Bob <bob@example.com>")
        encrypted = encrypt(recipients=[alice], bytes=b"for alice only")
        with pytest.raises(Exception):
            decrypt(decryptor=bob.secrets.decryptor(), bytes=encrypted)


class TestErrorCases:
    def test_verify_with_wrong_key(self, signing_key):
        wrong_key = Cert.generate("Wrong <wrong@example.com>")
        signed = sign(signing_key.secrets.signer(), b"data")

        def store(key_ids):
            return [wrong_key]

        with pytest.raises(Exception):
            verify(signed, store)

    def test_verify_missing_store(self):
        with pytest.raises(Exception):
            verify(bytes=b"not a real message")

    def test_verify_bytes_and_file_mutually_exclusive(self, signing_key, tmp_path):
        data = b"data"
        signed = sign(signing_key.secrets.signer(), data, mode=SignatureMode.DETACHED)
        signature = Sig.from_bytes(signed)
        f = tmp_path / "data.bin"
        f.write_bytes(data)

        def store(key_ids):
            return [signing_key]

        with pytest.raises(Exception):
            verify(bytes=data, file=str(f), store=store, signature=signature)

    def test_verify_no_bytes_or_file(self):
        def store(key_ids):
            return []

        with pytest.raises(Exception):
            verify(store=store)
