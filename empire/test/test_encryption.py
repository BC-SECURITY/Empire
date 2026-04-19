from os import urandom

import pytest

from empire.server.common import encryption


class TestPoly1305:
    def test_divceil(self):
        assert encryption.divceil(13, 5) == 3  # noqa: PLR2004
        assert encryption.divceil(15, 5) == 3  # noqa: PLR2004

    def test_create_tag(self):
        key = urandom(32)
        poly = encryption.Poly1305(key)
        data = urandom(16)
        tag = poly.create_tag(data)
        assert poly.create_tag(urandom(16)) != tag
        assert poly.create_tag(data) == tag

    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="256 bit"):
            encryption.Poly1305(urandom(16))


class TestChaCha20:
    def test_encrypt(self):
        key = urandom(32)
        chacha = encryption.ChaCha(key, urandom(12))
        data = urandom(10)
        assert chacha.encrypt(data) != data

    def test_decrypt(self):
        key = urandom(32)
        chacha = encryption.ChaCha(key, urandom(12))
        data = urandom(10)
        assert chacha.decrypt(chacha.encrypt(data)) == data

    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="256 bit"):
            encryption.ChaCha(urandom(16), urandom(12))

    def test_invalid_nonce_length(self):
        with pytest.raises(ValueError, match="96 bit"):
            encryption.ChaCha(urandom(32), urandom(8))


class TestChaCha20Poly1305:
    def test_encrypt(self):
        cipher = encryption.ChaCha20Poly1305(urandom(32))
        data = urandom(10)
        assert cipher.encrypt(urandom(12), data) != data

    def test_decrypt(self):
        cipher = encryption.ChaCha20Poly1305(urandom(32))
        data = urandom(10)
        nonce = urandom(12)
        assert cipher.decrypt(nonce, cipher.encrypt(nonce, data)) == data

    def test_seal_open(self):
        cipher = encryption.ChaCha20Poly1305(urandom(32))
        data = urandom(10)
        nonce = urandom(12)
        sealed = cipher.seal(nonce, data, "123")
        assert sealed != data
        assert cipher.open(nonce, sealed, "123") == data

    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="256 bit"):
            encryption.ChaCha20Poly1305(urandom(16))

    def test_tampered_ciphertext_raises(self):
        cipher = encryption.ChaCha20Poly1305(urandom(32))
        nonce = urandom(12)
        ct = cipher.encrypt(nonce, b"secret data")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(encryption.TagInvalidException):
            cipher.decrypt(nonce, bytes(tampered))


class TestAESCipher:
    def test_pad_depad_roundtrip(self):
        data = b"hello world"
        padded = encryption.AESCipher.pad(data)
        assert len(padded) % 16 == 0
        assert encryption.AESCipher.depad(padded) == data

    def test_depad_invalid_length(self):
        with pytest.raises(ValueError, match="invalid length"):
            encryption.AESCipher.depad(b"123")

    def test_encrypt_decrypt_roundtrip(self):
        key = urandom(16)
        data = b"test plaintext data"
        assert (
            encryption.AESCipher.decrypt(key, encryption.AESCipher.encrypt(key, data))
            == data
        )

    def test_decrypt_too_short(self):
        with pytest.raises(ValueError, match="larger then 16"):
            encryption.AESCipher.decrypt(urandom(16), b"short")

    def test_encrypt_then_hmac_verify_roundtrip(self):
        key = urandom(16)
        ct_hmac = encryption.AESCipher.encrypt_then_hmac(key, b"some sensitive data")
        assert encryption.AESCipher.verify_hmac(key, ct_hmac) is True

    def test_verify_hmac_wrong_key(self):
        key1 = urandom(16)
        ct_hmac = encryption.AESCipher.encrypt_then_hmac(key1, b"data")
        assert encryption.AESCipher.verify_hmac(urandom(16), ct_hmac) is False

    def test_verify_hmac_short_data(self):
        assert encryption.AESCipher.verify_hmac(urandom(16), b"short") is False

    def test_decrypt_and_verify_roundtrip(self):
        key = urandom(16)
        data = b"message to protect"
        ct = encryption.AESCipher.encrypt_then_hmac(key, data)
        assert encryption.AESCipher.decrypt_and_verify(key, ct) == data

    def test_decrypt_and_verify_invalid(self):
        with pytest.raises(Exception, match="Invalid ciphertext"):
            encryption.AESCipher.decrypt_and_verify(urandom(16), b"bad data")

    def test_generate_key(self):
        key = encryption.AESCipher.generate_key()
        assert isinstance(key, str)
        assert len(key) == 32  # noqa: PLR2004


class TestDiffieHellman:
    def test_two_party_key_exchange(self):
        alice = encryption.DiffieHellman()
        bob = encryption.DiffieHellman()
        alice.gen_key(bob.publicKey)
        bob.gen_key(alice.publicKey)
        assert alice.getKey() == bob.getKey()

    def test_invalid_generator_falls_back(self):
        dh = encryption.DiffieHellman(generator=11)
        assert dh.generator == 2  # noqa: PLR2004

    def test_short_key_length_uses_minimum(self):
        dh = encryption.DiffieHellman(keyLength=10)
        assert dh.keyLength == 180  # noqa: PLR2004

    def test_check_public_key_invalid(self):
        dh = encryption.DiffieHellman()
        assert dh.check_public_key(1) is False

    def test_gen_secret_invalid_key_raises(self):
        dh = encryption.DiffieHellman()
        with pytest.raises(Exception, match="Invalid public key"):
            dh.gen_secret(dh.privateKey, 1)


class TestEd25519:
    def test_publickey_returns_32_bytes(self):
        pk = encryption.publickey_unsafe(urandom(32))
        assert len(pk) == 32  # noqa: PLR2004

    def test_sign_and_verify_roundtrip(self):
        sk = urandom(32)
        pk = encryption.publickey_unsafe(sk)
        message = b"test message"
        sig = encryption.signature_unsafe(message, sk, pk)
        assert encryption.checkvalid(sig, message, pk) is True

    def test_checkvalid_wrong_message(self):
        sk = urandom(32)
        pk = encryption.publickey_unsafe(sk)
        sig = encryption.signature_unsafe(b"original", sk, pk)
        assert encryption.checkvalid(sig, b"tampered", pk) is False

    def test_checkvalid_wrong_key(self):
        sk1 = urandom(32)
        pk2 = encryption.publickey_unsafe(urandom(32))
        sig = encryption.signature_unsafe(
            b"message", sk1, encryption.publickey_unsafe(sk1)
        )
        assert encryption.checkvalid(sig, b"message", pk2) is False
