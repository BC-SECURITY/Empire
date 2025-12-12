from os import urandom

from empire.server.common import encryption


class TestPoly1305:
    def test_divceil(self):
        assert encryption.divceil(13, 5) == 3  # noqa: PLR2004
        assert encryption.divceil(15, 5) == 3  # noqa: PLR2004

    def test_create_tag(self):
        self.key = urandom(32)
        self.poly1305 = encryption.Poly1305(self.key)
        data = urandom(16)
        tag = self.poly1305.create_tag(data)
        new_tag_false = self.poly1305.create_tag(urandom(16))
        new_tag_true = self.poly1305.create_tag(data)
        assert tag != new_tag_false
        assert new_tag_true == tag


class TestChaCha20:
    def test_encrypt(self):
        self.key = urandom(32)
        self.poly1305 = encryption.Poly1305(self.key)
        self.chacha20 = encryption.ChaCha(self.key, urandom(12))
        data = urandom(10)
        encrypted = self.chacha20.encrypt(data)
        assert data != encrypted

    def test_decrypt(self):
        self.key = urandom(32)
        self.poly1305 = encryption.Poly1305(self.key)
        self.chacha20 = encryption.ChaCha(self.key, urandom(12))
        data = urandom(10)
        encrypted = self.chacha20.encrypt(data)
        decrypted = self.chacha20.decrypt(encrypted)
        assert decrypted == data


class TestChaCha20Poly1305:
    def test_encrypt(self):
        self.key = urandom(32)
        self.poly1305 = encryption.Poly1305(self.key)
        self.chacha20poly1305 = encryption.ChaCha20Poly1305(self.key)
        data = urandom(10)
        encrypted = self.chacha20poly1305.encrypt(urandom(12), data)
        assert data != encrypted

    def test_decrypt(self):
        self.key = urandom(32)
        self.poly1305 = encryption.Poly1305(self.key)
        self.chacha20poly1305 = encryption.ChaCha20Poly1305(self.key)
        data = urandom(10)
        nonce = urandom(12)
        encrypted = self.chacha20poly1305.encrypt(nonce, data)
        decrypted = self.chacha20poly1305.decrypt(nonce, encrypted)
        assert decrypted == data

    def test_seal(self):
        self.key = urandom(32)
        self.poly1305 = encryption.Poly1305(self.key)
        self.chacha20poly1305 = encryption.ChaCha20Poly1305(self.key)
        data = urandom(10)
        nonce = urandom(12)
        hmac_encrypted = self.chacha20poly1305.seal(nonce, data, "123")
        assert data != hmac_encrypted

    def test_unseal(self):
        self.key = urandom(32)
        self.poly1305 = encryption.Poly1305(self.key)
        self.chacha20poly1305 = encryption.ChaCha20Poly1305(self.key)
        data = urandom(10)
        nonce = urandom(12)
        hmac_encrypted = self.chacha20poly1305.seal(nonce, data, "123")
        hmac_decrypted = self.chacha20poly1305.open(nonce, hmac_encrypted, "123")
        assert hmac_decrypted == data
