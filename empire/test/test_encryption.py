import hashlib
import hmac as hmac_mod
import pathlib
from os import urandom

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from empire.server.common import encryption
from empire.server.common import packets as pkt


class TestAES256GCM:
    def test_encrypt(self):
        cipher = encryption.AES256GCM(urandom(32))
        data = urandom(10)
        assert cipher.encrypt(urandom(12), data) != data

    def test_decrypt(self):
        cipher = encryption.AES256GCM(urandom(32))
        data = urandom(10)
        nonce = urandom(12)
        assert cipher.decrypt(nonce, cipher.encrypt(nonce, data)) == data

    def test_seal_open(self):
        cipher = encryption.AES256GCM(urandom(32))
        data = urandom(10)
        nonce = urandom(12)
        sealed = cipher.seal(nonce, data, "123")
        assert sealed != data
        assert cipher.open(nonce, sealed, "123") == data

    def test_invalid_key_length(self):
        with pytest.raises(ValueError, match="256 bit"):
            encryption.AES256GCM(urandom(16))

    def test_tampered_ciphertext_raises(self):
        cipher = encryption.AES256GCM(urandom(32))
        nonce = urandom(12)
        ct = cipher.encrypt(nonce, b"secret data")
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        with pytest.raises(encryption.TagInvalidException):
            cipher.decrypt(nonce, bytes(tampered))

    def test_output_format(self):
        """AES-GCM output should be ciphertext (same length as plaintext) + 16-byte tag."""
        cipher = encryption.AES256GCM(urandom(32))
        pt = urandom(16)
        ct = cipher.encrypt(urandom(12), pt)
        assert len(ct) == len(pt) + 16

    def test_empty_plaintext(self):
        """Empty plaintext produces only the 16-byte tag."""
        cipher = encryption.AES256GCM(urandom(32))
        ct = cipher.encrypt(urandom(12), b"", None)
        assert len(ct) == 16  # noqa: PLR2004  tag only

    def test_non_block_aligned_plaintext(self):
        """Non-16-byte-aligned plaintext works correctly."""
        cipher = encryption.AES256GCM(urandom(32))
        pt = urandom(7)
        nonce = urandom(12)
        ct = cipher.encrypt(nonce, pt)
        assert cipher.decrypt(nonce, ct) == pt
        assert len(ct) == 7 + 16

    def test_aad_mismatch_raises(self):
        """Decryption with different AAD raises TagInvalidException."""
        cipher = encryption.AES256GCM(urandom(32))
        nonce = urandom(12)
        sealed = cipher.seal(nonce, b"data", "correct_aad")
        with pytest.raises(encryption.TagInvalidException):
            cipher.open(nonce, sealed, "wrong_aad")

    def test_multiple_routing_packets(self):
        """Build and parse multiple concatenated routing packets."""
        staging_key = "C" * 32
        pkt1 = pkt.build_routing_packet(
            staging_key, "SESS0001", "python", meta="STAGE0", encData=b"data1"
        )
        pkt2 = pkt.build_routing_packet(
            staging_key,
            "SESS0002",
            "powershell",
            meta="TASKING_REQUEST",
            encData=b"data2",
        )
        combined = pkt1 + pkt2
        result = pkt.parse_routing_packet(staging_key, combined)
        assert result is not None
        assert "SESS0001" in result
        assert "SESS0002" in result
        assert result["SESS0001"][3] == b"data1"
        assert result["SESS0002"][3] == b"data2"


class TestAESGCMInterop:
    """Cross-implementation tests: server (cryptography lib) vs agent (pure Python)."""

    @staticmethod
    def _load_agent_aesgcm():
        """Load the pure-Python AES256GCM from the agent stager code."""
        ns = {}
        stager_common = pathlib.Path("empire/server/listeners/common")
        exec(
            compile((stager_common / "aes.py.j2").read_text(), "aes.py.j2", "exec"), ns
        )
        exec(
            compile(
                (stager_common / "aesgcm.py.j2").read_text(), "aesgcm.py.j2", "exec"
            ),
            ns,
        )
        return ns["AES256GCM"]

    def test_server_encrypt_agent_decrypt(self):
        """Server encrypts with cryptography lib, agent decrypts with pure Python."""
        AgentAES256GCM = self._load_agent_aesgcm()
        key = urandom(32)
        nonce = urandom(12)
        plaintext = urandom(16)

        server_cipher = encryption.AES256GCM(key)
        ct = server_cipher.seal(nonce, plaintext, b"")

        agent_cipher = AgentAES256GCM(key)
        pt = agent_cipher.open(nonce, ct, b"")
        assert pt == plaintext

    def test_agent_encrypt_server_decrypt(self):
        """Agent encrypts with pure Python, server decrypts with cryptography lib."""
        AgentAES256GCM = self._load_agent_aesgcm()
        key = urandom(32)
        nonce = urandom(12)
        plaintext = urandom(16)

        agent_cipher = AgentAES256GCM(key)
        ct = agent_cipher.seal(nonce, plaintext, b"")

        server_cipher = encryption.AES256GCM(key)
        pt = server_cipher.open(nonce, ct, b"")
        assert pt == plaintext

    def test_identical_ciphertext(self):
        """Both implementations produce byte-identical output."""
        AgentAES256GCM = self._load_agent_aesgcm()
        key = urandom(32)
        nonce = urandom(12)
        plaintext = urandom(16)

        server_ct = encryption.AES256GCM(key).seal(nonce, plaintext, b"")
        agent_ct = AgentAES256GCM(key).seal(nonce, plaintext, b"")
        assert server_ct == agent_ct

    def test_interop_with_various_sizes(self):
        """Test interop with empty, small, and non-block-aligned plaintexts."""
        AgentAES256GCM = self._load_agent_aesgcm()
        key = urandom(32)

        for size in [0, 1, 7, 15, 16, 17, 31, 32, 33, 100]:
            nonce = urandom(12)
            plaintext = urandom(size)

            server_ct = encryption.AES256GCM(key).seal(nonce, plaintext, b"")
            agent_ct = AgentAES256GCM(key).seal(nonce, plaintext, b"")
            assert server_ct == agent_ct, f"Mismatch at size {size}"

            # Cross-decrypt
            assert AgentAES256GCM(key).open(nonce, server_ct, b"") == plaintext
            assert encryption.AES256GCM(key).open(nonce, agent_ct, b"") == plaintext


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

    def test_hmac_is_16_bytes(self):
        """HMAC truncation must be 16 bytes (128 bits) per FIPS SP 800-107."""
        key = urandom(32)
        data = b"test data for hmac"
        ct_hmac = encryption.AESCipher.encrypt_then_hmac(key, data)
        ct_only = encryption.AESCipher.encrypt(key, data)
        hmac_len = len(ct_hmac) - len(ct_only)
        assert hmac_len == 16  # noqa: PLR2004

    def test_old_10_byte_hmac_rejected(self):
        """Data with a 10-byte HMAC (old format) must fail verification."""
        key = urandom(32)
        ct = encryption.AESCipher.encrypt(key, b"payload")
        old_mac = hmac_mod.new(key, ct, digestmod=hashlib.sha256).digest()[0:10]
        old_format = ct + old_mac
        assert encryption.AESCipher.verify_hmac(key, old_format) is False

    def test_tampered_hmac_rejected(self):
        """Flipping a byte in the HMAC must fail verification."""
        key = urandom(32)
        ct_hmac = encryption.AESCipher.encrypt_then_hmac(key, b"data")
        tampered = bytearray(ct_hmac)
        tampered[-1] ^= 0xFF
        assert encryption.AESCipher.verify_hmac(key, bytes(tampered)) is False

    def test_decrypt_and_verify_rejects_old_10_byte_hmac(self):
        """decrypt_and_verify must reject data with old 10-byte HMAC."""
        key = urandom(32)
        plaintext = b"A" * 64
        ct = encryption.AESCipher.encrypt(key, plaintext)
        old_mac = hmac_mod.new(key, ct, digestmod=hashlib.sha256).digest()[0:10]
        with pytest.raises(Exception, match="Invalid ciphertext"):
            encryption.AESCipher.decrypt_and_verify(key, ct + old_mac)

    def test_verify_hmac_boundary_at_32_bytes(self):
        """Data of exactly 32 bytes must return False (too short for IV + ct + 16B HMAC)."""
        assert encryption.AESCipher.verify_hmac(urandom(16), urandom(32)) is False

    def test_generate_key(self):
        key = encryption.AESCipher.generate_key()
        assert isinstance(key, str)
        assert len(key) == 64  # noqa: PLR2004  hex-encoded 32 bytes
        raw = bytes.fromhex(key)
        assert len(raw) == 32  # noqa: PLR2004

    def test_generate_key_unique(self):
        """Each call should produce a different key."""
        keys = {encryption.AESCipher.generate_key() for _ in range(10)}
        assert len(keys) == 10  # noqa: PLR2004

    def test_generate_key_is_valid_hex(self):
        """Key must be valid hex (compatible with bytes.fromhex used in agent_communication_service)."""
        key = encryption.AESCipher.generate_key()
        try:
            bytes.fromhex(key)
        except ValueError:
            pytest.fail(f"generate_key() returned non-hex string: {key!r}")

    def test_generate_key_encrypt_decrypt_roundtrip(self):
        """Generated key works through the full bytes.fromhex -> encrypt -> decrypt path."""
        key_hex = encryption.AESCipher.generate_key()
        key_bytes = bytes.fromhex(key_hex)
        plaintext = b"agent checkin data"
        ct = encryption.AESCipher.encrypt_then_hmac(key_bytes, plaintext)
        assert encryption.AESCipher.decrypt_and_verify(key_bytes, ct) == plaintext


class TestHMACInterop:
    """Cross-implementation tests: server (cryptography lib) vs agent (pure Python aes.py)."""

    @staticmethod
    def _load_agent_aes():
        """Load the pure-Python AES functions from the agent stager code."""
        ns = {}
        stager_common = pathlib.Path("empire/server/listeners/common")
        exec(
            compile((stager_common / "aes.py.j2").read_text(), "aes.py.j2", "exec"), ns
        )
        return ns

    def test_server_encrypt_agent_decrypt(self):
        """Server encrypts with cryptography lib, agent decrypts with pure Python."""
        ns = self._load_agent_aes()
        key = urandom(32)
        data = b"cross implementation test"

        server_ct = encryption.AESCipher.encrypt_then_hmac(key, data)
        assert ns["verify_hmac"](key, server_ct) is True
        agent_pt = ns["aes_decrypt_and_verify"](key, server_ct)
        assert agent_pt.encode("latin-1") == data

    def test_agent_encrypt_server_decrypt(self):
        """Agent encrypts with pure Python, server decrypts with cryptography lib."""
        ns = self._load_agent_aes()
        key = urandom(32)
        data = b"cross implementation test"

        agent_ct = ns["aes_encrypt_then_hmac"](key, data)
        assert encryption.AESCipher.verify_hmac(key, agent_ct) is True
        server_pt = encryption.AESCipher.decrypt_and_verify(key, agent_ct)
        assert server_pt == data

    def test_both_produce_16_byte_hmac(self):
        """Both implementations use 16-byte HMAC truncation."""
        ns = self._load_agent_aes()
        key = urandom(32)
        data = b"hmac length check"

        server_ct = encryption.AESCipher.encrypt_then_hmac(key, data)
        agent_ct = ns["aes_encrypt_then_hmac"](key, data)

        server_ct_only = encryption.AESCipher.encrypt(key, data)
        agent_ct_only = ns["aes_encrypt"](key, data)

        assert len(server_ct) - len(server_ct_only) == 16  # noqa: PLR2004
        assert len(agent_ct) - len(agent_ct_only) == 16  # noqa: PLR2004


class TestKeySeparation:
    """Anchor the HKDF subkey derivation the four agent languages reimplement.

    Every agent (PowerShell, pure-Python, Go, C#) carries a "must stay
    byte-for-byte identical to the server" HKDF copy. A known-answer test on the
    server's derive_subkeys freezes the reference so any drift is caught here.
    """

    # Vector pinned from encryption.derive_subkeys for this exact staging key.
    STAGING_KEY = b"A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"
    K_ENC = bytes.fromhex(
        "ada8f0de28d9f85fdbe4fe6ccfe6ca672b099c33337fc57963d77902fba662f2"
    )
    K_MAC = bytes.fromhex(
        "f5b2eb12697950678051a9eb797cbc960e56a675f200e5741370dbdda00aa4fc"
    )

    def test_known_answer(self):
        k_enc, k_mac = encryption.derive_subkeys(self.STAGING_KEY)
        assert k_enc == self.K_ENC
        assert k_mac == self.K_MAC

    def test_subkeys_are_distinct_and_not_the_input(self):
        k_enc, k_mac = encryption.derive_subkeys(self.STAGING_KEY)
        assert len(k_enc) == 32  # noqa: PLR2004
        assert len(k_mac) == 32  # noqa: PLR2004
        assert k_enc != k_mac
        assert k_enc != self.STAGING_KEY
        assert k_mac != self.STAGING_KEY

    def test_str_and_bytes_keys_agree(self):
        # The server passes a str staging key and bytes session keys through the
        # same helper; both must derive the same subkeys.
        from_bytes = encryption.derive_subkeys(self.STAGING_KEY)
        from_str = encryption.derive_subkeys(self.STAGING_KEY.decode("UTF-8"))
        assert from_bytes == from_str

    def test_agent_python_hkdf_matches_server(self):
        # The pure-Python agent (aes.py.j2) must derive identical subkeys.
        ns = {}
        stager_common = pathlib.Path("empire/server/listeners/common")
        exec(
            compile((stager_common / "aes.py.j2").read_text(), "aes.py.j2", "exec"),
            ns,
        )
        agent_enc, agent_mac = ns["derive_subkeys"](self.STAGING_KEY)
        assert agent_enc == self.K_ENC
        assert agent_mac == self.K_MAC


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

    def test_hkdf_key_is_32_bytes(self):
        """HKDF-derived key should be exactly 32 bytes (256 bits)."""
        dh = encryption.DiffieHellman()
        other = encryption.DiffieHellman()
        dh.gen_key(other.publicKey)
        assert len(dh.getKey()) == 32  # noqa: PLR2004


class TestDiffieHellmanInterop:
    """Cross-implementation tests: server vs agent stager DH + HKDF."""

    @staticmethod
    def _load_agent_dh():
        ns = {}
        stager_common = pathlib.Path("empire/server/listeners/common")
        exec(
            compile(
                (stager_common / "diffiehellman.py.j2").read_text(),
                "diffiehellman.py.j2",
                "exec",
            ),
            ns,
        )
        return ns["DiffieHellman"]

    def test_server_agent_hkdf_interop(self):
        """Server and agent stager must derive identical keys via HKDF."""
        AgentDH = self._load_agent_dh()
        server_dh = encryption.DiffieHellman()
        agent_dh = AgentDH()

        server_dh.gen_key(agent_dh.publicKey)
        agent_dh.genKey(server_dh.publicKey)

        assert server_dh.getKey() == agent_dh.getKey()

    def test_hkdf_known_answer_vector(self):
        """Pin HKDF output for a known shared secret — use this vector in Go/C# tests.

        shared_secret=42, normalized to 768 bytes big-endian, salt=zeros(32),
        info=b"empire-session-key", length=32.
        """
        ikm = (42).to_bytes(768, "big")
        server_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=b"empire-session-key"
        ).derive(ikm)

        # Agent stager hand-rolled HKDF (hmac-based, IronPython compatible)
        salt = b"\x00" * 32
        prk = hmac_mod.new(salt, ikm, hashlib.sha256).digest()
        agent_key = hmac_mod.new(
            prk, b"empire-session-key" + b"\x01", hashlib.sha256
        ).digest()

        assert server_key == agent_key
        assert len(server_key) == 32  # noqa: PLR2004
        assert (
            server_key.hex()
            == "3013cbac5ff612b04092859f41f025db39b4ef21b9a742826d0baf7fa3eb5016"
        )


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
