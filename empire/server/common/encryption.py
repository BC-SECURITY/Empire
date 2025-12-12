import hashlib
import hmac
import logging
import os
import random
import ssl
import string
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey as _Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey as _Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305 as LibChaCha20Poly1305,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

log = logging.getLogger(__name__)

random_function = ssl.RAND_bytes
random_provider = "Python SSL"
ct_compare_digest = hmac.compare_digest


def to_bufferable(binary):
    if isinstance(binary, bytes):
        return binary
    return bytes(ord(b) for b in binary)


def _get_byte(c):
    return c


class AESCipher:
    """
    Cohesive namespace for AES/HMAC utilities.
    Prefer using these class methods over the legacy module-level functions
    which are kept for backward compatibility.
    """

    @staticmethod
    def pad(data):
        """Performs PKCS#7 padding for 128 bit block size."""
        pad = 16 - (len(data) % 16)
        return b"".join([data, to_bufferable(chr(pad).encode("UTF-8") * pad)])

    @staticmethod
    def depad(data):
        """Performs PKCS#7 depadding for 128 bit block size."""
        if len(data) % 16 != 0:
            raise ValueError("invalid length")

        pad = _get_byte(data[-1])
        return data[:-pad]

    @staticmethod
    def encrypt(key, data):
        """Encrypt with random IV (CBC) and return IV+ciphertext."""
        backend = default_backend()
        IV = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
        encryptor = cipher.encryptor()
        ct = encryptor.update(AESCipher.pad(data)) + encryptor.finalize()
        return IV + ct

    @staticmethod
    def encrypt_then_hmac(key, data):
        """Encrypt the data then calculate HMAC over the ciphertext."""

        data = AESCipher.encrypt(key, data)
        mac = hmac.new(key, data, digestmod=hashlib.sha256).digest()
        return data + mac[0:10]

    @staticmethod
    def decrypt(key, data):
        """Decrypt IV+ciphertext (CBC) and depad."""
        if len(data) > 16:  # noqa: PLR2004
            backend = default_backend()
            IV = data[0:16]
            cipher = Cipher(algorithms.AES(key), modes.CBC(IV), backend=backend)
            decryptor = cipher.decryptor()
            return AESCipher.depad(decryptor.update(data[16:]) + decryptor.finalize())
        raise ValueError("Data length must be larger then 16")

    @staticmethod
    def verify_hmac(key, data):
        """Verify the truncated (10-byte) SHA-256 HMAC.
        Returns True/False.
        """

        if len(data) > 20:  # noqa: PLR2004
            mac = data[-10:]
            data_ = data[:-10]
            expected = hmac.new(key, data_, digestmod=hashlib.sha256).digest()[0:10]
            return (
                hmac.new(key, expected, digestmod=hashlib.sha256).digest()
                == hmac.new(key, mac, digestmod=hashlib.sha256).digest()
            )
        return False

    @staticmethod
    def decrypt_and_verify(key, data):
        """Decrypt the data, but only if it has a valid MAC."""
        if len(data) > 32 and AESCipher.verify_hmac(key, data):  # noqa: PLR2004
            return AESCipher.decrypt(key, data[:-10])
        raise Exception("Invalid ciphertext received.")

    @staticmethod
    def generate_key():
        """Generate a random new 128-bit AES key using OS RNG."""
        rng = random.SystemRandom()
        return "".join(
            rng.sample(
                string.ascii_letters
                + string.digits
                + r"!#$%&()*+,-./:;<=>?@[\]^_`{|}~",
                32,
            )
        )


class DiffieHellman:
    """
    A reference implementation of the Diffie-Hellman protocol.
    By default, this class uses the 6144-bit MODP Group (Group 17) from RFC 3526.
    This prime is sufficient to generate an AES 256 key when used with
    a 540+ bit exponent.

    Authored by Mark Loiseau's implementation at https://github.com/lowazo/pyDHE
        version 3.0 of the GNU General Public License
        see ./data/licenses/pyDHE_license.txt for license info

    Also used in ./data/agent/stager.py for the Python key-negotiation stager
    """

    def __init__(self, generator=2, group=17, keyLength=540):
        """
        Generate the public and private keys.
        """
        min_keyLength = 180

        default_generator = 2
        valid_generators = [2, 3, 5, 7]

        if generator not in valid_generators:
            log.error("Error: Invalid generator. Using default.")
            self.generator = default_generator
        else:
            self.generator = generator

        if keyLength < min_keyLength:
            log.error("Error: keyLength is too small. Setting to minimum.")
            self.keyLength = min_keyLength
        else:
            self.keyLength = keyLength

        self.prime = self.get_prime(group)

        self.privateKey = self.gen_private_key(keyLength)
        self.publicKey = self.gen_public_key()

    def get_prime(self, group=17):
        """
        Given a group number, return a prime.
        """
        default_group = 17

        primes = {
            5: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF,
            14: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
            15: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF,
            16: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF,
            17: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF,
            18: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF,
        }

        if group in list(primes.keys()):
            return primes[group]

        log.error(f"Error: No prime with group {group:d}. Using default.")
        return primes[default_group]

    def gen_random(self, bits):
        """
        Generate a random number with the specified number of bits
        """
        _rand = 0
        _bytes = bits // 8 + 8

        while len(bin(_rand)) - 2 < bits:
            try:
                # Python 3
                _rand = int.from_bytes(random_function(_bytes), byteorder="big")
            except Exception:
                # Python 2
                _rand = int(random_function(_bytes).encode("hex"), 16)

        return _rand

    def gen_private_key(self, bits):
        """
        Generate a private key using a secure random number generator.
        """
        return self.gen_random(bits)

    def gen_public_key(self):
        """
        Generate a public key X with g**x % p.
        """
        return pow(self.generator, self.privateKey, self.prime)

    def check_public_key(self, otherKey):
        """
        Check the other party's public key to make sure it's valid.
        Since a safe prime is used, verify that the Legendre symbol == 1
        """
        return bool(
            otherKey > 2  # noqa: PLR2004
            and otherKey < self.prime - 1
            and pow(otherKey, (self.prime - 1) // 2, self.prime) == 1
        )

    def gen_secret(self, privateKey, otherKey):
        """
        Check to make sure the public key is valid, then combine it with the
        private key to generate a shared secret.
        """
        if self.check_public_key(otherKey) is True:
            return pow(otherKey, privateKey, self.prime)
        raise Exception("Invalid public key.")

    def gen_key(self, otherKey):
        """
        Derive the shared secret, then hash it to obtain the shared key.
        """
        self.sharedSecret = self.gen_secret(self.privateKey, otherKey)

        # Convert the shared secret (int) to an array of bytes in network order
        # Otherwise hashlib can't hash it.
        try:
            bin_str = bin(self.sharedSecret)[2:].zfill(6147)
            _sharedSecretBytes = int(bin_str, 2).to_bytes(len(bin_str), "big")
        except AttributeError:
            _sharedSecretBytes = str(self.sharedSecret)

        s = hashlib.sha256()
        s.update(bytes(_sharedSecretBytes))

        self.key = s.digest()

    def getKey(self):
        """
        Return the shared secret key
        """
        return self.key


def divceil(divident, divisor):
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))


class Poly1305:
    """Poly1305 authenticator

    Authored by Dušan Klinec's implementation at https://github.com/ph4r05/py-chacha20poly1305
    """

    P = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB  # 2^130-5

    @staticmethod
    def le_bytes_to_num(data):
        """Convert a number from little endian byte format"""
        ret = 0
        for i in range(len(data) - 1, -1, -1):
            ret <<= 8
            ret += data[i]
        return ret

    @staticmethod
    def num_to_16_le_bytes(num):
        """Convert number to 16 bytes in little endian format"""
        ret = [0] * 16
        for i, _ in enumerate(ret):
            ret[i] = num & 0xFF
            num >>= 8
        return bytearray(ret)

    def __init__(self, key):
        """Set the authenticator key"""
        key_byte_length = 32  # 32 bytes
        if len(key) != key_byte_length:
            raise ValueError("Key must be 256 bit long")
        self.acc = 0
        self.r = self.le_bytes_to_num(key[0:16])
        self.r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
        self.s = self.le_bytes_to_num(key[16:32])

    def create_tag(self, data):
        """Calculate authentication tag for data deterministically for the given key and data.
        This method must not mutate internal accumulator state so repeated calls with the same
        inputs return the same tag.
        """
        acc = 0
        for i in range(0, divceil(len(data), 16)):
            n = self.le_bytes_to_num(data[i * 16 : (i + 1) * 16] + b"\x01")
            acc += n
            acc = (self.r * acc) % self.P
        acc += self.s
        return self.num_to_16_le_bytes(acc)


class ChaCha:
    """Wrapper around cryptography's ChaCha20 stream cipher.
    Preserves existing API (key, nonce, counter=0, rounds=20) but ignores rounds.
    Nonce must be 12 bytes; we combine with 4-byte little-endian counter to form
    the 16-byte nonce required by cryptography's ChaCha20 implementation.
    """

    def __init__(self, key, nonce, counter=0, rounds=20):
        key_byte_length = 32
        if len(key) != key_byte_length:
            raise ValueError("Key must be 256 bit long")

        nonce_byte_length = 12
        if len(nonce) != nonce_byte_length:
            raise ValueError("Nonce must be 96 bit long")

        self.key = key
        self.nonce = nonce
        self.counter = counter & 0xFFFFFFFF
        self.rounds = rounds

    def _construct_nonce16(self, block_counter=0):
        ctr = (self.counter + block_counter) & 0xFFFFFFFF
        return struct.pack("<I", ctr) + self.nonce

    def _cipher(self, nonce16):
        algorithm = algorithms.ChaCha20(self.key, nonce16)
        return Cipher(algorithm, mode=None, backend=default_backend())

    def encrypt(self, plaintext):
        nonce16 = self._construct_nonce16(0)
        encryptor = self._cipher(nonce16).encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def key_stream(self, counter):
        # Generate 64 bytes of keystream for the given block index for compatibility
        nonce16 = self._construct_nonce16(counter)
        encryptor = self._cipher(nonce16).encryptor()
        return bytearray(encryptor.update(b"\x00" * 64) + encryptor.finalize())

    def decrypt(self, ciphertext):
        nonce16 = self._construct_nonce16(0)
        decryptor = self._cipher(nonce16).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class TagInvalidException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class ChaCha20Poly1305:
    """Wrapper around cryptography's ChaCha20Poly1305 AEAD cipher.

    Replaces the previous pure-Python implementation with the standard library
    from cryptography.hazmat.primitives.ciphers.aead.
    Preserves the existing API: encrypt/decrypt and seal/open.
    """

    def __init__(self, key, implementation="python"):
        key_byte_length = 32
        if len(key) != key_byte_length:
            raise ValueError("Key must be 256 bit long")

        self.isBlockCipher = False
        self.isAEAD = True
        self.nonceLength = 12
        self.tagLength = 16
        self.implementation = implementation
        self.name = "chacha20-poly1305"
        self.key = key
        self._aead = LibChaCha20Poly1305(key)

    def _to_bytes(self, associated_data):
        if associated_data is None:
            return None
        if isinstance(associated_data, str):
            return associated_data.encode("utf-8")
        return associated_data

    def encrypt(self, nonce, plaintext, associated_data=None):
        ad = self._to_bytes(associated_data)
        return self._aead.encrypt(nonce, plaintext, ad)

    def decrypt(self, nonce, ciphertext, associated_data=None):
        ad = self._to_bytes(associated_data)
        try:
            return self._aead.decrypt(nonce, ciphertext, ad)
        except Exception as err:
            raise TagInvalidException from err

    def seal(self, nonce, plaintext, data):
        ad = self._to_bytes(data)
        return self._aead.encrypt(nonce, plaintext, ad)

    def open(self, nonce, ciphertext, data):
        ad = self._to_bytes(data)
        try:
            return self._aead.decrypt(nonce, ciphertext, ad)
        except Exception as err:
            raise TagInvalidException from err


class SignatureMismatch(Exception):
    pass


def publickey_unsafe(sk: bytes) -> bytes:
    """Derive a public key from a 32-byte Ed25519 seed using cryptography.

    Parameters:
        sk (bytes): 32-byte private key seed (raw). Use .private_bytes_raw() to obtain.
    Returns:
        bytes: 32-byte public key in raw format.
    """
    priv = _Ed25519PrivateKey.from_private_bytes(bytes(sk))
    pub = priv.public_key()
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


def signature_unsafe(m: bytes, sk: bytes, pk: bytes) -> bytes:
    """Create a detached Ed25519 signature using cryptography.

    Parameters:
        m (bytes): Message to sign.
        sk (bytes): 32-byte private key seed.
        pk (bytes): Public key (ignored, kept for API compatibility).
    Returns:
        bytes: 64-byte signature.
    """
    priv = _Ed25519PrivateKey.from_private_bytes(bytes(sk))
    return priv.sign(bytes(m))


def checkvalid(s: bytes, m: bytes, pk: bytes) -> bool:
    """Verify an Ed25519 signature using cryptography.

    Returns True if valid, False otherwise.
    """
    try:
        _Ed25519PublicKey.from_public_bytes(bytes(pk)).verify(bytes(s), bytes(m))
        return True
    except Exception:
        return False
