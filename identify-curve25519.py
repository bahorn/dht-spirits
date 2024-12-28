"""
Idea here is to use ECDH to create a value that can act as an identifier that
only someone with the private keys can check if its valid.
This is meant to be for things like generating IDs in p2p networks, so you can
identify nodes, without them being able to tell who you are.

You can also technically just use RSA encryption, but that sucks and requires
more space.

By controlling how much of the hash you output you can control the amount of
false positives you get.
False negatives shouldn't be possible.

Overhead is 32 bytes for the pubkey you generated and how many bytes you want
to use to avoid false positives.

With weaker primitives (and tbh 2^40 is beyond what you'd want to do on any
random id you see) you can get this to work with a mainline DHT node id.
Just not sure what curves work for that.

Essentially what we are trying to construct is a authentication tag scheme
based on public key crypto instead of the more normal secret key approach.
"""
import binascii
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import \
        X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SECRET = b'random_secret'
LENGTH = 32


class Identify:
    KEYLEN = 32

    def __init__(self, key=None, secret=SECRET, length=LENGTH):
        self._private_key = X25519PrivateKey.generate()
        if key is not None:
            X25519PrivateKey.from_private_bytes(key)
        self._public_key = self._private_key.public_key()
        self._length = length
        self._secret = secret

    def pubkey(self):
        """
        Return the public key as a byte array
        """
        return self._public_key.public_bytes_raw()

    def get_hash(self, peer):
        b = X25519PublicKey.from_public_bytes(peer)
        shared_key = self._private_key.exchange(b)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=self._length,
            salt=None,
            info=self._secret,
        ).derive(shared_key)
        return derived_key

    def gen(self, peer):
        """
        Generate an token that can be used to identify.
        """
        return self.pubkey() + self.get_hash(peer)

    def verify(self, combo):
        pubkey, hash = combo[:self.KEYLEN], combo[self.KEYLEN:]
        return self.get_hash(pubkey) == hash


def step():
    a = Identify()
    b = Identify()
    c = Identify()
    a_p = a.pubkey()
    b_p = b.pubkey()
    c_p = c.pubkey()
    print(
        binascii.hexlify(a.gen(b_p)).decode('ascii'),
        base64.b64encode(a.gen(b_p)).decode('ascii')
    )
    assert b.verify(a.gen(b_p))
    assert a.verify(b.gen(a_p))
    assert not a.verify(b.gen(c_p))


def main():
    for i in range(32):
        step()


if __name__ == "__main__":
    main()
