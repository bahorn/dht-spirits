"""
False positive rate is lower than the calculated one as some x values aren't on
the curve, though we want this to be rare else we'll be easy to detect.

* https://mvalvekens.be/blog/2022/ecc-point-compression.html
"""
import base64
import binascii
import sys
import json
import secrets
import math
import tinyec.ec as ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from tinyec import registry
from util import modular_sqrt

SECRET = b'random_secret'
LENGTH = 20


def gen_curve(j):
    p = int(j['field']['p'], 16)
    x = int(j['subgroups'][0]['x'], 16)
    y = int(j['subgroups'][0]['y'], 16)
    order = int(j['subgroups'][0]['order'], 16)
    field = ec.SubGroup(p, (x, y), order, 1)

    curve = ec.Curve(int(j['a'], 16), int(j['b'], 16), field)
    return curve


def compress(point, include_odd=True):
    """
    Compress a curve point.
    """
    p = point.curve.field.p
    # determine how many bytes this curve needs to represent a point.
    count = math.ceil(math.ceil(math.log2(p)) / 8)

    top = b''
    if include_odd:
        top = bytes([0x32 if (point.y % 2 == 0) else 0x33])
    else:
        assert point.y % 2 == 0

    res = point.x.to_bytes(count, byteorder='big', signed=False)

    return top + res


def decompress(curve, compressed, include_odd=True):
    """
    Decompress a curve point
    """
    if include_odd and compressed[0] not in [0x32, 0x33]:
        raise Exception('Invalid Point, missing label')
    # This is just a hack to save a byte if we make the y always even
    s = 0
    if include_odd and compressed[0] == 0x33:
        s = 1

    start = 1 if include_odd else 0

    x = int.from_bytes(compressed[start:], byteorder='big', signed=False)

    if x >= curve.field.p - 1:
        raise Exception('Invalid point, larger than p - 1')

    y_ = modular_sqrt(x**3 + x * curve.a + curve.b, curve.field.p)

    if s == (y_ % 2):
        res = ec.Point(curve, x, y_)
    else:
        res = ec.Point(curve, x, curve.field.p - y_)

    if not res.on_curve:
        raise Exception('Invalid Point, not on curve')

    return res


class ECKey:
    def __init__(self, curve=None, key=None, include_odd=False):
        if curve:
            self._curve = curve
        else:
            self._curve = registry.get_curve('brainpoolP256r1')

        self._include_odd = include_odd

        if key:
            self._privkey = key
            self._pubkey = self._privkey * self._curve.g
        else:
            self.gen_key()

    def gen_key(self):
        """
        Generate a key that conforms to the requirements.
        """
        self._privkey = secrets.randbelow(self._curve.field.n)
        self._pubkey = self._privkey * self._curve.g

        while not self._include_odd and (self._pubkey.y % 2) != 0:
            self._privkey = secrets.randbelow(self._curve.field.n)
            self._pubkey = self._privkey * self._curve.g

    def pubkey(self):
        return compress(self._pubkey, include_odd=self._include_odd)

    def share_key(self, pubkey):
        """
        Just deriving a shared secret.
        """
        peer = decompress(
            self._curve,
            pubkey,
            include_odd=self._include_odd
        )

        return self._privkey * peer


class Identify:
    def __init__(self, curve, key=None, secret=SECRET, length=LENGTH):
        self._ec = ECKey(curve, key=key, include_odd=False)
        self._length = length
        self._secret = secret

    def pubkey(self):
        return self._ec.pubkey()

    def get_hash(self, peer, length):
        shared_key = compress(self._ec.share_key(peer))
        dervied_key = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=self._secret
        ).derive(shared_key)
        return dervied_key

    def gen(self, peer):
        pubkey = self.pubkey()
        length = self._length - len(pubkey)
        token = self.get_hash(peer, length)
        return pubkey + token

    def verify(self, combo):
        length = len(self.pubkey())
        pubkey, hash = combo[:length], combo[length:]
        return self.get_hash(pubkey, length=len(hash)) == hash


def step(curve):
    a = Identify(curve)
    b = Identify(curve)
    c = Identify(curve)
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


def test_decompress(curve):
    # tinyec outputs warnings if a point is not on the curve
    import warnings
    warnings.filterwarnings("ignore")
    c = 0
    for i in range(1000):
        try:
            decompress(curve, secrets.token_bytes(15), False)
            c += 1
        except Exception:
            continue
    print(c)
    warnings.filterwarnings("default")


def main():
    # using a custom curve we generated
    curve = gen_curve(json.load(open(sys.argv[1])))

    test_decompress(curve)

    for i in range(32):
        step(curve)


if __name__ == "__main__":
    main()
