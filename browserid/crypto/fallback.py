# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Crypto primitives implemented in pure python.

This file provides the "slow path" crypto implementation for PyBrowserID.
It implements everything in pure python, so it's very slow but very portable.

There is also a faster version built on M2Crypto, which should be picked up
automatically if you have that package installed.

"""

import os
from binascii import hexlify, unhexlify


class Key(object):
    """Generic base class for Key objects."""

    @classmethod
    def from_pem_data(cls, data=None, filename=None):
        """Alternative constructor for loading from PEM format data."""
        msg = "PEM data loading is not implemented for pure-python crypto."
        msg += "  Please install M2Crypto to access this functionality."
        raise NotImplementedError(msg)

    def to_pem_data(self):
        """Save the public key data to a PEM format string."""
        msg = "PEM data saving is not implemented for pure-python crypto."
        msg += "  Please install M2Crypto to access this functionality."
        raise NotImplementedError(msg)

    def verify(self, signed_data, signature):
        """Verify the given signature."""
        raise NotImplementedError

    def sign(self, data):
        """Sign the given data."""
        raise NotImplementedError


#  These constants are needed for encoding the name of the hash
#  algorithm into the RSA signature, per PKCS #1.
RSA_DIGESTINFO_HEADER = {
    "sha1": b"3021300906052b0e03021a05000414",
    "sha256": b"3031300d060960864801650304020105000420",
}


class RSKey(Key):
    """Generic base class for RSA key objects.

    Concrete subclasses should provide the DIGESTSIZE, HASHNAME and HASHMOD
    attributes.
    """

    # The size of the internal hex digest, in bytes.
    # This must equal the bit-length of the modulus "n" divided by 4.
    # The digest gets padded to this size to ensure that, when converted to
    # an integer, it will be of a similar magnitude to the modulus.
    DIGESTSIZE = None
    # The name and hashlib module to use for calculating the digest.
    HASHNAME = None
    HASHMOD = None

    def __init__(self, data):
        _check_keys(data, ("e", "n"))
        self.e = int(data["e"])
        self.n = int(data["n"])
        try:
            self.d = int(data["d"])
        except KeyError:
            self.d = None

    def verify(self, signed_data, signature):
        n, e = self.n, self.e
        m = int(hexlify(signature), 16)
        c = pow(m, e, n)
        digest = hex(c)[2:].rstrip("L").encode("ascii")
        padded_digest = digest.rjust(self.DIGESTSIZE, b"0")
        return padded_digest == self._get_digest(signed_data)

    def sign(self, data):
        n, e, d = self.n, self.e, self.d
        if not d:
            raise ValueError("private key not present")
        c = int(self._get_digest(data), 16)
        m = pow(c, d, n)
        return int2bytes(m)

    def _get_digest(self, data):
        digest = self.HASHMOD(data).hexdigest().encode("ascii")
        padded_digest = b"00" + RSA_DIGESTINFO_HEADER[self.HASHNAME] + digest
        padding_len = (self.DIGESTSIZE) - 4 - len(padded_digest)
        padded_digest = b"0001" + (b"f" * padding_len) + padded_digest
        return padded_digest


class DSKey(Key):
    """Generic base class for DSA key objects.

    Concrete subclasses should provide the BITLENGTH and HASHMOD attributes.
    """

    # The length of the signature to be produced, in bits.
    BITLENGTH = None
    # The hashlib module used to calculate the digest.
    HASHMOD = None

    def __init__(self, data):
        _check_keys(data, ("p", "q", "g", "y"))
        self.p = int(data["p"], 16)
        self.q = int(data["q"], 16)
        self.g = int(data["g"], 16)
        self.y = int(data["y"], 16)
        if "x" in data:
            self.x = int(data["x"], 16)
        else:
            self.x = None

    def verify(self, signed_data, signature):
        p, q, g, y = self.p, self.q, self.g, self.y
        signature = hexlify(signature)
        hexlength = self.BITLENGTH // 4
        signature = signature.rjust(hexlength * 2, b"0")
        if len(signature) != hexlength * 2:
            return False
        r = int(signature[:hexlength], 16)
        s = int(signature[hexlength:], 16)
        if r <= 0 or r >= q:
            return False
        if s <= 0 or s >= q:
            return False
        w = modinv(s, q)
        u1 = (int(self.HASHMOD(signed_data).hexdigest(), 16) * w) % q
        u2 = (r * w) % q
        v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
        return (v == r)

    def sign(self, data):
        p, q, g, y, x = self.p, self.q, self.g, self.y, self.x
        if not x:
            raise ValueError("private key not present")
        # We need to do lots of if-not-this-then-start-over type tests.
        # A while loop with continue statements is the cleanest way to do so.
        while True:
            k = int(hexlify(os.urandom(self.BITLENGTH // 8)), 16) % q
            if k == 0:
                continue
            r = pow(g, k, p) % q
            if r == 0:
                continue
            h = (int(self.HASHMOD(data).hexdigest(), 16) + (x * r)) % q
            s = (modinv(k, q) * h) % q
            if s == 0:
                continue
            break
        assert 0 < r < q
        assert 0 < s < q
        bytelength = self.BITLENGTH // 8
        r_bytes = int2bytes(r).rjust(bytelength, b"\x00")
        s_bytes = int2bytes(s).rjust(bytelength, b"\x00")
        return r_bytes + s_bytes


def modinv(a, m):
    """Find the modular inverse of a, with modulus m."""
    # This is a transliteration of the algorithm as it was described
    # to me by Wikipedia, using the Extended Euclidean Algorithm.
    x = 0
    lastx = 1
    y = 1
    lasty = 0
    b = m
    while b != 0:
        a, (q, b) = b, divmod(a, b)
        x, lastx = lastx - (q * x), x
        y, lasty = lasty - (q * y), y
    return lastx % m


def int2bytes(x):
    """Convert a Python integer to bigendian bytestring."""
    # It's faster to go via hex encoding in C code than it is to try
    # encoding directly into binary with a python-level loop.
    # (and hex-slice-strip seems consistently faster than using "%x" format)
    hexbytes = hex(x)[2:].rstrip("L").encode("ascii")
    if len(hexbytes) % 2:
        hexbytes = b"0" + hexbytes
    return unhexlify(hexbytes)


def _check_keys(data, keys):
    """Verify that the given data dict contains the specified keys."""
    for key in keys:
        if not key in data:
            msg = 'missing %s in data - %s' % (key, str(data.keys()))
            raise ValueError(msg)
