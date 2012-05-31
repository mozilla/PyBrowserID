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
from binascii import unhexlify


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
    "sha1": "3021300906052b0e03021a05000414",
    "sha256": "3031300d060960864801650304020105000420",
}


class RSKey(Key):
    """Generic base class for RSA key objects.

    Concrete subclasses should provide the SIZE, HASHNAME and HASHMOD
    attributes.
    """

    SIZE = None
    HASHNAME = None
    HASHMOD = None

    def __init__(self, data):
        _check_keys(data, ("e", "n"))
        self.e = long(data["e"])
        self.n = long(data["n"])
        try:
            self.d = long(data["d"])
        except KeyError:
            self.d = None

    def verify(self, signed_data, signature):
        n, e = self.n, self.e
        m = long(signature, 16)
        c = pow(m, e, n)
        padded_digest = hex(c)[2:].rstrip("L").rjust(self.SIZE * 2, "0")
        return padded_digest == self._get_digest(signed_data)

    def sign(self, data):
        n, e, d = self.n, self.e, self.d
        if not d:
            raise ValueError("private key not present")
        c = long(self._get_digest(data), 16)
        m = pow(c, d, n)
        return hex(m)[2:].rstrip("L")

    def _get_digest(self, data):
        digest = self.HASHMOD(data).hexdigest()
        padded_digest = "00" + RSA_DIGESTINFO_HEADER[self.HASHNAME] + digest
        padding_len = (self.SIZE * 2) - 4 - len(padded_digest)
        padded_digest = "0001" + ("f" * padding_len) + padded_digest
        return padded_digest


class DSKey(Key):
    """Generic base class for DSA key objects.

    Concrete subclasses should provide the BITLENGTH and HASHMOD attributes.
    """

    BITLENGTH = None
    HASHMOD = None

    def __init__(self, data):
        _check_keys(data, ("p", "q", "g", "y"))
        self.p = long(data["p"], 16)
        self.q = long(data["q"], 16)
        self.g = long(data["g"], 16)
        self.y = long(data["y"], 16)
        if "x" in data:
            self.x = long(data["x"], 16)
        else:
            self.x = None

    def verify(self, signed_data, signature):
        p, q, g, y = self.p, self.q, self.g, self.y
        signature = signature.encode("hex")
        hexlength = self.BITLENGTH / 4
        signature = signature.rjust(hexlength * 2, "0")
        if len(signature) != hexlength * 2:
            return False
        r = long(signature[:hexlength], 16)
        s = long(signature[hexlength:], 16)
        if r <= 0 or r >= q:
            return False
        if s <= 0 or s >= q:
            return False
        w = modinv(s, q)
        u1 = (long(self.HASHMOD(signed_data).hexdigest(), 16) * w) % q
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
            k = long(os.urandom(self.BITLENGTH / 8).encode("hex"), 16) % q
            if k == 0:
                continue
            r = pow(g, k, p) % q
            if r == 0:
                continue
            h = (long(self.HASHMOD(data).hexdigest(), 16) + (x * r)) % q
            s = (modinv(k, q) * h) % q
            if s == 0:
                continue
            break
        assert 0 < r < q
        assert 0 < s < q
        bytelength = self.BITLENGTH / 8
        r_bytes = int2bytes(r).rjust(bytelength, "\x00")
        s_bytes = int2bytes(s).rjust(bytelength, "\x00")
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
    """Convert a Python long integer to bigendian bytestring."""
    # It's faster to go via hex encoding in C code than it is to try
    # encoding directly into binary with a python-level loop.
    # (and hex-slice-strip seems consistently faster than using "%x" format)
    hexbytes = hex(x)[2:].rstrip("L")
    if len(hexbytes) % 2:
        hexbytes = "0" + hexbytes
    return unhexlify(hexbytes)


def _check_keys(data, keys):
    """Verify that the given data dict contains the specified keys."""
    for key in keys:
        if not key in data:
            msg = 'missing %s in data - %s' % (key, str(data.keys()))
            raise ValueError(msg)
