# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Crypto primitives built on top of M2Crypto.

This file provides the "fast path" crypto implementation for PyBrowserID.
It uses the public-key-crypto routines from M2Crypto for nice fast operation.

There is also a pure-python fallback module that's slower, but avoid
having to install M2Crypto.

"""

import struct
from binascii import hexlify, unhexlify

from M2Crypto import BIO

from browserid.crypto._m2_monkeypatch import m2
from browserid.crypto._m2_monkeypatch import DSA as _DSA
from browserid.crypto._m2_monkeypatch import RSA as _RSA


class Key(object):
    """Generic base class for Key objects."""

    KEY_MODULE = None

    @classmethod
    def from_pem_data(cls, data=None, filename=None):
        """Alternative constructor for loading from PEM format data."""
        self = cls.__new__(cls)
        if data is not None:
            bio = BIO.MemoryBuffer(str(data))
        elif filename is not None:
            bio = BIO.openfile(filename)
        else:
            msg = "Please specify either 'data' or 'filename' argument."
            raise ValueError(msg)
        self.keyobj = self.KEY_MODULE.load_pub_key_bio(bio)
        return self

    def to_pem_data(self):
        """Save the public key data to a PEM format string."""
        b = BIO.MemoryBuffer()
        try:
            self.keyobj.save_pub_key_bio(b)
            return b.getvalue()
        finally:
            b.close()

    def verify(self, signed_data, signature):
        """Verify the given signature."""
        raise NotImplementedError  # pragma: nocover

    def sign(self, data):
        """Sign the given data."""
        raise NotImplementedError  # pragma: nocover


#
#  RSA keys, implemented using the RSA support in M2Crypto.
#

class RSKey(Key):

    KEY_MODULE = _RSA
    DIGESTSIZE = None
    HASHNAME = None
    HASHMOD = None

    def __init__(self, data):
        _check_keys(data, ('e', 'n'))
        e = int2mpint(int(data["e"]))
        n = int2mpint(int(data["n"]))
        try:
            d = int2mpint(int(data["d"]))
        except KeyError:
            self.keyobj = _RSA.new_pub_key((e, n))
        else:
            self.keyobj = _RSA.new_key((e, n, d))

    def verify(self, signed_data, signature):
        digest = self.HASHMOD(signed_data).digest()
        try:
            return self.keyobj.verify(digest, signature, self.HASHNAME)
        except _RSA.RSAError:
            return False

    def sign(self, data):
        digest = self.HASHMOD(data).digest()
        return self.keyobj.sign(digest, self.HASHNAME)


#
#  DSA keys, implemented using the DSA support in M2Crypto, along with
#  some formatting tweaks to match what the browserid node-js server does.
#

class DSKey(Key):

    KEY_MODULE = _DSA
    BITLENGTH = None
    HASHMOD = None

    def __init__(self, data):
        _check_keys(data, ('p', 'q', 'g', 'y'))
        self.p = p = long(data["p"], 16)
        self.q = q = long(data["q"], 16)
        self.g = g = long(data["g"], 16)
        self.y = y = long(data["y"], 16)
        if "x" not in data:
            self.x = None
            self.keyobj = _DSA.load_pub_key_params(int2mpint(p), int2mpint(q),
                                                   int2mpint(g), int2mpint(y))
        else:
            self.x = x = long(data["x"], 16)
            self.keyobj = _DSA.load_key_params(int2mpint(p), int2mpint(q),
                                               int2mpint(g), int2mpint(y),
                                               int2mpint(x))

    @classmethod
    def from_pem_data(cls, data=None, filename=None):
        self = super(DSKey, cls).from_pem_data(data, filename)
        self.p = mpint2int(m2.dsa_get_p(self.keyobj.dsa))
        self.q = mpint2int(m2.dsa_get_q(self.keyobj.dsa))
        self.g = mpint2int(m2.dsa_get_g(self.keyobj.dsa))
        self.y = None
        self.x = None
        return self

    def verify(self, signed_data, signature):
        # Restore any leading zero bytes that might have been stripped.
        signature = hexlify(signature)
        hexlength = self.BITLENGTH // 4
        signature = signature.rjust(hexlength * 2, b"0")
        if len(signature) != hexlength * 2:
            return False
        # Split the signature into "r" and "s" components.
        r = long(signature[:hexlength], 16)
        s = long(signature[hexlength:], 16)
        if r <= 0 or r >= self.q:
            return False
        if s <= 0 or s >= self.q:
            return False
        # Now we can check the digest.
        digest = self.HASHMOD(signed_data).digest()
        return self.keyobj.verify(digest, int2mpint(r), int2mpint(s))

    def sign(self, data):
        if not self.x:
            raise ValueError("private key not present")
        digest = self.HASHMOD(data).digest()
        r, s = self.keyobj.sign(digest)
        # We need precisely "bytelength" bytes from each integer.
        # M2Crypto might give us more or less, so snip and pad appropriately.
        bytelength = self.BITLENGTH // 8
        r_bytes = r[4:].rjust(bytelength, b"\x00")[-bytelength:]
        s_bytes = s[4:].rjust(bytelength, b"\x00")[-bytelength:]
        return r_bytes + s_bytes


#
#  Other helper functions.
#


def int2mpint(x):
    """Convert a Python long integer to a string in OpenSSL's MPINT format."""
    # MPINT is big-endian bytes with a size prefix.
    # It's faster to go via hex encoding in C code than it is to try
    # encoding directly into binary with a python-level loop.
    # (and hex-slice-strip seems consistently faster than using "%x" format)
    hexbytes = hex(x)[2:].rstrip("L").encode("ascii")
    if len(hexbytes) % 2:
        hexbytes = b"0" + hexbytes
    bytes = unhexlify(hexbytes)
    # Add an extra significant byte that's just zero.  I think this is only
    # necessary if the number has its MSB set, to prevent it being mistaken
    # for a sign bit.  I do it uniformly since it's valid and simpler.
    return struct.pack(">I", len(bytes) + 1) + b"\x00" + bytes


def mpint2int(data):
    """Convert a string in OpenSSL's MPINT format to a Python long integer."""
    hexbytes = hexlify(data[4:])
    return long(hexbytes, 16)


def _check_keys(data, keys):
    """Verify that the given data dict contains the specified keys."""
    for key in keys:
        if not key in data:
            msg = 'missing %s in data - %s' % (key, str(data.keys()))
            raise ValueError(msg)
