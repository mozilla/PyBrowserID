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
from binascii import unhexlify

from browserid.crypto._m2_monkeypatch import DSA as _DSA
from browserid.crypto._m2_monkeypatch import RSA as _RSA


class Key(object):
    """Generic base class for Key objects."""

    def verify(self, signed_data, signature):
        raise NotImplementedError  # pragma: nocover

    def sign(self, data):
        raise NotImplementedError  # pragma: nocover


#
#  RSA keys, implemented using the RSA support in M2Crypto.
#

class RSKey(object):

    SIZE = None
    HASHMOD = None

    def __init__(self, data=None, obj=None):
        if data is None and obj is None:
            raise ValueError('You should specify either data or obj')
        if obj is not None:
            self.rsa = obj
        else:
            _check_keys(data, ('e', 'n'))
            e = int2mpint(int(data["e"]))
            n = int2mpint(int(data["n"]))
            try:
                d = int2mpint(int(data["d"]))
            except KeyError:
                self.rsa = _RSA.new_pub_key((e, n))
            else:
                self.rsa = _RSA.new_key((e, n, d))

    def verify(self, signed_data, signature):
        digest = self.HASHMOD(signed_data).digest()
        try:
            return self.rsa.verify(digest, signature, self.HASHNAME)
        except _RSA.RSAError:
            return False

    def sign(self, data):
        digest = self.HASHMOD(data).digest()
        return self.rsa.sign(digest, self.HASHNAME)


#
#  DSA keys, implemented using the DSA support in M2Crypto, along with
#  some formatting tweaks to match what the browserid node-js server does.
#

class DSKey(object):

    BITLENGTH = None
    HASHMOD = None

    def __init__(self, data=None, obj=None):
        if data is None and obj is None:
            raise ValueError('You should specify either data or obj')
        if obj:
            self.dsa = obj
        else:
            _check_keys(data, ('p', 'q', 'g', 'y'))

            self.p = p = long(data["p"], 16)
            self.q = q = long(data["q"], 16)
            self.g = g = long(data["g"], 16)
            self.y = y = long(data["y"], 16)
            if "x" not in data:
                self.x = None
                self.dsa = _DSA.load_pub_key_params(int2mpint(p), int2mpint(q),
                                                    int2mpint(g), int2mpint(y))
            else:
                self.x = x = long(data["x"], 16)
                self.dsa = _DSA.load_key_params(int2mpint(p), int2mpint(q),
                                                int2mpint(g), int2mpint(y),
                                            int2mpint(x))

    def verify(self, signed_data, signature):
        # Restore any leading zero bytes that might have been stripped.
        signature = signature.encode("hex")
        hexlength = self.BITLENGTH / 4
        signature = signature.rjust(hexlength * 2, "0")
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
        return self.dsa.verify(digest, int2mpint(r), int2mpint(s))

    def sign(self, data):
        if not self.x:
            raise ValueError("private key not present")
        digest = self.HASHMOD(data).digest()
        r, s = self.dsa.sign(digest)
        # We need precisely "bytelength" bytes from each integer.
        # M2Crypto might give us more or less, so snip and pad appropriately.
        bytelength = self.BITLENGTH / 8
        r_bytes = r[4:].rjust(bytelength, "\x00")[-bytelength:]
        s_bytes = s[4:].rjust(bytelength, "\x00")[-bytelength:]
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
    hexbytes = hex(x)[2:].rstrip("L")
    if len(hexbytes) % 2:
        hexbytes = "0" + hexbytes
    bytes = unhexlify(hexbytes)
    # Add an extra significant byte that's just zero.  I think this is only
    # necessary if the number has its MSB set, to prevent it being mistaken
    # for a sign bit.  I do it uniformly since it's valid and simpler.
    return struct.pack(">I", len(bytes) + 1) + "\x00" + bytes


def _check_keys(data, keys):
    """Verify that the given data dict contains the specified keys."""
    for key in keys:
        if not key in data:
            msg = 'missing %s in data - %s' % (key, str(data.keys()))
            raise ValueError(msg)
