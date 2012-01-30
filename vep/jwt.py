# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Utilities for dealing with Signed JSON Web Tokens.

"""

import struct
import hashlib
from binascii import unhexlify
from vep._m2_monkeypatch import DSA as _DSA
from vep._m2_monkeypatch import RSA as _RSA

from vep.utils import decode_bytes, encode_bytes
from vep.utils import decode_json_bytes, encode_json_bytes


def parse(jwt, cls=None):
    """Parse a JWT from a string."""
    if cls is None:
        cls = JWT
    algorithm, payload, signature = jwt.split(".")
    signed_data = algorithm + "." + payload
    try:
        algorithm = decode_json_bytes(algorithm)["alg"]
    except KeyError:
        raise ValueError("badly formed JWT")
    payload = decode_json_bytes(payload)
    signature = decode_bytes(signature)
    return cls(algorithm, payload, signature, signed_data)


def generate(payload, key):
    """Generate and sign a JWT for a dict payload."""
    alg = key.__class__.__name__[:-3]
    algorithm = encode_json_bytes({"alg": alg})
    payload = encode_json_bytes(payload)
    signature = encode_bytes(key.sign(".".join((algorithm, payload))))
    return ".".join((algorithm, payload, signature))


class JWT(object):
    """Class for parsing signed JSON Web Tokens.

    To parse a JWT from a bytestring, use the module-level parse() function.
    This class is really only for internal purposes.
    """

    def __init__(self, algorithm, payload, signature, signed_data):
        self.algorithm = algorithm
        self.payload = payload
        self.signature = signature
        self.signed_data = signed_data

    def check_signature(self, key_data):
        """Check that the JWT was signed with the given key."""
        if not self.algorithm.startswith(key_data["algorithm"]):
            return False
        key = load_key(self.algorithm, key_data)
        return key.verify(self.signed_data, self.signature)


def load_key(algorithm, key_data):
    """Load a Key object from the given data."""
    if not algorithm.isalnum():
        msg = "unknown signing algorithm: %s" % (algorithm,)
        raise ValueError(msg)
    try:
        key_class = globals()[algorithm + "Key"]
    except KeyError:
        msg = "unknown signing algorithm: %s" % (algorithm,)
        raise ValueError(msg)
    return key_class(key_data)


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

    def __init__(self, data):
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


class RS64Key(RSKey):
    SIZE = 64
    HASHNAME = "sha256"
    HASHMOD = hashlib.sha256


class RS128Key(RSKey):
    SIZE = 128
    HASHNAME = "sha256"
    HASHMOD = hashlib.sha256


class RS256Key(RSKey):
    SIZE = 256
    HASHNAME = "sha256"
    HASHMOD = hashlib.sha256


#
#  DSA keys, implemented using the DSA support in M2Crypto, along with
#  some formatting tweaks to match what the browserid node-js server does.
#

class DSKey(object):

    BITLENGTH = None
    HASHMOD = None

    def __init__(self, data):
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


class DS128Key(DSKey):
    BITLENGTH = 160
    HASHMOD = hashlib.sha1


class DS256Key(DSKey):
    BITLENGTH = 256
    HASHMOD = hashlib.sha256


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
