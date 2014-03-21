# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Utility functions for PyBrowserID.

"""

import sys
import json
import time
import base64
from binascii import hexlify, unhexlify


if sys.version_info > (3,):
    long = int
    unicode = str


# These are the JWT claims that have special meaning either to the
# JWT spec or to BrowserID.  Any claims not in this list will be
# collected into a special "extra claims" list.
RESERVED_JWT_CLAIMS = set([
  'iss',
  'sub',
  'aud',
  'exp',
  'nbf',
  'iat',
  'jti',
  'public-key',
  'pubkey',
  'principal'
])


def decode_bytes(value):
    """Decode BrowserID's base64 encoding format.

    BrowserID likes to strip padding characters off of base64-encoded strings,
    meaning we can't use the stdlib routines to decode them directly.  This
    is a simple wrapper that adds the padding back in.

    If the value is not correctly encoded, ValueError will be raised.
    """
    if isinstance(value, unicode):
        value = value.encode("ascii")
    pad = len(value) % 4
    if pad == 2:
        value += b"=="
    elif pad == 3:
        value += b"="
    elif pad != 0:
        raise ValueError("incorrect b64 encoding")
    try:
        return base64.urlsafe_b64decode(value)
    except TypeError as e:
        raise ValueError(str(e))


def encode_bytes(value):
    """Encode BrowserID's base64 encoding format.

    BrowserID likes to strip padding characters off of base64-encoded strings,
    meaning we can't use the stdlib routines to encode them directly.  This
    is a simple wrapper that strips the padding.
    """
    if isinstance(value, unicode):
        value = value.encode("ascii")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_json_bytes(value):
    """Decode a JSON object from some encoded bytes.

    This function decodes a JSON object from bytes encoded in the BrowserID
    base64 format.  If the bytes and invalid or do not encode a proper object,
    ValueError is raised.
    """
    obj = json.loads(decode_bytes(value).decode("utf8"))
    if not isinstance(obj, dict):
        raise ValueError("JSON did not contain an object")
    return obj


def encode_json_bytes(obj):
    """Encode an object as JSON bytes in the BrowserID base64 format."""
    if not isinstance(obj, dict):
        raise ValueError("Value is not a JSON object")
    return encode_bytes(json.dumps(obj).encode("utf8"))


def bundle_certs_and_assertion(certificates, assertion):
    """Bundle certificates and assertion into a single string.

    This function produces a BrowserID "bundled assertion" that combines the
    certificate chain and final assertion into a single string.
    """
    return "~".join(certificates) + "~" + assertion


def unbundle_certs_and_assertion(bundle):
    """Unbundle certificates and assertion from a single string.

    This function parses a BrowserID "bundled assertion" into the contained
    chain of certificates and final assertion.  The returned value is a tuple
    (certificates, assertion).
    """
    certificates, assertion = bundle.rsplit("~", 1)
    certificates = certificates.split("~")
    return certificates, assertion


def get_assertion_info(assertion):
    """Parse interesting information out of a BrowserID assertion.

    This function decodes and parses the given BrowserID assertion, returning
    a dict with the following items:

       * email:        the email address of the asserted identity
       * issuer:       the authority certifying the claimed identity
       * idpClaims:    extra claims included by the issuing authority
       * audience:     the audience to whom it is asserted
       * expires:      the timestamp at which the assertion expires, in ms
       * userClaims:   extra claims included by the identity claimant

    For backwards-compatiblity reasons, the following key is also provided:

       * principal:  the asserted identity, eg: {"email": "test@example.com"}

    This does *not* verify the assertion at all, it is merely a way to see
    the information that is being asserted.  If the assertion is malformed
    then ValueError will be raised.
    """
    info = {}
    try:
        certificates, assertion = unbundle_certs_and_assertion(assertion)
        # Get details of the asserted identity out of the certificate chain.
        # Older certificates include this as "principal" but newer ones
        # use the standard JWT "sub" field.
        payload = decode_json_bytes(certificates[-1].split(".")[1])
        if "principal" in payload:
            info["email"] = payload["principal"]["email"]
            info["principal"] = payload["principal"]
        else:
            info["email"] = payload["sub"]
            info["principal"] = {"email": payload["sub"]}
        info["issuer"] = payload["iss"]
        info["idpClaims"] = extract_extra_claims(payload)
        # Get the audience and expiry out of the assertion token.
        payload = decode_json_bytes(assertion.split(".")[1])
        info["audience"] = payload["aud"]
        info["expires"] = normalize_timestamp(payload["exp"])
        info["userClaims"] = extract_extra_claims(payload)
    except (TypeError, KeyError) as e:
        raise ValueError(e)
    return info


def extract_extra_claims(payload):
    """Extract any non-standard JWT claims for a JWT payload.

    This function searches the given payload dict for any claims that do
    not have a special meaning in the JWT or BrowserID specs, and returns
    a dict containing any such claims.

    As a backwards-compatibility measure, if there is a claim named "principal"
    and its value is a dict, then any keys therein apart from "email" will
    be added to the return value.
    """
    extra_claims = {}
    for key, value in payload.iteritems():
        if key not in RESERVED_JWT_CLAIMS:
            extra_claims[key] = value
    principal = payload.get("principal", None)
    if isinstance(principal, dict):
        for key, value in principal.iteritems():
            if key != "email" and key not in extra_claims:
                extra_claims[key] = value
    return extra_claims


def bytes_to_long(value):
    """Convert raw big-endian bytes into a python long object."""
    return long(hexlify(value), 16)


def long_to_bytes(value):
    """Convert the given long value to raw big-endian bytes."""
    # It's faster to go via hex encoding in C code than it is to try
    # encoding directly into binary with a python-level loop.
    # And hex-slice-strip seems consistently faster than using "%x" format.
    hexbytes = hex(value)[2:].rstrip("L").encode("ascii")
    if len(hexbytes) % 2:
        hexbytes = b"0" + hexbytes
    return unhexlify(hexbytes)


def u(value):
    """Helper function for constructing unicode string literals.

    Use it in lieu of the u"" prefix, like this:

        data = u("unicode string")

    """
    if sys.version_info < (3,):
        value = value.decode("unicode-escape")
    return value


def normalize_timestamp(ts):
    """Normalize the given timestamp into BrowserID standard representation.

    Previous versions of BrowserID, and hence of this library, uses integer
    millisecond timestamps.  The latest version uses integer seconds, causing
    much potential for confusion.  This helper function tries to provide some
    backwards-compatibility by detecting millisecond timestamps and converting
    them to seconds.
    """
    if ts is None:
        ts = time.time()
    ts = int(ts)
    if ts >= 1000000000000:
        # Ludicrously large, it must be a millisecond timestamp.
        ts = ts / 1000
    return ts
