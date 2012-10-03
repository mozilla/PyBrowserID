# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Utility functions for PyBrowserID.

"""

import sys
import json
import base64


if sys.version_info > (3,):
    long = int
    unicode = str


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


def bundle_certs_and_assertion(certificates, assertion, new_style=True):
    """Bundle certificates and assertion into a single string.

    This function produces a BrowserID "bundled assertion" that combines the
    certificate chain and final assertion into a single string.  By default
    it uses the "new-style" tilde-separated format; pass new_style=False to
    use the older b64-encoded-JSON format.
    """
    if new_style:
        return "~".join(certificates) + "~" + assertion
    else:
        return encode_json_bytes({
          "certificates": certificates,
          "assertion": assertion,
        })


def unbundle_certs_and_assertion(bundle):
    """Unbundle certificates and assertion from a single string.

    This function parses a BrowserID "bundled assertion" into the contained
    chain of certificates and final assertion.  The returned value is a tuple
    (certificates, assertion).
    """
    if "~" in bundle:
        certificates, assertion = bundle.rsplit("~", 1)
        certificates = certificates.split("~")
    else:
        data = decode_json_bytes(bundle)
        certificates = data["certificates"]
        assertion = data["assertion"]
    return certificates, assertion


def get_assertion_info(assertion):
    """Parse interesting information out of a BrowserID assertion.

    This function decodes and parses the given BrowserID assertion, returning
    a dict with the following items:

       * principal:  the asserted identity, eg: {"email": "test@example.com"}
       * audience:   the audience to whom it is asserted

    This does *not* verify the assertion at all, it is merely a way to see
    the information that is being asserted.  If the assertion is malformed
    then ValueError will be raised.
    """
    info = {}
    try:
        certificates, assertion = unbundle_certs_and_assertion(assertion)
        # Get the asserted principal out of the certificate chain.
        payload = decode_json_bytes(certificates[-1].split(".")[1])
        info["principal"] = payload["principal"]
        # Get the audience out of the assertion token.
        payload = decode_json_bytes(assertion.split(".")[1])
        info["audience"] = payload["aud"]
    except (TypeError, KeyError) as e:
        raise ValueError(e)
    return info


def to_int(value, base=10):
    """Convert the given value to a python integer.

    The given value can be an existing int or long object, or a string in
    the given base.  The result will always be a long on python2 and an
    int on python3 (which has not concept of a separate "long" type).
    """
    if not isinstance(value, str):
        return long(value)
    return long(value.replace(" ", "").replace("\n", "").strip(), base)


def to_hex(value):
    """Convert the given value to a long encoded into a hex string."""
    return hex(to_int(value))[2:].rstrip("L")


def u(value):
    """Helper function for constructing unicode string literals.

    Use it in lieu of the u"" prefix, like this:

        data = u("unicode string")

    """
    if sys.version_info < (3,):
        value = value.decode("unicode-escape")
    return value
