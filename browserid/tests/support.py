# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import time
import hashlib
from contextlib import contextmanager

from browserid.utils import (encode_bytes, bundle_certs_and_assertion,
                             normalize_timestamp, long_to_bytes)

from browserid import supportdoc
from browserid import jwt

# if unittest2 isn't available, assume that we are python 2.7
try:
    import unittest2 as unittest
except ImportError:
    import unittest  # NOQA


# This is an old assertion I generated on myfavoritebeer.org.
# It's expired and signed with an old private key.  It has
# the following info:
#
#  email:  rfkelly@mozilla.com
#  audience:  http://myfavoritebeer.org
#
EXPIRED_ASSERTION = """
    eyJhbGciOiJSUzI1NiJ9.eyJwdWJsaWMta2V5Ijp7ImFsZ29yaXRobSI6IkR
    TIiwieSI6IjZlYjFiMjIxNzg3YjZlYWFiNTBlZTNmNjg2M2M5YmIzNDFmOTA
    2MDI5Y2ZiNzc4NGQwYzA1YzZkNWJjMDUwYjdmMjY4MGFhYjUyZWRiYmM2N2Z
    iNDZmYWIwYWNjYTI0MGQ3ZjdmNmQ3MmYxZjkzZTZhZWYxMjhmMmYxMTUxMzk
    yZDdlYTFhYjIyZDE2OWY3YmFiYzNkYTcyZmMwNjgyYTlmYjQ4M2M2NjBjMjQ
    2ZjEzMzRjMDFlMzE3MmUxY2RmZDJlNjMwY2I0NGJmMzdmNDAyZDhhYjEyNWJ
    iNDA3MDcyYzNjZjk5ZjhmNTg3NzdlOTA3MWNhNzBjNzcxNjk0YTkiLCJwIjo
    iZmY2MDA0ODNkYjZhYmZjNWI0NWVhYjc4NTk0YjM1MzNkNTUwZDlmMWJmMmE
    5OTJhN2E4ZGFhNmRjMzRmODA0NWFkNGU2ZTBjNDI5ZDMzNGVlZWFhZWZkN2U
    yM2Q0ODEwYmUwMGU0Y2MxNDkyY2JhMzI1YmE4MWZmMmQ1YTViMzA1YThkMTd
    lYjNiZjRhMDZhMzQ5ZDM5MmUwMGQzMjk3NDRhNTE3OTM4MDM0NGU4MmExOGM
    0NzkzMzQzOGY4OTFlMjJhZWVmODEyZDY5YzhmNzVlMzI2Y2I3MGVhMDAwYzN
    mNzc2ZGZkYmQ2MDQ2MzhjMmVmNzE3ZmMyNmQwMmUxNyIsInEiOiJlMjFlMDR
    mOTExZDFlZDc5OTEwMDhlY2FhYjNiZjc3NTk4NDMwOWMzIiwiZyI6ImM1MmE
    0YTBmZjNiN2U2MWZkZjE4NjdjZTg0MTM4MzY5YTYxNTRmNGFmYTkyOTY2ZTN
    jODI3ZTI1Y2ZhNmNmNTA4YjkwZTVkZTQxOWUxMzM3ZTA3YTJlOWUyYTNjZDV
    kZWE3MDRkMTc1ZjhlYmY2YWYzOTdkNjllMTEwYjk2YWZiMTdjN2EwMzI1OTM
    yOWU0ODI5YjBkMDNiYmM3ODk2YjE1YjRhZGU1M2UxMzA4NThjYzM0ZDk2MjY
    5YWE4OTA0MWY0MDkxMzZjNzI0MmEzODg5NWM5ZDViY2NhZDRmMzg5YWYxZDd
    hNGJkMTM5OGJkMDcyZGZmYTg5NjIzMzM5N2EifSwicHJpbmNpcGFsIjp7ImV
    tYWlsIjoicmZrZWxseUBtb3ppbGxhLmNvbSJ9LCJpYXQiOjEzOTUzNzE2NDQ
    0OTQsImV4cCI6MTM5NTM3MTk1NDQ5NCwiaXNzIjoibG9naW4ubW96aWxsYS5
    vcmcifQ.CJ_MPvzlQBXEYkMg9ouMLdkkpN633ZeYZqyf2-owmcfwp4s29vs8
    8Z0fxmeKigNqrEOMD-VP0jV4CEmrAHkkMKPS1GZm9-iAgK4pJwkIwTOhMOLB
    mv3jz7g1FF7D5ZWJxK1TwJTSJD0z2yCwYohCvPj_V-ieDlEPEnwyjThM2_rM
    NpD9qj3t5JGVykf55f2JJ9joJgDLXy4zviC1Bq5jU24M2e9Gqdret4b47-oL
    _QoepIBzjwgG608WnELtauxziGkWbwJLNKgUq14EHl1vLGCLl8qK_-PdSJk0
    aDaiKMyKvqkY0ClBWhUTYuKI1yTIpkTfF8xoGh16FeoIly3zDw~eyJhbGciO
    iJEUzEyOCJ9.eyJleHAiOjEzOTUzNzE3NzUzODksImF1ZCI6Imh0dHA6Ly9t
    eWZhdm9yaXRlYmVlci5vcmcifQ.UmsN-LQbBy9osrdxV36n8Jqx10sftkljr
    lFRHHg5t_yl6ll3KXUBxw
""".replace(" ", "").replace("\n", "").strip()


def to_int(intstr, base=10):
    return long(str(intstr).replace(" ", "").replace("\n", ""), base)


def to_hex(intval):
    return hex(intval)[2:].rstrip("L")


# These are values used to generate dummy DSA keys.
# I took them directly from the javacript jwcrypto source code, which claims:
#    """
#    the following are based on the first FIPS186-3 test vectors for 1024/160
#    SHA-256 under the category A.2.3 Verifiable Canonical Generation of the
#    Generator g
#    """
DUMMY_Q = to_int("e21e04f911d1ed7991008ecaab3bf775984309c3", 16)


DUMMY_P = to_int("""
  ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429
  d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d39
  2e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f
  776dfdbd604638c2ef717fc26d02e17
""", 16)

DUMMY_G = to_int("""
  c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419
  e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d0
  3bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389a
  f1d7a4bd1398bd072dffa896233397a
""", 16)


def fetch_support_document(hostname, verify=None):
    """Fetch the BrowserID support document for the given hostname.

    Actually, this implementation generates a key locally based on
    a hash of the hostname.  This lets us exercise all the crypto code
    while using predictable local values.
    """

    if hostname == "redirect.org":
        return {"authority": "delegated.org"}

    if hostname == "redirect-twice.org":
        return {"authority": "redirect.org"}

    if hostname == "infinite.org":
        return {"authority": "infinite.org"}

    return {"public-key": get_keypair(hostname)[0]}


def get_keypair(hostname, legacy_format=False):
    """Generate a dummy keypair for the given hostname.

    This method generates a dummy DSA keypair for the given hostname.
    It returns a tuple (pub, priv) where "pub" is a dict of values for
    the public key, and "priv" is a DSA128Key object containing the
    private key.  Multiple calls to this method for the same hostname
    are guaranteed to produce the same key.

    To make this work we take advantage of the fact that DSA key generation
    is just "generate x by some random method, where 0 < x < q".  Replace
    "some random method" with "sha1 hash of hostname" and we're all set.
    """
    # Use pre-agreed parameters for p, q and g.
    q = DUMMY_Q
    p = DUMMY_P
    g = DUMMY_G
    # Generate private key x by "some random method".
    x = to_int(hashlib.sha1(hostname.encode("utf8")).hexdigest(), 16)
    assert x != 0, "SHA1(hostname) is zero - what are the odds?!"
    # Calculate public key y as usual.
    y = pow(g, x, p)
    # Format the data appropriately for latest or legacy assertiond.
    if legacy_format:
        data = {
          "algorithm": "DS",
          "p": to_hex(p),
          "q": to_hex(q),
          "g": to_hex(g),
          "y": to_hex(y),
          "x": to_hex(x),
        }
    else:
        data = {
          "kty": "DSA",
          "p": encode_bytes(long_to_bytes(p)),
          "q": encode_bytes(long_to_bytes(q)),
          "g": encode_bytes(long_to_bytes(g)),
          "y": encode_bytes(long_to_bytes(y)),
          "x": encode_bytes(long_to_bytes(x)),
        }
    privkey = jwt.DS128Key(data)
    del data["x"]
    return data, privkey


def make_assertion(email, audience, issuer=None, exp=None,
                    assertion_sig=None, certificate_sig=None,
                    email_keypair=None, issuer_keypair=None,
                    user_claims=None, idp_claims=None,
                    legacy_format=False):
    """Generate a new dummy assertion for the given email address.

    This method lets you generate BrowserID assertions using dummy private
    keys. Called with just an email and audience it will generate an assertion
    from login.persona.org.

    By specifying the "exp", "assertion_sig" or "certificate_sig" arguments
    it is possible generate invalid assertions for testing purposes.
    """
    if issuer is None:
        issuer = "login.persona.org"
    if exp is None:
        exp = time.time() + 60
    # Legacy format uses integer millisecond timestamps.
    exp = normalize_timestamp(exp)
    if legacy_format:
        exp = exp * 1000
    # Get private key for the email address itself.
    if email_keypair is None:
        email_keypair = get_keypair(email, legacy_format=legacy_format)
    email_pub, email_priv = email_keypair
    # Get private key for the hostname so we can sign it.
    if issuer_keypair is None:
        issuer_keypair = get_keypair(issuer, legacy_format=legacy_format)
    iss_pub, iss_priv = issuer_keypair

    # Generate the assertion, signed with email's public key.
    assertion = {
        "exp": exp,
        "aud": audience,
    }
    if user_claims is not None:
        assertion.update(user_claims)
    assertion = jwt.generate(assertion, email_priv)
    if assertion_sig is not None:
        assertion = ".".join(assertion.split(".")[:-1] +
                                [encode_bytes(assertion_sig)])
    # Generate the certificate signing the email's public key
    # with the issuer's public key.  The details differ between
    # current and legacy formats.
    if legacy_format:
        certificate = {
            "iss": issuer,
            "exp": exp,
            "principal": {"email": email},
            "public-key": email_pub,
        }
    else:
        certificate = {
            "iss": issuer,
            "exp": exp,
            "sub": email,
            "pubkey": email_pub,
        }
    if idp_claims is not None:
        certificate.update(idp_claims)
    certificate = jwt.generate(certificate, iss_priv)
    if certificate_sig is not None:
        certificate = ".".join(certificate.split(".")[:-1] +
                                [encode_bytes(certificate_sig)])
    # Combine them into a BrowserID bundled assertion.
    return bundle_certs_and_assertion([certificate], assertion)


@contextmanager
def patched_supportdoc_fetching(replacement=None, exc=None):
    """Patch the key fetching mechanism with the given callable.

    This is to allow easier testing.
    """
    def raise_exception(*args, **kwargs):
        raise exc

    if exc is not None:
        replacement = raise_exception
    if replacement is None:
        replacement = fetch_support_document
    old_callable = supportdoc.fetch_support_document
    supportdoc.fetch_support_document = replacement
    yield
    supportdoc.fetch_support_document = old_callable


def callwith(context):
    """Decorator to call a function with a context manager."""
    def decorator(func):
        def wrapper(*args, **kwds):
            with context:
                return func(*args, **kwds)
        return wrapper
    return decorator
