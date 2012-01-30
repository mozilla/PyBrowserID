# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Utility functions for PyVEP.

"""

import os
import json
import ssl
import time
import base64
import socket
import httplib
import urllib2
import warnings
from fnmatch import fnmatch

from vep.errors import ConnectionError


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
        value += "=="
    elif pad == 3:
        value += "="
    elif pad != 0:
        raise ValueError("incorrect b64 encoding")
    try:
        return base64.urlsafe_b64decode(value)
    except TypeError, e:
        raise ValueError(str(e))


def encode_bytes(value):
    """Encode BrowserID's base64 encoding format.

    BrowserID likes to strip padding characters off of base64-encoded strings,
    meaning we can't use the stdlib routines to encode them directly.  This
    is a simple wrapper that strips the padding.
    """
    if isinstance(value, unicode):
        value = value.encode("ascii")
    return base64.urlsafe_b64encode(value).rstrip("=")


def decode_json_bytes(value):
    """Decode a JSON object from some encoded bytes.

    This function decodes a JSON object from bytes encoded in the BrowserID
    base64 format.  If the bytes and invalid or do not encode a proper object,
    ValueError is raised.
    """
    obj = json.loads(decode_bytes(value))
    if not isinstance(obj, dict):
        raise ValueError("JSON did not contain an object")
    return obj


def encode_json_bytes(obj):
    """Encode an object as JSON bytes in the BrowserID base64 format."""
    if not isinstance(obj, dict):
        raise ValueError("Value is not a JSON object")
    return encode_bytes(json.dumps(obj))


def bundle_certs_and_assertion(certificates, assertion, new_style=True):
    """Bundle certificates and assertion into a single string.

    This function produces a VEP "bundled assertion" that combines the
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

    This function parse a VEP "bundled assertion" into the contained chain
    of certificates and final assertion.  The returned value is a tuple
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
    except (TypeError, KeyError), e:
        raise ValueError(str(e))
    return info


# When using secure_urlopen we search for the platform default ca-cert file.
# This is done on-demand and the result cached in this global variable.
DEFAULT_CACERT_FILE = None
POSSIBLE_CACERT_FILES = ["/etc/ssl/certs/ca-certificates.crt",
                         "/etc/ssl/certs/ca-bundle.crt",
                         "/etc/ssl/ca-bundle.pem",
                         "/etc/pki/tls/certs/ca-bundle.crt"]

_OPENER_CACHE = {}


## TODO: We're using M2Crypto anyway, should also use it for the below?

def secure_urlopen(url, data=None, timeout=None, ca_certs=None):
    """More secure replacement for urllib2.urlopen.

    This function provides an alternative to urllib2.urlopen which does
    basic validation and verification of HTTPS server certificates.
    """
    global DEFAULT_CACERT_FILE
    # Try to find platform default ca-cert file if none was specified.
    if ca_certs is None:
        ca_certs = DEFAULT_CACERT_FILE
        if ca_certs is None:
            for filenm in POSSIBLE_CACERT_FILES:
                if os.path.exists(filenm):
                    ca_certs = DEFAULT_CACERT_FILE = filenm
                    break
            if ca_certs is None:
                msg = "Could not locate a CA certificates file for HTTPS."\
                      " Your requests will be vulnerable to man-in-the-middle"\
                      " attacks.  It is *HIGHLY RECOMMENDED* that you specify"\
                      " the ca_certs parameter with the path to a valid"\
                      " certificates file."
                warnings.warn(msg, stacklevel=2)
    # Use a cached opener if possible.
    try:
        opener = _OPENER_CACHE[ca_certs]
    except KeyError:
        opener = urllib2.build_opener(ValidatingHTTPSHandler(ca_certs))
        _OPENER_CACHE[ca_certs] = opener
    try:
        return opener.open(url, data, timeout)
    except (EnvironmentError, httplib.HTTPException), e:
        raise ConnectionError(str(e))


class ValidatingHTTPSHandler(urllib2.HTTPSHandler):
    """A urllib2 HTTPS handler that validates server certificates.

    This class provides a urllib2-compatible opener that will validate
    the HTTPS server certificate against the requested hostname before
    proceeding with the connection.

    It's mostly a wrapper around ValidatingHTTPSConnection, which is where
    all the fun really happens.
    """

    def __init__(self, ca_certs):
        urllib2.HTTPSHandler.__init__(self)
        self.ca_certs = ca_certs

    def https_open(self, req):
        return self.do_open(self._get_connection, req)

    def _get_connection(self, host, timeout):
        return ValidatingHTTPSConnection(host, timeout=timeout,
                                         ca_certs=self.ca_certs)


class ValidatingHTTPSConnection(httplib.HTTPSConnection):
    """HTTPSConnection that validates the server certificate.

    This class adds some SSL certificate-checking to httplib.  It's not
    robust and it's not complete, it's just enough to verify the certificate
    of the browserid.org verifier server.  Hopefully it will also work with
    other verifier URLs you might like to use.

    The connector also restricts SSL to version 3 in order to avoid
    downgrading the connection to an insecure older version.

    It doesn't do revocation checks.  It should.  But I've no idea how.

    The code uses implementations hints provided by:

        http://www.heikkitoivonen.net/blog/2008/10/14/ssl-in-python-26/

    """

    def __init__(self, *args, **kwds):
        self.ca_certs = kwds.pop("ca_certs", None)
        httplib.HTTPSConnection.__init__(self, *args, **kwds)

    def connect(self):
        addr = (self.host, self.port)
        sock = socket.create_connection(addr, self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        kwds = {"ssl_version": ssl.PROTOCOL_SSLv3}
        if self.ca_certs is None:
            kwds["cert_reqs"] = ssl.CERT_NONE
        else:
            kwds["ca_certs"] = self.ca_certs
            kwds["cert_reqs"] = ssl.CERT_REQUIRED
        self.sock = ssl.wrap_socket(sock, **kwds)
        if self.ca_certs is not None:
            cert = self.sock.getpeercert()
            self._validate_certificate(cert)

    def _validate_certificate(self, cert):
        now = time.time()
        # Refuse to connect if there's no certificate.
        if cert is None:
            err = "no SSL certificate for %s" % (self.host,)
            raise socket.error(err)
        # Refuse to connect if the certificate has expired.
        if "notAfter" in cert:
            if ssl.cert_time_to_seconds(cert["notAfter"]) < now:
                err = "expired SSL certificate for %s" % (self.host,)
                raise socket.error(err)
        # Refuse to connect if the certificate is missing subject data.
        if "subject" not in cert:
            err = "malformed SSL certificate for %s" % (self.host,)
            raise socket.error(err)
        # Try to match the certificate to the requested host.
        if not self._validate_certificate_hostname(cert):
            err = "invalid SSL certificate for %s" % (self.host,)
            raise socket.error(err)

    def _validate_certificate_hostname(self, cert):
        for rdn in cert["subject"]:
            for name, value in rdn:
                if name == "commonName":
                    if value == self.host:
                        return True
                    elif fnmatch(self.host, value):
                        return True
                    # Ugh.
                    # It seems https://browserid.org uses the certificate for
                    # https://www.browserid.org, but redirects us away from
                    # that domain.  Apparently this is OK..?
                    elif value == "www." + self.host:
                        return True
        return False
