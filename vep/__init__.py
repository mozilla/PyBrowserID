# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is PyVEP
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (rkelly@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****
"""

Python client library for the Verified Email Protocol.

"""

import os
import ssl
import time
import json
import struct
import base64
import socket
import httplib
import urllib2
import hashlib
import M2Crypto
from urlparse import urljoin
from fnmatch import fnmatch
from xml.dom import minidom


BROWSERID_VERIFIER_URL = "https://browserid.org/verify"


class RemoteVerifier(object):
    """Class for remote verification of VEP identity assertions.

    This class submits assertions to the browserid.org verifier service
    for remote verification.  It's slower but potentially a little bit
    safer than the still-under-development LocalVerifier class.
    """

    def __init__(self, verifier_url=None, urlopen=None):
        if verifier_url is None:
            verifier_url = BROWSERID_VERIFIER_URL
        if urlopen is None:
            urlopen = secure_urlopen
        self.verifier_url = verifier_url
        self.urlopen = urlopen

    def verify(self, assertion, audience=None):
        """Verify the given VEP assertion.

        This method posts the given VEP assertion to the remove verifier
        service.  If it is successfully verified then a dict giving the
        email and audience is returned.  If it is not valid then an error
        is raised.

        If the 'audience' argument is given, it first verifies that the
        audience of the assertion matches the one given.  This can help
        avoid doing lots of crypto for assertions that can't be valid.
        If you don't specify an audience, you *MUST* validate the audience
        value returned by this method.
        """
        # Read audience from assertion if not specified.
        if audience is None:
            token = json.loads(decode_bytes(assertion))["assertion"]
            audience = json.loads(decode_bytes(token.split(".")[1]))["aud"]
        # Encode the data into x-www-form-urlencoded.
        post_data = {"assertion": assertion, "audience": audience}
        post_data = "&".join("%s=%s" % item for item in post_data.items())
        # Post it to the verifier.
        resp = self.urlopen(self.verifier_url, post_data)
        try:
            info = resp.info()
        except AttributeError:
            info = {}
        content_length = info.get("Content-Length")
        if content_length is None:
            data = resp.read()
        else:
            data = resp.read(int(content_length))
        data = json.loads(data)
        # Did it come back clean?
        if data.get('status') != "okay":
            raise ValueError(str(data))
        assert data.get('audience') == audience
        return data


class LocalVerifier(object):
    """Class for local verification of VEP identity assertions.

    This class implements the logic for verifying identity assertions under
    the Verified Email Protocol.  Pass a VEP assertion token to the verify()
    method and let it work its magic.
    """

    HOST_META_PATH = "/.well-known/host-meta"
    HOST_META_REL_PUBKEY = "https://browserid.org/vocab#publickey"

    def __init__(self, urlopen=None, trusted_secondaries=None):
        if urlopen is None:
            urlopen = secure_urlopen
        if trusted_secondaries is None:
            trusted_secondaries = ("browserid.org",)
        self.urlopen = urlopen
        self.trusted_secondaries = trusted_secondaries
        self.public_keys = {}

    def verify(self, assertion, audience=None, now=None):
        """Verify the given VEP assertion.

        This method parses a VEP identity assertion, verifies the bundled
        chain of certificates and signatures, and returns the extracted
        email address and audience.

        If the 'audience' argument is given, it first verifies that the
        audience of the assertion matches the one given.  This can help
        avoid doing lots of crypto for assertions that can't be valid.
        If you don't specify an audience, you *MUST* validate the audience
        value returned by this method.

        If the 'now' argument is given, it is used as the current time in
        milliseconds.  This lets you verify expired assertions.
        """
        if now is None:
            now = int(time.time() * 1000)
        data = json.loads(decode_bytes(assertion))
        # Check that the assertion is usable and valid.
        # No point doing all that crypto if we're going to fail out anyway.
        assertion = JWT.parse(data["assertion"])
        if audience is not None:
            if assertion.payload["aud"] != audience:
                raise ValueError("mismatched audience")
        if assertion.payload["exp"] < now:
            raise ValueError("expired assertion")
        # Follow the certificate chain to get to the claiming principal.
        certificates = data["certificates"]
        certificates = [JWT.parse(c) for c in certificates]
        cert = self.verify_certificate_chain(certificates, now=now)
        email = cert.payload["principal"]["email"]
        # Check that the root issuer is trusted.
        root_issuer = certificates[0].payload["iss"]
        if root_issuer not in self.trusted_secondaries:
            if not email.endswith("@" + root_issuer):
                raise ValueError("untrusted root issuer")
        # Check the signature on the assertion.
        if not assertion.check_signature(cert.payload["public-key"]):
            raise ValueError("invalid signature on assertion")
        # Looks good!
        return {"status": "okay",
                "audience": assertion.payload["aud"],
                "email": email}

    def get_public_key(self, hostname):
        """Get the VEP public key for the given hostname.

        This function uses the well-known host meta-data file to locate and
        download the public key for the given hostname.  It keeps a cache
        in memory to avoid hitting the internet for every check.
        """
        hostname = "https://" + hostname
        try:
            (ok, key) = self.public_keys[hostname]
        except KeyError:
            try:
                # Read the host meta file to find key URL.
                meta = self._urlread(urljoin(hostname, self.HOST_META_PATH))
                meta = minidom.parseString(meta)
                for link in meta.getElementsByTagName("Link"):
                    rel = link.attributes.get("rel").value.lower()
                    if rel is not None:
                        if rel == self.HOST_META_REL_PUBKEY:
                            pubkey_url = link.attributes["href"].value
                            break
                else:
                    raise ValueError("Host has no public key")
                # Read and load the public key.
                key = self._urlread(urljoin(hostname, pubkey_url))
                key = json.loads(key)
                ok = True
                self.public_keys[hostname] = (True, key)
            except Exception, e:
                ok = False
                key = str(e)
                self.public_keys[hostname] = (False, key)
        if not ok:
            raise ValueError(key)
        return key

    def verify_certificate_chain(self, certificates, now=None):
        """Verify a signed chain of certificates.

        This function checks the signatures on the given chain of JWT
        certificates.  It looks up the public key for the issuer of the
        first certificate, then uses each certificate in turn to check the
        signature on its successor.

        If the entire chain is valid then to final certificate is returned.
        """
        assert certificates
        if now is None:
            now = int(time.time() * 1000)
        root_issuer = certificates[0].payload["iss"]
        root_key = self.get_public_key(root_issuer)
        current_key = root_key
        for cert in certificates:
            if cert.payload["exp"] < now:
                raise ValueError("expired certificate in chain")
            if not cert.check_signature(current_key):
                raise ValueError("bad signature in chain")
            current_key = cert.payload["public-key"]
        return cert

    def _urlread(self, url, data=None):
        """Read the given URL, return response as a string."""
        resp = self.urlopen(url, data)
        try:
            info = resp.info()
        except AttributeError:
            info = {}
        content_length = info.get("Content-Length")
        if content_length is None:
            data = resp.read()
        else:
            data = resp.read(int(content_length))
        return data


class JWT(object):
    """Class for parsing signed JSON Web Tokens."""

    def __init__(self, alg, payload, sig, sigbytes):
        self.alg = alg
        self.payload = payload
        self.sig = sig
        self.sigbytes = sigbytes

    @classmethod
    def parse(cls, jwt):
        """Parse a JWT from a string."""
        alg, payload, sig = jwt.split(".")
        sigbytes = alg + "." + payload
        alg = json.loads(decode_bytes(alg))["alg"]
        payload = json.loads(decode_bytes(payload))
        sig = decode_bytes(sig)
        return cls(alg, payload, sig, sigbytes)

    def check_signature(self, key):
        """Check that the JWT was signed with the given key."""
        if not self.alg.startswith(key["algorithm"]):
            return False
        if self.alg == "RS64":
            return self._check_signature_rs64(key)
        if self.alg == "RS128":
            return self._check_signature_rs128(key)
        raise ValueError("Unsupported Signature Type: %r" % (self.alg,))

    def _check_signature_rs64(self, key):
        e = int2mpint(int(key["e"]))
        n = int2mpint(int(key["n"]), pad=65)
        key = M2Crypto.RSA.new_pub_key((e, n))
        digest = hashlib.sha256(self.sigbytes).digest()
        try:
            return key.verify(digest, self.sig, "sha256")
        except M2Crypto.RSA.RSAError, e:
            if "bad signature" not in str(e):
                raise
            return False

    def _check_signature_rs128(self, key):
        e = int2mpint(int(key["e"]))
        n = int2mpint(int(key["n"]), pad=129)
        key = M2Crypto.RSA.new_pub_key((e, n))
        digest = hashlib.sha256(self.sigbytes).digest()
        try:
            return key.verify(digest, self.sig, "sha256")
        except M2Crypto.RSA.RSAError, e:
            if "bad signature" not in str(e):
                raise
            return False


def int2mpint(x, pad=None):
    """Convert integer into OpenSSL's MPINT format."""
    # The horror...the horror...
    bytes = []
    while x:
        bytes.append(chr(x % 256))
        x = x / 256
    if pad is not None:
        while len(bytes) < pad:
            bytes.append("\x00")
    bytes.reverse()
    return struct.pack(">I", len(bytes)) + "".join(bytes)


def decode_bytes(value):
    """Decode BrowserID's base64 encoding format.

    BrowserID likes to strip padding characters off of base64-encoded strings,
    meaning we can't use the stdlib routines to decode them directly.  This
    is a simple wrapper that adds the padding back in.
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
    return base64.urlsafe_b64decode(value)


# When using secure_urlopen we search for the platform default ca-cert file.
# This is done on-demand and the result cached in this global variable.
DEFAULT_CACERT_FILE = None
POSSIBLE_CACERT_FILES = ["/etc/ssl/certs/ca-certificates.crt",
                         "/etc/ssl/certs/ca-bundle.crt",
                         "/etc/ssl/ca-bundle.pem",
                         "/etc/pki/tls/certs/ca-bundle.crt"]

_OPENER_CACHE = {}


## We're using M2Crypto anyway, should also use it for the below?

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
                err = "could not locate default ca_certs file"
                raise RuntimeError(err)
    # Use a cached opener if possible.
    try:
        opener = _OPENER_CACHE[ca_certs]
    except KeyError:
        opener = urllib2.build_opener(ValidatingHTTPSHandler(ca_certs))
        _OPENER_CACHE[ca_certs] = opener
    return opener.open(url, data, timeout)


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
        if self.ca_certs is None:
            raise TypeError("missing keyword argument: ca_certs")
        httplib.HTTPSConnection.__init__(self, *args, **kwds)

    def connect(self):
        addr = (self.host, self.port)
        sock = socket.create_connection(addr, self.timeout)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_SSLv3,
                                    cert_reqs=ssl.CERT_REQUIRED,
                                    ca_certs=self.ca_certs)
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
