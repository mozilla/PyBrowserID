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

Python library for the Verified Email Protocol.

"""

__ver_major__ = 0
__ver_minor__ = 1
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


import time
import json
from urlparse import urljoin
from xml.dom import minidom

from vep.utils import secure_urlopen, decode_bytes
from vep.jwt import JWT

import warnings
warning_message = "The VEP certificate format has not been finalized and may "\
                  "change in backwards-incompatible ways.  If you find that "\
                  "the latest version of this module cannot verify a valid "\
                  "VEP assertion, please contact the author."
warnings.warn(warning_message, FutureWarning)


BROWSERID_VERIFIER_URL = "https://browserid.org/verify"

DEFAULT_TRUSTED_SECONDARIES = ("browserid.org", "diresworb.org",
                               "dev.diresworb.org")


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
            trusted_secondaries = DEFAULT_TRUSTED_SECONDARIES
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
                msg = "untrusted root issuer: %s" % (root_issuer,)
                raise ValueError(msg)
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
                # Try to read the host-meta file to find the key URL.
                # If there's no host-meta file, just look at /pk
                try:
                    meta_url = urljoin(hostname, self.HOST_META_PATH)
                    meta = self._urlread(meta_url)
                    meta = minidom.parseString(meta)
                    for link in meta.getElementsByTagName("Link"):
                        rel = link.attributes.get("rel").value.lower()
                        if rel is not None:
                            if rel == self.HOST_META_REL_PUBKEY:
                                pubkey_url = link.attributes["href"].value
                                break
                    else:
                        raise ValueError("Host has no public key")
                except Exception, e:
                    # We have no guarantee what sort of error will get raised
                    # or how to find the status code from it :-(
                    if "404" not in str(e):
                        raise
                    pubkey_url = urljoin(hostname, "/pk")
                # Now read the public key from that URL.
                # Cache it on success. TODO: should expire cache occasionally
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
