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

import time
import json
import warnings
from urlparse import urljoin
from xml.dom import minidom

from vep.jwt import JWT
from vep.utils import secure_urlopen, decode_json_bytes
from vep.errors import (ConnectionError,
                        InvalidSignatureError,
                        ExpiredSignatureError,
                        AudienceMismatchError)


DEFAULT_TRUSTED_SECONDARIES = ("browserid.org", "diresworb.org",
                               "dev.diresworb.org")


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
        self._emit_warning()

    def _emit_warning(self):
        """Emit a scary warning so users will know this isn't final yet."""
        msg = "The VEP certificate format has not been finalized and may "\
              "change in backwards-incompatible ways.  If you find that "\
              "the latest version of this module cannot verify a valid "\
              "VEP assertion, please contact the author."
        warnings.warn(msg, FutureWarning, stacklevel=2)

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
        milliseconds.  This lets you verify expired assertions, e.g. for
        testing purposes.
        """
        if now is None:
            now = int(time.time() * 1000)
        data = decode_json_bytes(assertion)
        # This catches KeyError and turns it into ValueError.
        try:
            # Check that the assertion is usable and valid.
            # No point doing all that crypto if we're going to fail out anyway.
            assertion = JWT.parse(data["assertion"])
            if audience is not None:
                if assertion.payload["aud"] != audience:
                    raise AudienceMismatchError(assertion.payload["aud"])
            if assertion.payload["exp"] < now:
                raise ExpiredSignatureError(assertion.payload["exp"])
            # Parse out the list of certificates.
            certificates = data["certificates"]
            certificates = [JWT.parse(c) for c in certificates]
            # Check that the root issuer is trusted.
            # No point doing all that crypto if we're going to fail out anyway.
            email = certificates[-1].payload["principal"]["email"]
            root_issuer = certificates[0].payload["iss"]
            if root_issuer not in self.trusted_secondaries:
                if not email.endswith("@" + root_issuer):
                    msg = "untrusted root issuer: %s" % (root_issuer,)
                    raise InvalidSignatureError(msg)
            # Verify the entire chain of certificates.
            cert = self.verify_certificate_chain(certificates, now=now)
            # Check the signature on the assertion.
            if not assertion.check_signature(cert.payload["public-key"]):
                raise InvalidSignatureError("invalid signature on assertion")
        except KeyError:
            raise ValueError("Malformed JWT")
        # Looks good!
        return {
          "status": "okay",
          "audience": assertion.payload["aud"],
          "email": email,
          "issuer": root_issuer,
        }

    def get_public_key(self, hostname):
        """Get the VEP public key for the given hostname.

        This method keeps a local in-memory cache of public keys, and uses
        that to fulfill requests if possible.  If the key is not available
        locally then it calls fetch_public_key() to retreive it.
        This function uses the well-known host meta-data file to locate and
        download the public key for the given hostname.  It keeps a cache
        in memory to avoid hitting the internet for every check.
        """
        # TODO: periodically expire the cache
        try:
            (ok, key) = self.public_keys[hostname]
        except KeyError:
            try:
                key = self.fetch_public_key(hostname)
                ok = True
            except Exception, e:
                key = str(e)
                ok = False
            self.public_keys[hostname] = (ok, key)
        if not ok:
            raise ConnectionError(key)
        return key

    def fetch_public_key(self, hostname):
        """Fetch the VEP public key for the given hostname.

        This function uses the well-known host meta-data file to locate and
        download the public key for the given hostname.  It keeps a cache
        in memory to avoid hitting the internet for every check.
        """
        hostname = "https://" + hostname
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
                # This will be caught by the enclosing try-except.
                # Just like a goto...
                raise ValueError("Host has no public key file")
        except Exception, e:
            # We have no guarantee what sort of error will get raised
            # or how to find the status code from it :-(
            if "404" not in str(e):
                raise
            pubkey_url = urljoin(hostname, "/pk")
        # Now read the public key from that URL.
        key = self._urlread(urljoin(hostname, pubkey_url))
        return json.loads(key)

    def verify_certificate_chain(self, certificates, now=None):
        """Verify a signed chain of certificates.

        This function checks the signatures on the given chain of JWT
        certificates.  It looks up the public key for the issuer of the
        first certificate, then uses each certificate in turn to check the
        signature on its successor.

        If the entire chain is valid then to final certificate is returned.
        """
        if not certificates:
            raise ValueError("chain must have at least one certificate")
        if now is None:
            now = int(time.time() * 1000)
        root_issuer = certificates[0].payload["iss"]
        root_key = self.get_public_key(root_issuer)
        current_key = root_key
        for cert in certificates:
            if cert.payload["exp"] < now:
                raise ExpiredSignatureError("expired certificate in chain")
            if not cert.check_signature(current_key):
                raise InvalidSignatureError("bad signature in chain")
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
            try:
                data = resp.read(int(content_length))
            except ValueError:
                raise ConnectionError("server sent invalid content-length")
        return data
