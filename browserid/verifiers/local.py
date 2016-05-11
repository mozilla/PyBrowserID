# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import re
import time
import warnings

from browserid import jwt
from browserid.verifiers import Verifier
from browserid.supportdoc import SupportDocumentManager
from browserid.utils import unbundle_certs_and_assertion
from browserid.errors import (InvalidSignatureError,
                              ExpiredSignatureError,
                              UnsupportedCertChainError)


VALID_EMAIL = re.compile(r"^([\w!#$%&'*+/=?^`{|}~.\-]+)@" + \
                         r"([\w.\-]+(:[0-9]{1,5})?)$")


class LocalVerifier(Verifier):
    """Class for local verification of BrowserID identity assertions.

    This class implements the logic for verifying identity assertions under
    the Verified Email Protocol.  Pass a BrowserID assertion token to the
    verify() method and let it work its magic.
    """

    def __init__(self, audiences=None, trusted_secondaries=None,
                 supportdocs=None, warning=True):
        super(LocalVerifier, self).__init__(audiences)
        self.trusted_secondaries = trusted_secondaries
        self.supportdocs = supportdocs or SupportDocumentManager()

        if warning:
            _emit_warning()

    def parse_jwt(self, data):
        return jwt.parse(data)

    def verify(self, assertion, audience=None, now=None):
        """Verify the given BrowserID assertion.

        This method parses a BrowserID identity assertion, verifies the
        bundled chain of certificates and signatures, and returns the
        extracted email address and audience.

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

        # This catches KeyError and turns it into ValueError.
        # It saves having to test for the existence of individual
        # items in the various assertion payloads.
        try:
            # Check the audience against the given value, or the wildcards.
            self.check_audience(assertion, audience)

            # Grab the assertion, check that it has not expired.
            # No point doing all that crypto if we're going to fail out anyway.
            certificates, assertion = unbundle_certs_and_assertion(assertion)
            if len(certificates) > 1:
                raise UnsupportedCertChainError("too many certs")
            assertion = self.parse_jwt(assertion)
            if assertion.payload["exp"] < now:
                raise ExpiredSignatureError(assertion.payload["exp"])

            # Parse out the list of certificates.
            certificates = [self.parse_jwt(c) for c in certificates]

            # Extract the email, and the hostname of its provider.
            email = certificates[-1].payload["principal"]["email"]
            match = VALID_EMAIL.match(email)
            if match is None:
                raise ValueError("invalid email in assertion")
            provider = match.group(2)

            # Check that the root issuer is trusted.
            # No point doing all that crypto if we're going to fail out anyway.
            root_issuer = certificates[0].payload["iss"]
            if not self.is_trusted_issuer(provider, root_issuer):
                msg = "untrusted root issuer: %s" % (root_issuer,)
                raise InvalidSignatureError(msg)

            # Verify the entire chain of certificates.
            cert = self.verify_certificate_chain(certificates, now=now)

            # Check the signature on the assertion.
            if not self.check_token_signature(assertion, cert):
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

    def is_trusted_issuer(self, hostname, issuer):
        """Check whether the issuer is trusted for a given hostname."""
        return self.supportdocs.is_trusted_issuer(hostname, issuer,
                                                  self.trusted_secondaries)

    def check_token_signature(self, data, cert):
        """Check for a valid signature on the given JWT."""
        return data.check_signature(cert.payload["public-key"])

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
        root_key = self.supportdocs.get_key(root_issuer)
        current_key = root_key
        for cert in certificates:
            if cert.payload["exp"] < now:
                raise ExpiredSignatureError("expired certificate in chain")
            if not cert.check_signature(current_key):
                raise InvalidSignatureError("bad signature in chain")
            current_key = cert.payload["public-key"]
        return cert


def _emit_warning():
    """Emit a scary warning so users will know this isn't final yet."""
    msg = "The BrowserID certificate format has not been finalized and may "\
           "change in backwards-incompatible ways.  If you find that "\
           "the latest version of this module cannot verify a valid "\
           "BrowserID assertion, please contact the author."
    warnings.warn(msg, FutureWarning, stacklevel=3)
