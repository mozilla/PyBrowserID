# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import json

from browserid import netutils
from browserid.verifiers import Verifier
from browserid.errors import (InvalidSignatureError,
                              ConnectionError,
                              AudienceMismatchError)

BROWSERID_VERIFIER_URL = "https://verifier.login.persona.org/verify"


class RemoteVerifier(Verifier):
    """Class for remote verification of BrowserID identity assertions.

    This class submits assertions to the persona.org verifier service
    for remote verification.  It's slower but potentially a little bit
    safer than the still-under-development LocalVerifier class.
    """

    def __init__(self, audiences=None, verifier_url=None):
        if verifier_url is None:
            verifier_url = BROWSERID_VERIFIER_URL
        super(RemoteVerifier, self).__init__(audiences)
        self.verifier_url = verifier_url

    def verify(self, assertion, audience=None):
        """Verify the given BrowserID assertion.

        This method posts the given BrowserID assertion to the remote verifier
        service.  If it is successfully verified then a dict giving the
        email and audience is returned.  If it is not valid then an error
        is raised.

        If the 'audience' argument is given, it first verifies that the
        audience of the assertion matches the one given.  This can help
        avoid doing lots of crypto for assertions that can't be valid.
        If you don't specify an audience, you *MUST* validate the audience
        value returned by this method.
        """
        # Check the audience locally.
        # No point talking to the network if we know it's going to fail.
        # If no explicit audience was given, this will also parse it out
        # for inclusion in the request to the remote verifier service.
        audience = self.check_audience(assertion, audience)

        response = netutils.post(self.verifier_url, {'assertion': assertion,
                                                     'audience': audience})

        # BrowserID server sends "500 server error" for broken assertions.
        # For now, just translate that directly.  Should check by hand.
        if response.status_code == 500:
            raise ValueError('Malformed assertion')

        try:
            data = json.loads(response.text)
        except ValueError:
            raise ConnectionError("server returned invalid response")

        # Did it come back clean?
        if data.get('status') != "okay":
            raise InvalidSignatureError(str(data))
        if data.get('audience') != audience:
            raise AudienceMismatchError(data.get("audience"), audience)
        return data
