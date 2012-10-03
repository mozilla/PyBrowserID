# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import re
import fnmatch

from browserid.errors import AudienceMismatchError
from browserid.utils import (unbundle_certs_and_assertion,
                             decode_json_bytes)


if sys.version_info > (3,):
    basestring = (str,)


class Verifier(object):
    """Abstract base class for verifying BrowserID assertions."""

    def __init__(self, audiences=None):
        self.audiences = audiences
        self._audience_re = self._compile_audience_patterns(audiences)

    def verify(self, assertion, audience=None):
        """Verify the given BrowserID assertion.

        This method checks the validity of the given BrowserID assertion and,
        if valid, returns the dict of asserted data.  If it is not valid then
        an error will be raised.

        If the 'audience' argument is given, the assertion must be for that
        specific audience.  Otherwise, it must be for an audience matching
        one of the patterns provided in the constructor.
        """
        raise NotImplementedError

    def check_audience(self, assertion, expected_audience=None):
        """Check that the assertion matches the expected audience.

        This method verifies that the audience for the given assertion is
        as expected - either matching the audience parameter if given, or
        or matching one of the audience patterns from the constructor if not.

        If the audience matches then it is returned as a string; if not then
        an AudienceMismatchError is raised.
        """
        try:
            _, token = unbundle_certs_and_assertion(assertion)
            audience = decode_json_bytes(token.split(".")[1])["aud"]
        except (KeyError, IndexError):
            raise ValueError("Malformed JWT")
        if expected_audience is None:
            audience_re = self._audience_re
        else:
            audience_re = self._compile_audience_patterns(expected_audience)
        if audience_re is None:
            raise AudienceMismatchError
        if not audience_re.match(audience):
            raise AudienceMismatchError
        return audience

    def _compile_audience_patterns(self, audiences):
        """Compile a list of audience patterns into a regular expression."""
        if not audiences:
            return None
        if isinstance(audiences, basestring):
            audiences = (audiences,)
        regexps = []
        for pattern in audiences:
            regexp = fnmatch.translate(pattern)
            if "://" not in regexp:
                regexp = "([a-z]+://)?" + regexp
            regexps.append("(" + regexp + ")")
        return re.compile("|".join(regexps))
