# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Python library for the BrowserID identity protocol.

"""

__ver_major__ = 0
__ver_minor__ = 11
__ver_patch__ = 0
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


from browserid.errors import (Error,  # NOQA
                              ConnectionError,  # NOQA
                              TrustError,  # NOAQ
                              ExpiredSignatureError,  # NOQA
                              InvalidSignatureError,  # NOQA
                              AudienceMismatchError)  # NOQA

from browserid.verifiers.remote import RemoteVerifier  # NOQA
from browserid.verifiers.local import LocalVerifier  # NOQA


_DEFAULT_VERIFIER = None


def verify(assertion, audience=None):
    """Verify the given BrowserID assertion.

    This function uses the "best" verification method available in order to
    verify the given BrowserID assertion and return a dict of user data.  The
    best method currently involves POSTing to the hosted verifier service on
    persona.org; eventually it will do local verification.
    """
    global _DEFAULT_VERIFIER
    if _DEFAULT_VERIFIER is None:
        _DEFAULT_VERIFIER = RemoteVerifier()
    return _DEFAULT_VERIFIER.verify(assertion, audience)
