# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Python library for the Verified Email Protocol.

"""

__ver_major__ = 0
__ver_minor__ = 3
__ver_patch__ = 2
__ver_sub__ = ""
__ver_tuple__ = (__ver_major__, __ver_minor__, __ver_patch__, __ver_sub__)
__version__ = "%d.%d.%d%s" % __ver_tuple__


from vep.errors import (Error,  # NOQA
                        ConnectionError,  # NOQA
                        TrustError,  # NOAQ
                        ExpiredSignatureError,  # NOQA
                        InvalidSignatureError,  # NOQA
                        AudienceMismatchError)  # NOQA

from vep.verifiers.remote import RemoteVerifier  # NOQA
from vep.verifiers.local import LocalVerifier  # NOQA
from vep.verifiers.dummy import DummyVerifier  # NOQA


def verify(assertion, audience=None):
    """Verify the given VEP assertion.

    This function uses the "best" verification method available in order to
    verify the given VEP assertion and return a dict of user data.  The best
    method currently involves POSTing to the hosted verifier service on
    browserid.org; eventually it will do local verification.
    """
    return verify_remote(assertion, audience)


_DEFAULT_REMOTE_VERIFIER = None
_DEFAULT_LOCAL_VERIFIER = None
_DEFAULT_DUMMY_VERIFIER = None


def verify_remote(assertion, audience=None):
    """Verify the given VEP assertion by posting to the remote verifier.

    This is a convenience wrapper that uses the RemoteVerifier class in its
    default configuration. If you have more particular needs, create your own
    instance of RemoteVerifier and use its verify() method.
    """
    global _DEFAULT_REMOTE_VERIFIER
    if _DEFAULT_REMOTE_VERIFIER is None:
        _DEFAULT_REMOTE_VERIFIER = RemoteVerifier()
    return _DEFAULT_REMOTE_VERIFIER.verify(assertion, audience)


def verify_local(assertion, audience=None):
    """Verify the given VEP assertion by doing local certificate checking.

    This is a convenience wrapper that uses the LocalVerifier class in its
    default configuration. If you have more particular needs, create your own
    instance of LocalVerifier and use its verify() method.
    """
    global _DEFAULT_LOCAL_VERIFIER
    if _DEFAULT_LOCAL_VERIFIER is None:
        _DEFAULT_LOCAL_VERIFIER = LocalVerifier()
    return _DEFAULT_LOCAL_VERIFIER.verify(assertion, audience)


def verify_dummy(assertion, audience=None):
    """Verify the given VEP assertion as a dummy assertion.

    This is a convenience wrapper that uses the DummyVerifier class in its
    default configuration. If you have more particular needs, create your own
    instance of DummyVerifier and use its verify() method.
    """
    global _DEFAULT_DUMMY_VERIFIER
    if _DEFAULT_DUMMY_VERIFIER is None:
        _DEFAULT_DUMMY_VERIFIER = DummyVerifier()
    return _DEFAULT_DUMMY_VERIFIER.verify(assertion, audience)
