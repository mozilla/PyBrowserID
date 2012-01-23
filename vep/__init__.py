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
__ver_minor__ = 3
__ver_patch__ = 1
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
    default configuration.  If you have more particular needs, create your own
    instance of RemoteVerifier and use its verify() methd.
    """
    global _DEFAULT_REMOTE_VERIFIER
    if _DEFAULT_REMOTE_VERIFIER is None:
        _DEFAULT_REMOTE_VERIFIER = RemoteVerifier()
    return _DEFAULT_REMOTE_VERIFIER.verify(assertion, audience)


def verify_local(assertion, audience=None):
    """Verify the given VEP assertion by doing local certificate checking.

    This is a convenience wrapper that uses the LocalVerifier class in its
    default configuration.  If you have more particular needs, create your own
    instance of LocalVerifier and use its verify() methd.
    """
    global _DEFAULT_LOCAL_VERIFIER
    if _DEFAULT_LOCAL_VERIFIER is None:
        _DEFAULT_LOCAL_VERIFIER = LocalVerifier()
    return _DEFAULT_LOCAL_VERIFIER.verify(assertion, audience)


def verify_dummy(assertion, audience=None):
    """Verify the given VEP assertion as a dummy assertion.

    This is a convenience wrapper that uses the DummyVerifier class in its
    default configuration.  If you have more particular needs, create your own
    instance of DummyVerifier and use its verify() methd.
    """
    global _DEFAULT_DUMMY_VERIFIER
    if _DEFAULT_DUMMY_VERIFIER is None:
        _DEFAULT_DUMMY_VERIFIER = DummyVerifier()
    return _DEFAULT_DUMMY_VERIFIER.verify(assertion, audience)
