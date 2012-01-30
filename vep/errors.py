# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Error classes for PyVEP.

"""


class Error(Exception):
    """Base error class for all PyVEP exceptions."""
    pass


class ConnectionError(Error):
    """Error raised when PyVEP fails to connect to a remote server."""
    pass


class TrustError(Error):
    """Base error class when assertions are well-formed but untrusted."""
    pass


class InvalidSignatureError(TrustError):
    """Error raised when PyVEP encounters an invalid signature."""
    pass


class InvalidIssuerError(TrustError):
    """Error raised when a cert is from an invalid/untrusted issuer."""
    pass


class ExpiredSignatureError(TrustError):
    """Error raised when PyVEP encounters an expired signature or assertion."""
    pass


class AudienceMismatchError(TrustError):
    """Error raised when the audience does not match."""
    pass
