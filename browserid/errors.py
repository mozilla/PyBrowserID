# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Error classes for PyBrowserID.

"""


class Error(Exception):
    """Base error class for all PyBrowserID exceptions."""
    pass


class ConnectionError(Error):
    """Error raised when PyBrowserID fails to connect to a remote server."""
    description = 'Failed to connect to remote server.'


class TrustError(Error):
    """Base error class when assertions are well-formed but untrusted."""
    description = 'Untrusted assertion.'


class InvalidSignatureError(TrustError):
    """Error raised when PyBrowserID encounters an invalid signature."""
    description = 'Signature is invalid.'


class InvalidIssuerError(TrustError):
    """Error raised when a cert is from an invalid/untrusted issuer."""
    description = 'Certificate issued by invalid or untrusted issuer.'


class ExpiredSignatureError(TrustError):
    """Error raised when PyBrowserID encounters an expired signature."""
    description = 'Signature is expired.'


class AudienceMismatchError(TrustError):
    """Error raised when the audience does not match."""
    description = 'Audience does not match server.'


class UnsupportedCertChainError(TrustError):
    """The spec for multi-cert chains is in flux; we don't support them yet."""
    description = 'Multiple-certificate chains not supported.'
