========================================================
PyBrowserID: a python library for the BrowserID Protocol
========================================================

This is a python client library for the BrowserID protocol that underlies
Mozilla Persona:

    https://login.persona.org/

For the vast majority of deployments, you will simply want to call the module-
level "verify" functon to verify a given assertion::

    >>> data = browserid.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

The precise implementation of this function will change depending on the
current recommendations of the BrowserID team.  Currently it POSTs the
assertion to the remote verifier service on persona.org.

Note that you *must* specify your site's root URL as the second argument
to that function.  This is the "expected audience" and is a key security
feature of BrowserID.

If you are not able to determine the precise hostname by which your site
is being accessed (e.g. due to virtual hosting) then you may specify one or
more wildcard patterns like so::

    >>> data = browserid.verify(BROWSERIDASSERTION, ["http://*.mysite.com"])
    >>> print data["email"]
    "test@example.com"

For finer control over the verification process, you can create an instance of
a "Verifier" class and avoid having to specify the audience patterns over
and over again::

    >>> verifier = browserid.RemoteVerifier(["*.mysite.com"])
    >>> data = verifier.verify(BROWSERIDASSERTION)
    >>> print data["email"]
    "test@example.com"

For improved performance, or if you just want to live on the bleeding edge,
you can explicitly perform verification locally by using the LocalVerifier
class like so::

    >>> verifier = browserid.LocalVerifier(["*.mysite.com"])
    >>> data = verifier.verify(BROWSERIDASSERTION)
    >>> print data["email"]
    "test@example.com"

Note that the details of the BrowserID Protocol are still in flux, so
local verification might break due to incompatible changes.  As things 
stabilise this will become the default implementation.
