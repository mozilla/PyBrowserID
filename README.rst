========================================================
PyBrowserID: a python library for the BrowseriD Protocol
========================================================

This is a python client library for the BrowserID protocol:

    https://browserid.org/

For the vast majority of deployments, you will simply want to call the "verify"
functon to verify a given assertion::

    >>> data = browserid.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

The precise implementation of this function will change depending on the
current recommendedations of the BrowserID team.  Currently it POSTs the
assertion to the remote verifier services on browserid.org.

Note that you *must* specify your site's root URL as the second argument
to that function.  This is the "expected audience" and is a key security
feature of BrowserID.

If specifying the audience every time is infeasible, you can create an
instance of a "Verifier" class and specify wildcard patterns for the
expected audience::

    >>> verifier = browserid.RemoteVerifier(["*.mysite.com"])
    >>> data = verifier.verify(BROWSERIDASSERTION)
    >>> print data["email"]
    "test@example.com"

For improved performance, or if you just want to live on the bleeding edge,
you can explicitly perform verification locally like so::

    >>> verifier = browserid.LocalVerifier(["*.mysite.com"])
    >>> data = verifier.verify(BROWSERIDASSERTION)
    >>> print data["email"]
    "test@example.com"

Note that the details of the BrowserID Protocol are still in flux, so
local verification might break due to incompatible changes.  As things 
stabilise this will become the default implementation.
