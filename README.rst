========================================================
PyBrowserID: a python library for the BrowserID Protocol
========================================================

This is a python client library for the BrowserID Protocol:

    https://browserid.org/

For the vast majority of deployments, you will simply want to call the "verify"
functon to verify a given assertion::

    >>> data = browserid.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

The precise implementation of this function will change depending on the
current recommendedations of the BrowserID team.  Currently it POSTs the
assertion to the remote verifier services on browserid.org.

If you have specialised needs, you can also create a "verifier" class to
encapsulate any custom settings you may require.  For example, here is how
to do remote verification using a custom url-opening function::

    >>> verifier = browserid.RemoteVerifier(urlopen=my_urlopen_func)
    >>> data = verifier.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

For improved performance, or if you just want to live on the bleeding edge,
you can explicitly perform verification locally like so::

    >>> verifier = browserid.LocalVerifier()
    >>> data = verifier.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

Note that the details of the Verified Email Protocol are still in flux, so
local verification might break due to incompatible changes.  As things 
stabilise this will become the default implementation.
