=======================================================
PyVEP: a python library for the Verified Email Protocol
=======================================================

This is a python client library for the Verified Email Protocol, a.k.a
Mozilla's BrowserID project.  See here for details:

    https://wiki.mozilla.org/Identity/Verified_Email_Protocol

And see here for how to integrate it into your website:

    https://browserid.org/

For the vast majority of deployments, you will simply want to call the "verify"
functon to verify a given assertion::

    >>> data = vep.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

The precise implementation of this function will change depending on the
current recommendedations of the BrowserID team.  Currently it POSTs the
assertion to the remote verifier services on browserid.org.

For improved performance, or if you just want to live on the bleeding edge,
you can explicitly perform verification locally like so::

    >>> data = vep.verify_local(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

Note that the details of the Verified Email Protocol are still in flux, so
local verification might break due to incompatible changes.  As things 
stabilise this will become the default implementation.

If you have specialised needs, you can also create a "verifier" class to
encapsulate any custom settings you may require.  For example, here is how
to do remote verification using a custom url-opening function::

    >>> verifier = vep.RemoteVerifier(urlopen=my_urlopen_func)
    >>> data = verifier.verify_local(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"
