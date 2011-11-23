=======================================================
PyVEP: a python library for the Verified Email Protocol
=======================================================

This is a python client library for the Verifier Email Protocol, a.k.a
Mozilla's BrowserID project.

For the most stable support, you can use the browserid.org remote verifier
service to check your assertions::

    >>> verifier = vep.RemoteVerifier()
    >>> data = verifier.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"


For improved performance, or if you just want to live on the bleeding edge,
you can perform verification locally like so::

    >>> verifier = vep.LocalVerifier()
    >>> data = verifier.verify(BROWSERIDASSERTION, "http://mysite.com")
    >>> print data["email"]
    "test@example.com"

