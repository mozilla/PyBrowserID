=======================================================
PyVEP: a python library for the Verified Email Protocol
=======================================================

This is a python client library for the Verified Email Protocol, a.k.a
Mozilla's BrowserID project.  See here for details:

    https://wiki.mozilla.org/Identity/Verified_Email_Protocol

And see here for how to integrate it into your website:

    https://browserid.org/

To just get something stable and working, it's currently recommended that you
use the browserid.org remote verifier service to check your assertions. Do
so like this::

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

As the Verified Email Protocol gets locked down more firmly, using the local
verifier will become the preferred method of checking VEP identity assertions.
