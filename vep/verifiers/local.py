# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import time
import json
import warnings
import collections
import threading
from urlparse import urljoin

from vep import jwt
from vep.utils import secure_urlopen, unbundle_certs_and_assertion
from vep.errors import (ConnectionError,
                        InvalidSignatureError,
                        InvalidIssuerError,
                        ExpiredSignatureError,
                        AudienceMismatchError)


DEFAULT_TRUSTED_SECONDARIES = ("browserid.org", "diresworb.org",
                               "dev.diresworb.org")


class LocalVerifier(object):
    """Class for local verification of VEP identity assertions.

    This class implements the logic for verifying identity assertions under
    the Verified Email Protocol.  Pass a VEP assertion token to the verify()
    method and let it work its magic.
    """

    WELL_KNOWN_URL = "/.well-known/vep"

    def __init__(self, urlopen=None, trusted_secondaries=None, cache=None):
        if urlopen is None:
            urlopen = secure_urlopen
        if trusted_secondaries is None:
            trusted_secondaries = DEFAULT_TRUSTED_SECONDARIES
        if cache is None:
            cache = FIFOCache()
        self.urlopen = urlopen
        self.trusted_secondaries = trusted_secondaries
        self.cached_public_keys = cache
        self._emit_warning()

    def _emit_warning(self):
        """Emit a scary warning so users will know this isn't final yet."""
        msg = "The VEP certificate format has not been finalized and may "\
              "change in backwards-incompatible ways.  If you find that "\
              "the latest version of this module cannot verify a valid "\
              "VEP assertion, please contact the author."
        warnings.warn(msg, FutureWarning, stacklevel=3)

    def verify(self, assertion, audience=None, now=None):
        """Verify the given VEP assertion.

        This method parses a VEP identity assertion, verifies the bundled
        chain of certificates and signatures, and returns the extracted
        email address and audience.

        If the 'audience' argument is given, it first verifies that the
        audience of the assertion matches the one given.  This can help
        avoid doing lots of crypto for assertions that can't be valid.
        If you don't specify an audience, you *MUST* validate the audience
        value returned by this method.

        If the 'now' argument is given, it is used as the current time in
        milliseconds.  This lets you verify expired assertions, e.g. for
        testing purposes.
        """
        if now is None:
            now = int(time.time() * 1000)
        # This catches KeyError and turns it into ValueError.
        # It saves having to test for the existence of individual
        # items in the various assertion payloads.
        try:
            certificates, assertion = unbundle_certs_and_assertion(assertion)
            # Check that the assertion is usable and valid.
            # No point doing all that crypto if we're going to fail out anyway.
            assertion = jwt.parse(assertion)
            if audience is not None:
                if assertion.payload["aud"] != audience:
                    raise AudienceMismatchError(assertion.payload["aud"])
            if assertion.payload["exp"] < now:
                raise ExpiredSignatureError(assertion.payload["exp"])
            # Parse out the list of certificates.
            certificates = [jwt.parse(c) for c in certificates]
            # Check that the root issuer is trusted.
            # No point doing all that crypto if we're going to fail out anyway.
            email = certificates[-1].payload["principal"]["email"]
            root_issuer = certificates[0].payload["iss"]
            if root_issuer not in self.trusted_secondaries:
                if not email.endswith("@" + root_issuer):
                    msg = "untrusted root issuer: %s" % (root_issuer,)
                    raise InvalidSignatureError(msg)
            # Verify the entire chain of certificates.
            cert = self.verify_certificate_chain(certificates, now=now)
            # Check the signature on the assertion.
            if not assertion.check_signature(cert.payload["public-key"]):
                raise InvalidSignatureError("invalid signature on assertion")
        except KeyError:
            raise ValueError("Malformed JWT")
        # Looks good!
        return {
          "status": "okay",
          "audience": assertion.payload["aud"],
          "email": email,
          "issuer": root_issuer,
        }

    def get_public_key(self, hostname):
        """Get the VEP public key for the given hostname.

        This method keeps a cache of public keys, and uses that to fullfil
        requests if possible.  If the key is not cached then it calls the
        fetch_public_key() method to retreive it.
        """
        try:
            # Use a cached key if available.
            (error, key) = self.cached_public_keys[hostname]
        except KeyError:
            # Fetch the key afresh from the specified server.
            # Cache any failures so we're not flooding bad hosts.
            error = key = None
            try:
                key = self.fetch_public_key(hostname)
            except Exception, e:
                error = e
            self.cached_public_keys[hostname] = (error, key)
        if error is not None:
            raise error
        return key

    def fetch_public_key(self, hostname):
        """Fetch the VEP public key for the given hostname.

        This function uses the well-known VEP meta-data file to extract
        the public key for the given hostname.
        """
        hostname = "https://" + hostname
        # Try to find the public key.  If it can't be found then we
        # raise an InvalidIssuerError.  Any other connection-related
        # errors are passed back up to the caller.
        try:
            # Try to read the well-known vep file to load the key.
            try:
                vep_url = urljoin(hostname, self.WELL_KNOWN_URL)
                vep_data = self._urlread(vep_url)
            except ConnectionError, e:
                if "404" not in str(e):
                    raise
                # The well-known file was not found, try falling back to
                # just "/pk".  Not really a good idea, but that's currently
                # the only way to get browserid.org's public key.
                pubkey_url = urljoin(hostname, "/pk")
                key = self._urlread(urljoin(hostname, pubkey_url))
                try:
                    key = json.loads(key)
                except ValueError:
                    msg = "Host %r has malformed public key document"
                    raise InvalidIssuerError(msg % (hostname,))
            else:
                # The well-known file was found, it must contain the key
                # data as part of its JSON response.
                try:
                    key = json.loads(vep_data)["public-key"]
                except (ValueError, KeyError):
                    msg = "Host %r has malformed VEP metadata document"
                    raise InvalidIssuerError(msg % (hostname,))
            return key
        except ConnectionError, e:
            if "404" not in str(e):
                raise
            msg = "Host %r does not declare support for VEP" % (hostname,)
            raise InvalidIssuerError(msg)

    def verify_certificate_chain(self, certificates, now=None):
        """Verify a signed chain of certificates.

        This function checks the signatures on the given chain of JWT
        certificates.  It looks up the public key for the issuer of the
        first certificate, then uses each certificate in turn to check the
        signature on its successor.

        If the entire chain is valid then to final certificate is returned.
        """
        if not certificates:
            raise ValueError("chain must have at least one certificate")
        if now is None:
            now = int(time.time() * 1000)
        root_issuer = certificates[0].payload["iss"]
        root_key = self.get_public_key(root_issuer)
        current_key = root_key
        for cert in certificates:
            if cert.payload["exp"] < now:
                raise ExpiredSignatureError("expired certificate in chain")
            if not cert.check_signature(current_key):
                raise InvalidSignatureError("bad signature in chain")
            current_key = cert.payload["public-key"]
        return cert

    def _urlread(self, url, data=None):
        """Read the given URL, return response as a string."""
        # Anything that goes wrong inside this function will
        # be re-raised as an instance of ConnectionError.
        try:
            resp = self.urlopen(url, data)
            try:
                info = resp.info()
            except AttributeError:
                info = {}
            content_length = info.get("Content-Length")
            if content_length is None:
                data = resp.read()
            else:
                try:
                    data = resp.read(int(content_length))
                except ValueError:
                    raise ConnectionError("server sent invalid content-length")
        except Exception, e:
            raise ConnectionError(str(e))
        return data


class FIFOCache(object):
    """A simple in-memory FIFO cache for VEP public keys.

    This is a *very* simple in-memory FIFO cache, used as the default object
    for caching VEP public keys in the LocalVerifier.  Items are kept for
    'cache_timeout' seconds before being evicted from the cache.  If the
    'max_size' argument is not None and the cache grows above this size,
    items will be evicted early in order of insertion into the cache.

    (An LFU cache would be better but that's a whole lot more work...)
    """

    def __init__(self, cache_timeout=60 * 60, max_size=1000):
        self.cache_timeout = cache_timeout
        self.max_size = max_size
        self.items_map = {}
        self.items_queue = collections.deque()
        self._lock = threading.Lock()

    def __getitem__(self, key):
        """Lookup the given key in the cache.

        This method retrieves the value cached under the given key, evicting
        it from the cache if expired.
        """
        (timestamp, value) = self.items_map[key]
        if self.cache_timeout:
            expiry_time = timestamp + self.cache_timeout
            if expiry_time < time.time():
                # Lock the cache while evicting, and double-check that
                # it hasn't been updated by another thread in the meantime.
                # This is a little more work during eviction, but it means we
                # can avoid locking in the common case of non-expired items.
                self._lock.acquire()
                try:
                    if self.items_map[key][0] == timestamp:
                        # Just delete it from items_map.  Trying to find
                        # and remove it from items_queue would be expensive,
                        # so we count on a subsequent write to clean it up.
                        del self.items_map[key]
                except KeyError:
                    pass
                finally:
                    self._lock.release()
                    raise KeyError(key)
        return value

    def __setitem__(self, key, value):
        """Cache the given value under the given key.

        This method caches the given value under the given key, checking that
        there's enough room in the cache and evicting items if necessary.
        """
        now = time.time()
        with self._lock:
            # First we need to make sure there's enough room.
            # This is a great opportunity to evict any expired items,
            # helping to keep memory small for sparse caches.
            if self.cache_timeout:
                expiry_time = now - self.cache_timeout
                while self.items_queue:
                    (e_key, e_item) = self.items_queue[0]
                    if e_item[0] >= expiry_time:
                        break
                    self.items_queue.popleft()
                    if self.items_map.get(e_key) == e_item:
                        del self.items_map[e_key]
            # If the max size has been exceeded, evict things in time order.
            if self.max_size:
                while len(self.items_map) >= self.max_size:
                    (e_key, e_item) = self.items_queue.popleft()
                    if self.items_map.get(e_key) == e_item:
                        del self.items_map[e_key]
            # Now we can store the incoming item.
            item = (now, value)
            self.items_queue.append((key, item))
            self.items_map[key] = item

    def __delitem__(self, key):
        """Remove the given key from the cache."""
        # This is a lazy delete.  Removing it from items_map means it
        # wont be found by __get__, and the entry in items_queue will
        # get cleaned up when its expiry time rolls around.
        del self.items_map[key]

    def __len__(self):
        """Get the currently number of items in the cache."""
        return len(self.items_map)
