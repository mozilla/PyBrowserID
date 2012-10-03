# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import sys
import json
import collections
import threading
import time

if sys.version_info > (3,):
    from urllib.parse import urljoin
else:
    from urlparse import urljoin  # NOQA

from browserid import netutils
from browserid.errors import (ConnectionError,
                              InvalidIssuerError)

WELL_KNOWN_URL = "/.well-known/browserid"

DEFAULT_MAX_DELEGATIONS = 6

DEFAULT_TRUSTED_SECONDARIES = ("browserid.org", "diresworb.org",
                               "dev.diresworb.org" "login.anosrep.org",
                               "login.persona.org")


class SupportDocumentManager(object):
    """Manager for mapping hostnames to their BrowserID support documents.

    This object handles the association of a hostname with its BrowserID
    support document, if any.  It automatically fetches support documents
    as required and stores them in a cache for future reference.
    """

    def __init__(self, cache=None, verify=None, **kwargs):
        self.verify = verify
        if cache is None:
            cache = FIFOCache(**kwargs)
        self.cache = cache

    def get_support_document(self, hostname):
        """Get the BrowserID support document for the given hostname."""
        try:
            # Use a cached key if available.
            (error, supportdoc) = self.cache[hostname]
        except KeyError:
            # Fetch the key afresh from the specified server.
            # Cache any failures so we're not flooding bad hosts.
            error = supportdoc = None
            try:
                supportdoc = self.fetch_support_document(hostname)
            except Exception as e:  # NOQA
                error = e
            self.cache[hostname] = (error, supportdoc)
        if error is not None:
            raise error
        return supportdoc

    def get_key(self, hostname):
        """Get the public key for verifying assertions from the given host."""
        supportdoc = self.get_support_document(hostname)
        try:
            key = supportdoc['public-key']
        except KeyError:
            raise InvalidIssuerError(
                    "Host %r doesn't provide a public key" % hostname)

        return key

    def fetch_support_document(self, hostname):
        """Fetch the BrowserID support document for the given hostname."""
        return fetch_support_document(hostname, verify=self.verify)

    def is_trusted_issuer(self, hostname, issuer, trusted_secondaries=None,
            max_delegations=DEFAULT_MAX_DELEGATIONS):
        """Check whether an issuer is trusted to assert for a given hostname.

        This method checks whether the given issuer is trusted to assert
        identitiers for the given hostname.  There are three cases in which
        this can be true:

          * The hostname and issuer and the same
          * The issuer is in the list of trusted secondaries
          * The hostname delegates authority to the issuer

        You can disable the check for delegated authority by setting the
        max_delegations argument to 0.
        """
        if hostname == issuer:
            return True

        if trusted_secondaries is None:
            trusted_secondaries = DEFAULT_TRUSTED_SECONDARIES

        if issuer in trusted_secondaries:
            return True

        num_delegations = 0
        while num_delegations < max_delegations:
            try:
                supportdoc = self.get_support_document(hostname)
            except (InvalidIssuerError, ConnectionError):
                break
            authority = supportdoc.get("authority")
            if authority is None:
                break
            if authority == issuer:
                return True
            hostname = authority
            num_delegations += 1

        return False


class FIFOCache(object):
    """A simple in-memory FIFO cache for BrowserID public keys.

    This is a *very* simple in-memory FIFO cache, used as the default object
    for caching BrowserID public keys in the LocalVerifier.  Items are kept
    for 'cache_timeout' seconds before being evicted from the cache.  If the
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
                    raise KeyError
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


def fetch_support_document(hostname, well_known_url=None, verify=None):
    """Fetch the BrowserID well-known file for the given hostname.

    This function fetches and parses the well-known BrowserID meta-data file.

    :param verify: verify the certificate when requesting ssl resources
    """
    if well_known_url is None:
        well_known_url = WELL_KNOWN_URL

    hostname = 'https://%s' % hostname

    # Try to find the support document.  If it can't be found then we
    # raise an InvalidIssuerError.  Any other connection-related
    # errors are passed back up to the caller.
    response = netutils.get(urljoin(hostname, well_known_url), verify=verify)
    if response.status_code == 200:
        try:
            data = json.loads(response.text)
        except ValueError:
            raise InvalidIssuerError('Host %r has malformed BrowserID '
                                     'support document' % hostname)
    else:
        # The well-known file was not found, try falling back to
        # just "/pk".
        response = netutils.get(urljoin(hostname, '/pk'), verify=verify)
        if response.status_code == 200:
            try:
                key = json.loads(response.text)
            except ValueError:
                raise InvalidIssuerError('Host %r has malformed BrowserID '
                                         'metadata document' % hostname)

            data = {"public-key": key}
        else:
            raise InvalidIssuerError('Host %r does not declare support for '
                                     'BrowserID' % hostname)

    return data
