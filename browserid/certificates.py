# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
import json
import collections
import threading
import time
from urlparse import urljoin

import requests
from requests.exceptions import RequestException

from browserid.errors import (ConnectionError,
                              InvalidIssuerError)

WELL_KNOWN_URL = "/.well-known/browserid"


class CertificatesManager(object):
    """A simple certificate handler. It acts like a dictionary of
    certificates. The key being the hostname and the value the certificate
    itself. the certificate manager populates itself automatically, so you
    don't need to fetch the public key when you get a KeyError.
    """

    def __init__(self, cache=None, verify=None, **kwargs):
        self.verify = verify
        if cache is None:
            cache = FIFOCache(**kwargs)
        self.cache = cache

    def __getitem__(self, hostname):
        try:
            # Use a cached key if available.
            (error, key) = self.cache[hostname]
        except KeyError:
            # Fetch the key afresh from the specified server.
            # Cache any failures so we're not flooding bad hosts.
            error = key = None
            try:
                key = self.fetch_public_key(hostname)
            except Exception, e:  # NOQA
                error = e
            self.cache[hostname] = (error, key)
        if error is not None:
            raise error
        return key

    def fetch_public_key(self, hostname):
        return fetch_public_key(hostname, verify=self.verify)


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

        If the key doesn't exist, it loads it using the fetch_public_key
        method.
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


def _get(url, verify):
    """Fetch resource with requests."""
    try:
        return requests.get(url, verify=verify)
    except RequestException, e:
        msg = "Impossible to get %s. Reason: %s" % (url, str(e))
        raise ConnectionError(msg)


def fetch_public_key(hostname, well_known_url=WELL_KNOWN_URL, verify=None):
    """Fetch the BrowserID public key for the given hostname.

    This function uses the well-known BrowserID meta-data file to extract
    the public key for the given hostname.

    :param verify: verify the certificate when requesting ssl resources
    """
    hostname = 'https://%s' % hostname

    # Try to find the public key.  If it can't be found then we
    # raise an InvalidIssuerError.  Any other connection-related
    # errors are passed back up to the caller.
    response = _get(urljoin(hostname, well_known_url), verify=verify)
    if response.status_code == 200:
        try:
            key = json.loads(response.text)['public-key']
        except (ValueError, KeyError):
            raise InvalidIssuerError('Host %r has malformed public key '
                                     'document' % hostname)
    else:
        # The well-known file was not found, try falling back to
        # just "/pk".
        response = _get(urljoin(hostname, '/pk'), verify=verify)
        if response.status_code == 200:
            try:
                key = json.loads(response.text)
            except ValueError:
                raise InvalidIssuerError('Host %r has malformed BrowserID '
                                         'metadata document' % hostname)
        else:
            raise InvalidIssuerError('Host %r does not declare support for '
                                     'BrowserID' % hostname)

    return key
