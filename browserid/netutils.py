# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Network-related utility functions for PyBrowserID.

"""

import socket

import requests
from requests.exceptions import RequestException

from browserid.errors import ConnectionError


def get(url, verify=True):
    """Fetch the specified URL with a GET request."""
    return request("GET", url, verify=verify)


def post(url, data={}, verify=True):
    """Fetch the specified URL with a POST request."""
    return request("POST", url, data=data, verify=verify)


def request(method, url, **kwds):
    """Make an HTTP request to the given URL."""
    try:
        return requests.request(method, url, **kwds)
    except (RequestException, socket.error) as e:
        msg = "Failed to %s %s. Reason: %s" % (method, url, str(e))
        raise ConnectionError(msg)
