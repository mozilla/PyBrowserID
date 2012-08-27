# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Network-related utility functions for PyBrowserID.

"""

import requests
from requests.exceptions import RequestException

from browserid.errors import ConnectionError


def get(url, verify=True):
    """Fetch the specified URL with a GET request."""
    try:
        return requests.get(url, verify=verify)
    except RequestException, e:
        msg = "Failed to GET %s. Reason: %s" % (url, str(e))
        raise ConnectionError(msg)


def post(url, params={}, verify=True):
    """Fetch the specified URL with a POST request."""
    try:
        return requests.post(url, params, verify=verify)
    except RequestException, e:
        msg = "Failed to POST %s. Reason: %s" % (url, str(e))
        raise ConnectionError(msg)
