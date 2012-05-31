# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.
"""

Best-effort crypto primitives for PyBrowserID.

If you have M2Crypto installed, this package will provide a nice fast
implementation of the RSKey and DSKey classes needed to do the crypto
work behind BrowserID.  If you don't, you'll get a very slow but very
portable pure-python version.

"""

try:
    from browserid.crypto.m2 import Key, RSKey, DSKey
except ImportError:
    from browserid.crypto.fallback import Key, RSKey, DSKey  # NOQA
