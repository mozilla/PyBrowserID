# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is PyVEP
#
# The Initial Developer of the Original Code is the Mozilla Foundation.
# Portions created by the Initial Developer are Copyright (C) 2011
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
#   Ryan Kelly (rkelly@mozilla.com)
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK *****

import time
import json
from urlparse import urljoin
from xml.dom import minidom

from vep.utils import secure_urlopen, decode_bytes
from vep.jwt import JWT

import warnings
warning_message = "The VEP certificate format has not been finalized and may "\
                  "change in backwards-incompatible ways.  If you find that "\
                  "the latest version of this module cannot verify a valid "\
                  "VEP assertion, please contact the author."


def warn_about_certificate_format_changes(stacklevel=2):
    warnings.warn(warning_message, FutureWarning, stacklevel=stacklevel)


BROWSERID_VERIFIER_URL = "https://browserid.org/verify"

DEFAULT_TRUSTED_SECONDARIES = ("browserid.org", "diresworb.org",
                               "dev.diresworb.org")


class RemoteVerifier(object):
    """Class for remote verification of VEP identity assertions.

    This class submits assertions to the browserid.org verifier service
    for remote verification.  It's slower but potentially a little bit
    safer than the still-under-development LocalVerifier class.
    """

    def __init__(self, verifier_url=None, urlopen=None):
        if verifier_url is None:
            verifier_url = BROWSERID_VERIFIER_URL
        if urlopen is None:
            urlopen = secure_urlopen
        self.verifier_url = verifier_url
        self.urlopen = urlopen

    def verify(self, assertion, audience=None):
        """Verify the given VEP assertion.

        This method posts the given VEP assertion to the remove verifier
        service.  If it is successfully verified then a dict giving the
        email and audience is returned.  If it is not valid then an error
        is raised.

        If the 'audience' argument is given, it first verifies that the
        audience of the assertion matches the one given.  This can help
        avoid doing lots of crypto for assertions that can't be valid.
        If you don't specify an audience, you *MUST* validate the audience
        value returned by this method.
        """
        # Read audience from assertion if not specified.
        if audience is None:
            token = json.loads(decode_bytes(assertion))["assertion"]
            audience = json.loads(decode_bytes(token.split(".")[1]))["aud"]
        # Encode the data into x-www-form-urlencoded.
        post_data = {"assertion": assertion, "audience": audience}
        post_data = "&".join("%s=%s" % item for item in post_data.items())
        # Post it to the verifier.
        resp = self.urlopen(self.verifier_url, post_data)
        try:
            info = resp.info()
        except AttributeError:
            info = {}
        content_length = info.get("Content-Length")
        if content_length is None:
            data = resp.read()
        else:
            data = resp.read(int(content_length))
        data = json.loads(data)
        # Did it come back clean?
        if data.get('status') != "okay":
            raise ValueError(str(data))
        assert data.get('audience') == audience
        return data
