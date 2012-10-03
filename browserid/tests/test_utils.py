# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from browserid.utils import encode_bytes, decode_bytes
from browserid.utils import encode_json_bytes, decode_json_bytes
from browserid.utils import get_assertion_info, u
from browserid.tests.support import unittest


class TestUtils(unittest.TestCase):

    def test_encode_decode_bytes(self):
        self.assertEquals(b"HELLO", decode_bytes(encode_bytes(b"HELLO")))
        self.assertEquals(b"HELLO", decode_bytes(encode_bytes(u("HELLO"))))
        self.assertRaises(ValueError, decode_bytes, u("\N{SNOWMAN}"))
        self.assertRaises(ValueError, decode_bytes, "A===")

    def test_encode_decode_json_bytes(self):
        obj = {"hello": "world"}
        self.assertEquals(obj, decode_json_bytes(encode_json_bytes(obj)))
        self.assertRaises(ValueError,
                          decode_json_bytes, encode_bytes("NOJSON4U"))
        self.assertRaises(ValueError,
                          decode_json_bytes, encode_bytes("42"))
        self.assertRaises(ValueError,
                          decode_json_bytes, encode_bytes("[1, 2, 3]"))
        self.assertRaises(ValueError, encode_json_bytes, 42)
        self.assertRaises(ValueError, encode_json_bytes, [1, 3, 3])

    def test_get_assertion_info(self):
        assertion = """
        eyJjZXJ0aWZpY2F0ZXMiOlsiZXlKaGJHY2lPaUpTVXpFeU9DSjkuZXlKcGMzTWlPaUppY
        205M2MyVnlhV1F1YjNKbklpd2laWGh3SWpveE16SXhPVFF4T1Rnek1EVXdMQ0p3ZFdKc2
        FXTXRhMlY1SWpwN0ltRnNaMjl5YVhSb2JTSTZJbEpUSWl3aWJpSTZJamd4TmpreE5UQTB
        OVGswTkRVek5EVTFPREF4TlRreU5Ea3hNemsyTkRFNE56RTJNVFUwTkRNNE5EWXdPREl6
        TXpBMU1USXlPRGN3TURRNE56TTFNREk1TURrek16a3lNRFkzTURFMU1qQTBORGd6TWpVM
        U56WXdOREE1TnpFeU9EYzNNVGswT1RVek1UQXdNVFEyTkRVek56TTJOakU0TlRVek5EY3
        hNakkxT0RreU16TTFPRFV4TWpZNU1EQXdOREF5TVRrMk9ERTBNRGtpTENKbElqb2lOalU
        xTXpjaWZTd2ljSEpwYm1OcGNHRnNJanA3SW1WdFlXbHNJam9pY25saGJrQnlabXN1YVdR
        dVlYVWlmWDAua19oaEtYMFRCVnUyX2szbV9uRDVOVWJfTktwX19PLTY1MW1CRUl3S1NZZ
        GlOenQwQm9WRkNEVEVueEhQTWJCVjJaejk0WDgtLVRjVXJidEV0MWV1S1dWdjMtNTFUOU
        xBZnV6SEhfekNCUXJVbmxkMVpXSmpBM185ZEhQeTMwZzRMSU9YZTJWWmd0T1Nva3MyZFE
        4ZDNvazlSUTJQME5ERzB1MDBnN3lGejE4Il0sImFzc2VydGlvbiI6ImV5SmhiR2NpT2lK
        U1V6WTBJbjAuZXlKbGVIQWlPakV6TWpFNU1qazBOelU0TWprc0ltRjFaQ0k2SW1oMGRIQ
        TZMeTl0ZVdaaGRtOXlhWFJsWW1WbGNpNXZjbWNpZlEuQWhnS2Q0eXM0S3FnSGJYcUNSS3
        hHdlluVmFJOUwtb2hYSHk0SVBVWDltXzI0TWdfYlU2aGRIMTNTNnFnQy1vSHBpS3BfTGl
        6cDRGRjlUclBjNjBTRXcifQ
        """.replace(" ", "").replace("\n", "").strip()
        data = get_assertion_info(assertion)
        self.assertEquals(data["principal"]["email"], "ryan@rfk.id.au")
        self.assertEquals(data["audience"], "http://myfavoritebeer.org")
        self.assertRaises(ValueError, get_assertion_info, "JUNK")
        self.assertRaises(ValueError, get_assertion_info, "X")
        self.assertRaises(ValueError, get_assertion_info, "\x00\x01\x02")
        bad_assertion = encode_json_bytes({"fake": "assertion"})
        self.assertRaises(ValueError, get_assertion_info, bad_assertion)
