# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

from browserid.utils import encode_bytes, decode_bytes
from browserid.utils import encode_json_bytes, decode_json_bytes
from browserid.utils import get_assertion_info, u
from browserid.tests.support import unittest, EXPIRED_ASSERTION


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
        data = get_assertion_info(EXPIRED_ASSERTION)
        self.assertEquals(data["email"], "rfkelly@mozilla.com")
        self.assertEquals(data["principal"]["email"], "rfkelly@mozilla.com")
        self.assertEquals(data["audience"], "http://myfavoritebeer.org")
        self.assertEquals(data["issuer"], "login.mozilla.org")
        self.assertRaises(ValueError, get_assertion_info, "JUNK")
        self.assertRaises(ValueError, get_assertion_info, "X")
        self.assertRaises(ValueError, get_assertion_info, "\x00\x01\x02")
        bad_assertion = encode_json_bytes({"fake": "assertion"})
        self.assertRaises(ValueError, get_assertion_info, bad_assertion)
