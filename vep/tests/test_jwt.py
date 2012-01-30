# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

from vep.verifiers.dummy import DummyVerifier
from vep.utils import encode_json_bytes, encode_bytes
from vep import jwt


class TestJWT(unittest.TestCase):

    def test_error_jwt_with_no_algorithm(self):
        token = ".".join((
          encode_json_bytes({}),
          encode_json_bytes({}),
          encode_bytes("signature"),
        ))
        self.assertRaises(ValueError, jwt.parse, token)

    def test_error_jwt_with_mismatched_algorithm(self):
        pub, priv = DummyVerifier._get_keypair("TEST")
        token = jwt.generate({}, priv)
        token = jwt.parse(token)
        pub["algorithm"] = "RS"
        self.assertFalse(token.check_signature(pub))

    def test_loading_unknown_algorithms(self):
        self.assertRaises(ValueError, jwt.load_key, "os.unlink", {})
        self.assertRaises(ValueError, jwt.load_key, "EG", {})
        self.assertRaises(ValueError, jwt.load_key, "DS64", {})

    def test_rsa_verification(self):
        # This is a dummy RSA key I generated via PyCrypto.
        # M2Crypto doesn't seem to let me get at the values of e, n and d.
        # I've line wrapped it for readability.
        def _long(value):
            return long(value.replace(" ", "").replace("\n", "").strip())
        data = {
            "e": 65537L,
            "n": _long("""110897663942528265066856163966583557538666146275146
                       569193074111045116764854772535689458732714049671807506
                       396649306730328647317126800964431366624486416551078177
                       528195103050868728550429561392842977259407335332582178
                       624191611001106449477645116630750398871838788574825885
                       770446686329706009000279629721965986677219L"""),
            "d": _long("""295278123166626215026113502482091502365034141401240
                       159363282304307076544046230487782634982660202141239450
                       481640966544735782181647417005558287318200095948234745
                       214183393770321992676297531378428617531522265932631860
                       693144704788708252936752025413728425562033678747736289
                       64114133156747686886305629893015763517873L"""),
        }
        key = jwt.RS64Key(data)
        data.pop("d")
        pubkey = jwt.RS64Key(data)
        # This key should be able to sign and verify things to itself.
        self.assertTrue(pubkey.verify("hello", key.sign("hello")))
        self.assertFalse(pubkey.verify("HELLO", key.sign("hello")))

    def test_dsa_verification(self):
        # This is a dummy DSA key I generated via PyCrypto.
        # M2Crypto doesn't seem to let me get at the values of x and y.
        # I've line wrapped it for readability.
        def _hex(value):
            return hex(long(value.replace(" ", "").replace("\n", "").strip()))
        data = {
            "p": _hex("""6703904104057623261995085583676902361410672713749348
                      7374515589871295072792250899011720632358392764362903244
                      12395020783955234715731001076129344181463063193L"""),
            "q": hex(1006478751418673383937866166434285354892250535133L),
            "g": _hex("""1801778249650423365253284139284406405780267098493217
                      0320675876307450879812560049234773036938891018778074993
                      01874343843218156663689824126183823813389886834L"""),
            "y": _hex("""4148629652526876030475847300836791685289385792662680
                      5886292874741635965095055693693232436255359496594291250
                      77637642734034732001089176915352691113947372211L"""),
            "x": hex(487025797851506801093339352420308364866214860934L),
        }
        key = jwt.DS128Key(data)
        data.pop("x")
        pubkey = jwt.DS128Key(data)
        # This key should be able to sign and verify things to itself.
        self.assertTrue(pubkey.verify("hello", key.sign("hello")))
        self.assertFalse(pubkey.verify("HELLO", key.sign("hello")))
        self.assertRaises(Exception, pubkey.sign, "hello")
        # And it should gracefully handle a variety of stupid input:
        #   - signature too long
        self.assertFalse(pubkey.verify("HELLO", "X" * 100))
        #   - "r" value too large
        self.assertFalse(pubkey.verify("HELLO", ("\xFF" * 20) + "\x01" * 20))
        #   - "s" value too large
        self.assertFalse(pubkey.verify("HELLO", "\x01" + ("\xFF" * 20)))
