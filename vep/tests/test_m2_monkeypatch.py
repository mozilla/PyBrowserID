# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import unittest

from vep.jwt import int2mpint
import vep._m2_monkeypatch as _m2


# Dummy RSA key for testing purposes.
def _long(value):
    return long(value.replace(" ", "").replace("\n", "").strip())

DUMMY_RSA_E = 65537L
DUMMY_RSA_N = _long("""110897663942528265066856163966583557538666146275146
                    569193074111045116764854772535689458732714049671807506
                    396649306730328647317126800964431366624486416551078177
                    528195103050868728550429561392842977259407335332582178
                    624191611001106449477645116630750398871838788574825885
                    770446686329706009000279629721965986677219L""")
DUMMY_RSA_D = _long("""295278123166626215026113502482091502365034141401240
                    159363282304307076544046230487782634982660202141239450
                    481640966544735782181647417005558287318200095948234745
                    214183393770321992676297531378428617531522265932631860
                    693144704788708252936752025413728425562033678747736289
                    64114133156747686886305629893015763517873L""")


class TestM2MonkeyPatch(unittest.TestCase):

    def test_setting_invalid_data_on_dsa_key(self):
        k = _m2.DSA.gen_params(512)
        k.gen_key()
        _m2.dsa_set_pub(k.dsa, k.pub)
        self.assertRaises(_m2.DSA.DSAError, _m2.dsa_set_pub, k.dsa, "\x00")
        _m2.dsa_set_priv(k.dsa, k.priv)
        self.assertRaises(_m2.DSA.DSAError, _m2.dsa_set_priv, k.dsa, "\x00")

    def test_setting_invalid_data_on_rsa_key(self):
        args = map(int2mpint, (DUMMY_RSA_E, DUMMY_RSA_N, DUMMY_RSA_D))
        k = _m2.RSA.new_key(args)
        self.assertTrue(k.verify("hello", k.sign("hello")))
        _m2.rsa_set_d(k.rsa, int2mpint(DUMMY_RSA_D))
        self.assertRaises(_m2.RSA.RSAError, _m2.rsa_set_d, k.rsa, "\x00")
        self.assertTrue(k.verify("hello", k.sign("hello")))

    def test_dsa_signing_works_with_loaded_keys(self):
        d_orig = _m2.DSA.gen_params(512)
        d_orig.gen_key()
        d_pub = _m2.DSA.load_pub_key_params(d_orig.p, d_orig.q, d_orig.g,
                                        d_orig.pub)
        d_priv = _m2.DSA.load_key_params(d_orig.p, d_orig.q, d_orig.g,
                                     d_orig.pub, d_orig.priv)
        # Check that the attributes are copied across effectively.
        for nm in ("p", "q", "g", "pub"):
            self.assertEquals(getattr(d_orig, nm), getattr(d_pub, nm))
            self.assertEquals(getattr(d_orig, nm), getattr(d_priv, nm))
        self.assertEquals(d_orig.priv, d_priv.priv)
        # Check that they can all validate signatures from original key.
        r, s = d_orig.sign("helloworld")
        self.assertTrue(d_orig.verify("helloworld", r, s))
        self.assertTrue(d_pub.verify("helloworld", r, s))
        self.assertTrue(d_priv.verify("helloworld", r, s))
        # Check that they can all validate signatures from loaded priv key.
        r, s = d_priv.sign("helloworld")
        self.assertTrue(d_orig.verify("helloworld", r, s))
        self.assertTrue(d_pub.verify("helloworld", r, s))
        self.assertTrue(d_priv.verify("helloworld", r, s))
