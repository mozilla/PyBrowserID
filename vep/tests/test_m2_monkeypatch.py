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
