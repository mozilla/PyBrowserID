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

from vep.m2_dsa_patch import DSA

class TestDSAPatch(unittest.TestCase):

    def test_signing_works_with_loaded_keys(self):
        d_orig = DSA.gen_params(512)
        d_orig.gen_key()
        d_pub = DSA.load_pub_key_params(d_orig.p, d_orig.q, d_orig.g,
                                        d_orig.pub)
        d_priv = DSA.load_key_params(d_orig.p, d_orig.q, d_orig.g,
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
