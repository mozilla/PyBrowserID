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
import unittest
import warnings

import vep
from vep import jwt
from vep import RemoteVerifier, LocalVerifier, DummyVerifier
from vep.verifiers.local import FIFOCache
from vep.utils import encode_json_bytes, decode_json_bytes
from vep.errors import (TrustError,
                        ConnectionError,
                        ExpiredSignatureError,
                        InvalidSignatureError,
                        InvalidIssuerError,
                        AudienceMismatchError)

# This is an old assertion I generated on myfavoritebeer.org.
# It's expired and signed with an old private key.
EXPIRED_ASSERTION = """
    eyJjZXJ0aWZpY2F0ZXMiOlsiZXlKaGJHY2lPaUpTVXpJMU5pSjkuZXlKcGMzTWlPaUppY2
    05M2MyVnlhV1F1YjNKbklpd2laWGh3SWpveE16SXpPVGcyTURJM01qUXdMQ0pwWVhRaU9q
    RXpNak00T1RrMk1qY3lOREFzSW5CMVlteHBZeTFyWlhraU9uc2lZV3huYjNKcGRHaHRJam
    9pUkZNaUxDSjVJam9pT1RCa056azBabVkzWmpVeE56WTNZVEJpWm1GaU5UQTVOVFZrTXpR
    ek1qQmxNemhtTldKbE1qSmhaVFE1TURNME5qQmlabUk0TmpFMk1qTTVOamhtTW1Oa09EQX
    lOemd4Tm1FeU5ESXhaR0ZqWWpnNU9UTTJOalF6WWpRNVlXRTVOMkU1T0RSa01UVmpaakU0
    WXpZeFpEUXlNemcyWWpRM01UQTJNR0kyWlRVMU9HSXhObVZsTTJZMVkyWmlaVEZoTmpVeU
    5tUXpNelpoT0RFMVlUZzROelExTXpFNU1UVmpOVEk1TlRoaVpqWXdaalV6TkRoaU5XTXdO
    RGc0T0Raa00yRTNNVGt5WWpBeU9EWm1ZV0kzT1Roak5HVmtNekkzWlRGa01HUXlZMk0yWk
    RKa05tTmpOV014T0dObU5UWXhORFZqTm1Zd01qVXpNamswWldZeU0yVmhZbVk0TXpSa05E
    aGlOakZoTldRME9UUm1PREptTWpWak5XUmlZbUV6TVRreE16UmtZbU13WlRka05EbGhaRE
    kyWW1NeE1EWXdaR016TW1GaU5tTTNabUpoWkdNNVpHRmtaV0ZpWlRZMllXUmpaR0poTm1F
    ME5ESm1PV1poWmprelkyUXdOV000WVRFNU5ERTFaalF5WldFMk9HRXlNV1ZtWlRWbE16UX
    hNV1poWm1Wa05XVm1NR1ZqTjJVd01XRmlNMlExTXpsbE16TmxOemMxWmpWbU0yVXdZVFpr
    TkRnNU16WmtOVEprT0RNeU5ERm1ZbU5rWW1abFpXTXdZalJrWmprME5EWTRNbU0wWVRZMk
    4ySmpOekJsTm1NME5UQTBObUptWlRrek9UUmlNMkkwTW1NeU5UQXdOMlF5WXpJMVpUaGpO
    MlZoWWpObFpETXhZVGNpTENKd0lqb2laRFpqTkdVMU1EUTFOamszTnpVMll6ZGhNekV5Wk
    RBeVl6SXlPRGxqTWpWa05EQm1PVGsxTkRJMk1XWTNZalU0TnpZeU1UUmlObVJtTVRBNVl6
    Y3pPR0kzTmpJeU5tSXhPVGxpWWpkbE16Tm1PR1pqTjJGak1XUmpZek14Tm1VeFpUZGpOem
    c1TnpNNU5URmlabU0yWm1ZeVpUQXdZMk01T0RkalpEYzJabU5tWWpCaU9HTXdNRGsyWWpC
    aU5EWXdabVptWVdNNU5qQmpZVFF4TXpaak1qaG1OR0ptWWpVNE1HUmxORGRqWmpkbE56a3
    pOR016T1RnMVpUTmlNMlE1TkROaU56ZG1NRFpsWmpKaFpqTmhZek0wT1RSbVl6TmpObVpq
    TkRrNE1UQmhOak00TlRNNE5qSmhNREppWWpGak9ESTBZVEF4WWpkbVl6WTRPR1UwTURJNE
    5USTNZVFU0WVdRMU9HTTVaRFV4TWpreU1qWTJNR1JpTldRMU1EVmlZekkyTTJGbU1qa3pZ
    bU01TTJKalpEWmtPRGcxWVRFMU56VTNPV1EzWmpVeU9UVXlNak0yWkdRNVpEQTJZVFJtWX
    pOaVl6SXlORGRrTWpGbU1XRTNNR1kxT0RRNFpXSXdNVGMyTlRFek5UTTNZems0TTJZMVlU
    TTJOek0zWmpBeFpqZ3lZalEwTlRRMlpUaGxOMll3Wm1GaVl6UTFOMlV6WkdVeFpEbGpOV1
    JpWVRrMk9UWTFZakV3WVRKaE1EVTRNR0l3WVdRd1pqZzRNVGM1WlRFd01EWTJNVEEzWm1J
    M05ETXhOR0V3TjJVMk56UTFPRFl6WW1NM09UZGlOekF3TW1WaVpXTXdZakF3TUdFNU9HVm
    lOamszTkRFME56QTVZV014TjJJME1ERWlMQ0p4SWpvaVlqRmxNemN3WmpZME56SmpPRGMx
    TkdOalpEYzFaVGs1TmpZMlpXTTRaV1l4Wm1RM05EaGlOelE0WW1KaVl6QTROVEF6WkRneV
    kyVTRNRFUxWVdJellpSXNJbWNpT2lJNVlUZ3lOamxoWWpKbE0ySTNNek5oTlRJME1qRTNP
    V1E0Wmpoa1pHSXhOMlptT1RNeU9UZGtPV1ZoWWpBd016YzJaR0l5TVRGaE1qSmlNVGxqT0
    RVMFpHWmhPREF4Tmpaa1pqSXhNekpqWW1NMU1XWmlNakkwWWpBNU1EUmhZbUl5TW1SaE1t
    TTNZamM0TlRCbU56Z3lNVEkwWTJJMU56VmlNVEUyWmpReFpXRTNZelJtWXpjMVlqRmtOem
    MxTWpVeU1EUmpaRGRqTWpOaE1UVTVPVGt3TURSak1qTmpaR1ZpTnpJek5UbGxaVGMwWlRn
    NE5tRXhaR1JsTnpnMU5XRmxNRFZtWlRnME56UTBOMlF3WVRZNE1EVTVNREF5WXpNNE1UbG
    hOelZrWXpka1kySmlNekJsTXpsbFptRmpNelpsTURkbE1tTTBNRFJpTjJOaE9UaGlNall6
    WWpJMVptRXpNVFJpWVRrell6QTJNalUzTVRoaVpEUTRPV05sWVRaa01EUmlZVFJpTUdJM1
    pqRTFObVZsWWpSak5UWmpORFJpTlRCbE5HWmlOV0pqWlRsa04yRmxNR1ExTldJek56a3lN
    alZtWldJd01qRTBZVEEwWW1Wa056Sm1Nek5sTURZMk5HUXlPVEJsTjJNNE5EQmtaak5sTW
    1GaVlqVmxORGd4T0RsbVlUUmxPVEEyTkRabU1UZzJOMlJpTWpnNVl6WTFOakEwTnpZM09U
    bG1OMkpsT0RReU1HRTJaR013TVdRd056aGtaVFF6TjJZeU9EQm1abVl5WkRka1pHWXhNal
    E0WkRVMlpURmhOVFJpT1RNellUUXhOakk1WkRaak1qVXlPVGd6WXpVNE56azFNVEExT0RB
    eVpETXdaRGRpWTJRNE1UbGpaalpsWmlKOUxDSndjbWx1WTJsd1lXd2lPbnNpWlcxaGFXd2
    lPaUp5ZVdGdVFISm1heTVwWkM1aGRTSjlmUS5rRTQzY0NrQ2d0Z1J5TUE5N1c4Rmo2a3hG
    bUhVMGdUdVNlelhFWWxldktPZGVxNFhJV0RqeHBWUy1Fekt3X0s1bTkyS2M3dXlHSy1nRl
    VvaENjc2gxSFhHNXhBOXRwMzJvOXhFelFrWEVOR1pPU3VZMUN4NGNmOWNiYkh4UkdLdGVR
    S1RXVUdZVEhLMWJRZ09hMEFNaGpZMmc3eUwtbk5SMGJES2dBMDE0b3VkSjhjMVVQYm10dG
    1FQjRoZk43aEVVeVZKb0hDSVdGeTV1TlpiV2Q4X1NtSXhvUk9TS2dzZzNrdDJ6bWRiaWdE
    Yks3ZmFKZkMtUEg0ZVpSM1Q2dkZWTDhkTk4yMzhCN24yWlp6N1kzU1BtZ3Y3QmlGNGRJYl
    NkQmZjb2dGMlhsZHBVNTRRNE5xeTBSQjg4TUV1eWNWajZObmhyUThWOFVYRFdEQ21TaUJt
    bmciXSwiYXNzZXJ0aW9uIjoiZXlKaGJHY2lPaUpFVXpJMU5pSjkuZXlKbGVIQWlPakV6TW
    pNNE9UazNORGMyTURVc0ltRjFaQ0k2SW1oMGRIQTZMeTl0ZVdaaGRtOXlhWFJsWW1WbGNp
    NXZjbWNpZlEuZDRITjc5WnBFR0x1blVBbnNBcjFKRXAyTml0djUzTy1ib1BGNnZ0RzA5QV
    U0MGdaNzRkTi1FTTV5TnBINDZLcUpRTXZKbzlHeUhoT1hoekZZT1R2Z1EifQ
""".replace(" ", "").replace("\n", "").strip()


class VerifierTestCases(object):
    """Generic testcases for Verifier implementations."""

    def test_expired_assertion(self):
        self.assertRaises(TrustError, self.verifier.verify, EXPIRED_ASSERTION)

    def test_junk(self):
        self.assertRaises(ValueError, self.verifier.verify, "JUNK")
        self.assertRaises(ValueError, self.verifier.verify, "J")
        self.assertRaises(ValueError, self.verifier.verify, "\x01\x02")

    def test_malformed_assertions(self):
        errors = (ValueError, TrustError)
        # This one doesn't actually contain an assertion
        assertion = encode_json_bytes({})
        self.assertRaises(errors, self.verifier.verify, assertion)
        # This one has no certificates
        pub, priv = DummyVerifier._get_keypair("TEST")
        assertion = encode_json_bytes({
            "assertion": jwt.generate({"aud": "TEST"}, priv),
            "certificates": []
        })
        self.assertRaises(errors, self.verifier.verify, assertion)


class TestLocalVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.verifier = LocalVerifier()
        # There should be a warning about using this verifier.
        self.assertEquals(w[0].category, FutureWarning)

    def test_error_while_fetching_public_key(self):
        def urlopen(*args, **kwds):
            raise RuntimeError("TESTING")
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_missing_well_known_document(self):
        def urlopen(url, data):
            raise RuntimeError("404 Not Found")
        self.verifier.urlopen = urlopen
        self.assertRaises(InvalidIssuerError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_malformed_well_known_document(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def read():
                    return "I AINT NO JSON, FOOL!"
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(InvalidIssuerError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_malformed_pub_key_document(self):
        called = []
        def urlopen(url, data):
            # First call must raise 404 so it will look for /pk.
            # Second call must return invalid JSON.
            class response(object):
                @staticmethod
                def read():
                    if not called:
                        called.append(True)
                        raise ValueError("404 Not Found")
                    return "I AINT NO JSON, FOOL!"
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(InvalidIssuerError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_well_known_doc_with_no_public_key(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def read():
                    return "{}"
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(InvalidIssuerError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_well_known_doc_with_public_key(self):
        #  The browserid.org server doesn't currently have /.well-known/vep.
        #  This simulates it with a dummy key.
        def urlopen(url, data):  # NOQA
            class response(object):
                @staticmethod
                def read():
                    key = DummyVerifier.fetch_public_key("browserid.org")
                    return json.dumps({"public-key": key})
            return response
        self.verifier.urlopen = urlopen
        assertion = DummyVerifier.make_assertion("t@m.com", "http://e.com")
        self.assertTrue(self.verifier.verify(assertion))

    def test_handling_of_invalid_content_length_header_from_server(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def info():
                    return {"Content-Length": "forty-two"}
                @staticmethod  # NOQA
                def read(size):
                    raise RuntimeError  # pragma: nocover
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_error_handling_in_verify_certificate_chain(self):
        self.assertRaises(ValueError,
                          self.verifier.verify_certificate_chain, [])
        certs = decode_json_bytes(EXPIRED_ASSERTION)["certificates"]
        certs = [jwt.parse(cert) for cert in certs]
        self.assertRaises(ExpiredSignatureError,
                          self.verifier.verify_certificate_chain, certs)


class TestRemoteVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        self.verifier = RemoteVerifier()

    def test_handling_of_valid_response_from_server(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def read():
                    return '{"email": "t@m.com", '\
                           ' "status": "okay", '\
                           ' "audience": "http://myfavoritebeer.org"}'
            return response
        self.verifier.urlopen = urlopen
        data = self.verifier.verify(EXPIRED_ASSERTION)
        self.assertEquals(data["email"], "t@m.com")

    def test_handling_of_invalid_content_length_header_from_server(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def info():
                    return {"Content-Length": "forty-two"}
                @staticmethod  # NOQA
                def read(size):
                    raise RuntimeError  # pragma: nocover
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION)

    def test_handling_of_invalid_json_from_server(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def read():
                    return "SERVER RETURNS SOMETHING THAT ISNT JSON"
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION)

    def test_handling_of_incorrect_audience_returned_by_server(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def read():
                    return '{"email": "t@m.com", '\
                           ' "status": "okay", '\
                           '"audience": "WRONG"}'
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(AudienceMismatchError,
                          self.verifier.verify, EXPIRED_ASSERTION)

    def test_handling_of_500_error_from_server(self):
        def urlopen(url, data):
            raise ConnectionError("500 Server Error")
        self.verifier.urlopen = urlopen
        self.assertRaises(ValueError,
                          self.verifier.verify, EXPIRED_ASSERTION)

    def test_handling_of_503_error_from_server(self):
        def urlopen(url, data):
            raise ConnectionError("503 Back Off Will Ya?!")
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION)


class TestDummyVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.verifier = DummyVerifier()
        # There should be no warnings from the dummy verifier.
        self.assertEquals(len(w), 0)

    def test_verification_of_valid_dummy_assertion(self):
        audience = "http://example.com"
        assertion = self.verifier.make_assertion("test@example.com", audience)
        self.assertTrue(self.verifier.verify(assertion))
        self.assertTrue(self.verifier.verify(assertion, audience))
        self.assertRaises(AudienceMismatchError,
                          self.verifier.verify, assertion, "http://moz.com")

    def test_verification_of_oldstyle_dummy_assertion(self):
        audience = "http://example.com"
        assertion = self.verifier.make_assertion("test@example.com", audience,
                                                 new_style=False)
        self.assertTrue(self.verifier.verify(assertion))
        self.assertTrue(self.verifier.verify(assertion, audience))
        self.assertRaises(AudienceMismatchError,
                          self.verifier.verify, assertion, "http://moz.com")

    def test_verification_of_untrusted_issuer(self):
        audience = "http://example.com"
        issuer = "moz.com"
        # Assertions for @moz.com addresses can come from moz.com
        assertion = self.verifier.make_assertion("test@moz.com", audience,
                                                 issuer=issuer)
        self.assertTrue(self.verifier.verify(assertion, audience))
        # But assertions for other addresses cannot.
        assertion = self.verifier.make_assertion("test@example.com", audience,
                                                 issuer=issuer)
        self.assertRaises(InvalidSignatureError,
                          self.verifier.verify, assertion, audience)

    def test_verification_of_expired_dummy_assertion(self):
        audience = "http://example.com"
        now = (time.time() * 1000)
        assertion = self.verifier.make_assertion("test@example.com", audience,
                                                 exp=now - 1)
        self.assertTrue(self.verifier.verify(assertion, now=now - 2))
        self.assertRaises(ExpiredSignatureError,
                          self.verifier.verify, assertion)

    def test_verification_of_dummy_assertion_with_bad_assertion_sig(self):
        audience = "http://example.com"
        assertion = self.verifier.make_assertion("test@example.com", audience,
                                                 assertion_sig="BADTOTHEBONE")
        self.assertRaises(InvalidSignatureError,
                          self.verifier.verify, assertion)

    def test_verification_of_dummy_assertion_with_bad_certificate_sig(self):
        audience = "http://example.com"
        assertion = self.verifier.make_assertion("test@example.com", audience,
                                                 certificate_sig="CORRUPTUS")
        self.assertRaises(InvalidSignatureError,
                          self.verifier.verify, assertion)

    def test_cache_eviction_based_on_time(self):
        cache = FIFOCache(cache_timeout=0.1)
        verifier = DummyVerifier(cache=cache)
        # Prime the cache by verifying an assertion.
        assertion = self.verifier.make_assertion("test@example.com", "")
        self.assertTrue(verifier.verify(assertion))
        # Make it error out if re-fetching the keys
        def fetch_public_key(hostname):
            raise RuntimeError("key fetch disabled")
        verifier.fetch_public_key = fetch_public_key
        # It should be in the cache, so this works fine.
        verifier.verify(assertion)
        # But after sleeping it gets evicted and the error is triggered.
        time.sleep(0.1)
        self.assertRaises(RuntimeError, verifier.verify, assertion)

    def test_cache_eviction_based_on_size(self):
        cache = FIFOCache(max_size=2)
        verifier = DummyVerifier(cache=cache)
        # Prime the cache by verifying some assertions.
        assertion1 = self.verifier.make_assertion("test@1.com", "", "1.com")
        self.assertTrue(verifier.verify(assertion1))
        assertion2 = self.verifier.make_assertion("test@2.com", "", "2.com")
        self.assertTrue(verifier.verify(assertion2))
        self.assertEquals(len(cache), 2)
        # Hitting a third host should evict the first public key.
        assertion3 = self.verifier.make_assertion("test@3.com", "", "3.com")
        self.assertTrue(verifier.verify(assertion3))
        self.assertEquals(len(cache), 2)
        # Make it error out if re-fetching any keys
        def fetch_public_key(hostname):
            raise RuntimeError("key fetch disabled")
        verifier.fetch_public_key = fetch_public_key
        # It should have to re-fetch for 1, but not 2.
        self.assertTrue(verifier.verify(assertion2))
        self.assertRaises(RuntimeError, verifier.verify, assertion1)

    def test_cache_eviction_during_write(self):
        cache = FIFOCache(cache_timeout=0.1)
        verifier = DummyVerifier(cache=cache)
        # Prime the cache by verifying an assertion.
        assertion1 = self.verifier.make_assertion("test@1.com", "", "1.com")
        self.assertTrue(verifier.verify(assertion1))
        self.assertEquals(len(cache), 1)
        # Let that cached key expire
        time.sleep(0.1)
        # Now grab a different key; caching it should purge the expired key.
        assertion2 = self.verifier.make_assertion("test@2.com", "", "2.com")
        self.assertTrue(verifier.verify(assertion2))
        self.assertEquals(len(cache), 1)
        # Check that only the second entry is in cache.
        def fetch_public_key(hostname):
            raise RuntimeError("key fetch disabled")
        verifier.fetch_public_key = fetch_public_key
        self.assertTrue(verifier.verify(assertion2))
        self.assertRaises(RuntimeError, verifier.verify, assertion1)


class TestShortcutFunctions(unittest.TestCase):

    def test_shortcut(self):
        self.assertRaises(TrustError, vep.verify, EXPIRED_ASSERTION)

    def test_shortcut_remote(self):
        self.assertRaises(TrustError, vep.verify_remote, EXPIRED_ASSERTION)

    def test_shortcut_local(self):
        with warnings.catch_warnings():
            warnings.simplefilter("always")
            self.assertRaises(TrustError, vep.verify_local, EXPIRED_ASSERTION)

    def test_shortcut_dummy(self):
        self.assertRaises(TrustError, vep.verify_dummy, EXPIRED_ASSERTION)
