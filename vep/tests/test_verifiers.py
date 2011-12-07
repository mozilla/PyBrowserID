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
import unittest
import warnings

from vep import RemoteVerifier, LocalVerifier, DummyVerifier
from vep.utils import encode_json_bytes, encode_bytes, decode_json_bytes
from vep.jwt import JWT, load_key
from vep.errors import (TrustError,
                        ConnectionError,
                        ExpiredSignatureError,
                        InvalidSignatureError,
                        AudienceMismatchError)

# This is an old assertion I generated on myfavoritebeer.org.
EXPIRED_ASSERTION = """
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


# This is an old assertion I generated on dev.myfavoritebeer.org.
EXPIRED_ASSERTION_DEV = """
    eyJjZXJ0aWZpY2F0ZXMiOlsiZXlKaGJHY2lPaUpFVXpJMU5pSjkuZXlKcGMzTWlPaU
    prWlhZdVpHbHlaWE4zYjNKaUxtOXlaeUlzSW1WNGNDSTZNVE15TWpFd01UZzNPVGd5
    Tnl3aWFXRjBJam94TXpJeU1ERTFORGM1T0RJNExDSndkV0pzYVdNdGEyVjVJanA3SW
    1Gc1oyOXlhWFJvYlNJNklrUlRJaXdpZVNJNklqRTNNekV6TXpZMk5tWXlaVGsyWldV
    MVpqQXpOakExTWpReVlXSTJOamxoTmpZeFpqZzBNVGMzTVRRMk1qRmpaREl3WXpWaF
    lXWXdZak15WVdOak5qVm1NVGhpT1Raa1pXWTFPV1EzWTJZeU16VTBPVGd4TldSa04y
    VXpOakl6WlRZek9XWTJOVFZqTlRnd05EazNNREkyT0RNNVpqZzROMlpoTnpRek5UaG
    pZVEl5WW1VME5ETTNNRFl3T1RBMlpHWXdNbUkxWWpRNVlqQTBOekpoWkdNd1ltUTNa
    VE5rTkRBMk1EZ3dOV1F6TnpFM05ESTJOV1UzWWpSa01URXdZVEU0WTJGaFlqQTJOak
    V6WmpaalpqVmtOV00zTmpRd016QXpOVGN3T0dRNVpEUXlaV1UyTmpnMU9XSmlOVE13
    WXpobU1HRXlNalF5T0dVMU9EaGhNRFUyWWpCak1ETmpNV0UzT0RnMU5UQm1NRGhsWV
    RJeVptRTFOR1EyTWpGak5USXhZbVUzT0RZME9UZzNaVFJoWkRKbVlqTmxZekV6WW1F
    NFlUZzNZVFkxTldNNU9HSTBZVGszTWpNek1XSXdNREF5TkRjM1pHRTRaRFUxTXpObF
    lqZzFZV0l5T1RJeE56YzFabVZoTURnME9UTTRaVEJqWkRFek9HVTFNV1ZrWkdJNVl6
    bGhPVGM1TnpZeU5qRTBZbUl3TkdJNE1XTTNNbUV3TURjM05XWmxOVEprTVRabE9XUm
    1ZbU0zTjJZM1pUQmpORGc0TkROall6UXlZekV6TVRreFlqQXpPREk1TVRabU5EWXpO
    V1kzWmpFeU5UZ3lZVEk1TW1Zd1pEVTFZakUxTnprNFl6a3hNVGt5WldJMk9UWXpOak
    EyTlRrMU0ySmpOR0ZtWlRJMUlpd2ljQ0k2SW1RMll6UmxOVEEwTlRZNU56YzFObU0z
    WVRNeE1tUXdNbU15TWpnNVl6STFaRFF3WmprNU5UUXlOakZtTjJJMU9EYzJNakUwWW
    paa1pqRXdPV00zTXpoaU56WXlNalppTVRrNVltSTNaVE16WmpobVl6ZGhZekZrWTJN
    ek1UWmxNV1UzWXpjNE9UY3pPVFV4WW1aak5tWm1NbVV3TUdOak9UZzNZMlEzTm1aal
    ptSXdZamhqTURBNU5tSXdZalEyTUdabVptRmpPVFl3WTJFME1UTTJZekk0WmpSaVpt
    STFPREJrWlRRM1kyWTNaVGM1TXpSak16azROV1V6WWpOa09UUXpZamMzWmpBMlpXWX
    lZV1l6WVdNek5EazBabU16WXpabVl6UTVPREV3WVRZek9EVXpPRFl5WVRBeVltSXhZ
    emd5TkdFd01XSTNabU0yT0RobE5EQXlPRFV5TjJFMU9HRmtOVGhqT1dRMU1USTVNak
    kyTmpCa1lqVmtOVEExWW1NeU5qTmhaakk1TTJKak9UTmlZMlEyWkRnNE5XRXhOVGMx
    Tnpsa04yWTFNamsxTWpJek5tUmtPV1F3Tm1FMFptTXpZbU15TWpRM1pESXhaakZoTn
    pCbU5UZzBPR1ZpTURFM05qVXhNelV6TjJNNU9ETm1OV0V6Tmpjek4yWXdNV1k0TW1J
    ME5EVTBObVU0WlRkbU1HWmhZbU0wTlRkbE0yUmxNV1E1WXpWa1ltRTVOamsyTldJeE
    1HRXlZVEExT0RCaU1HRmtNR1k0T0RFM09XVXhNREEyTmpFd04yWmlOelF6TVRSaE1E
    ZGxOamMwTlRnMk0ySmpOemszWWpjd01ESmxZbVZqTUdJd01EQmhPVGhsWWpZNU56UX
    hORGN3T1dGak1UZGlOREF4SWl3aWNTSTZJbUl4WlRNM01HWTJORGN5WXpnM05UUmpZ
    MlEzTldVNU9UWTJObVZqT0dWbU1XWmtOelE0WWpjME9HSmlZbU13T0RVd00yUTRNbU
    5sT0RBMU5XRmlNMklpTENKbklqb2lPV0U0TWpZNVlXSXlaVE5pTnpNellUVXlOREl4
    Tnpsa09HWTRaR1JpTVRkbVpqa3pNamszWkRsbFlXSXdNRE0zTm1SaU1qRXhZVEl5WW
    pFNVl6ZzFOR1JtWVRnd01UWTJaR1l5TVRNeVkySmpOVEZtWWpJeU5HSXdPVEEwWVdK
    aU1qSmtZVEpqTjJJM09EVXdaamM0TWpFeU5HTmlOVGMxWWpFeE5tWTBNV1ZoTjJNMF
    ptTTNOV0l4WkRjM05USTFNakEwWTJRM1l6SXpZVEUxT1RrNU1EQTBZekl6WTJSbFlq
    Y3lNelU1WldVM05HVTRPRFpoTVdSa1pUYzROVFZoWlRBMVptVTRORGMwTkRka01HRT
    JPREExT1RBd01tTXpPREU1WVRjMVpHTTNaR05pWWpNd1pUTTVaV1poWXpNMlpUQTNa
    VEpqTkRBMFlqZGpZVGs0WWpJMk0ySXlOV1poTXpFMFltRTVNMk13TmpJMU56RTRZbV
    EwT0RsalpXRTJaREEwWW1FMFlqQmlOMll4TlRabFpXSTBZelUyWXpRMFlqVXdaVFJt
    WWpWaVkyVTVaRGRoWlRCa05UVmlNemM1TWpJMVptVmlNREl4TkdFd05HSmxaRGN5Wm
    pNelpUQTJOalJrTWprd1pUZGpPRFF3WkdZelpUSmhZbUkxWlRRNE1UZzVabUUwWlRr
    d05qUTJaakU0Tmpka1lqSTRPV00yTlRZd05EYzJOems1WmpkaVpUZzBNakJoTm1Sak
    1ERmtNRGM0WkdVME16ZG1Namd3Wm1abU1tUTNaR1JtTVRJME9HUTFObVV4WVRVMFlq
    a3pNMkUwTVRZeU9XUTJZekkxTWprNE0yTTFPRGM1TlRFd05UZ3dNbVF6TUdRM1ltTm
    tPREU1WTJZMlpXWWlmU3dpY0hKcGJtTnBjR0ZzSWpwN0ltVnRZV2xzSWpvaWNubGhi
    a0J5Wm1zdWFXUXVZWFVpZlgwLkd2YW1GVzBFdVJidmF6SzAwdGVJWnRpYlYxOU9tbV
    UweDlJSGtHZjdWamVJSTZSeG41QWdOaEJxMFRjZTRBbDcxNU1jbUF0bDBidFNHd0hr
    azN5ZnJnIl0sImFzc2VydGlvbiI6ImV5SmhiR2NpT2lKRVV6STFOaUo5LmV5SmxlSE
    FpT2pFek1qSXdNall3TWpJMU1qZ3NJbUYxWkNJNkltaDBkSEE2THk5a1pYWXViWGxt
    WVhadmNtbDBaV0psWlhJdWIzSm5JbjAuZUVvS2FGdUJQV0lSRnBFQ2ZmREU3b2wtej
    RaM0Y5djNvZjhhNU1SWVpXNkQzN3dOSWlNYmRZTEJBTHRzR3Z3RVZ2ZC1ncWpldWtt
    Z1hHTWM0Ynl0dFEifQ
""".replace(" ", "").replace("\n", "").strip()


class VerifierTestCases(object):
    """Generic testcases for Verifier implementations."""

    def test_expired_assertion(self):
        self.assertRaises(TrustError,
                          self.verifier.verify, EXPIRED_ASSERTION)

    def test_expired_assertion_dev(self):
        self.assertRaises(TrustError,
                          self.verifier.verify, EXPIRED_ASSERTION_DEV)

    def test_junk(self):
        self.assertRaises(ValueError, self.verifier.verify, "JUNK")
        self.assertRaises(ValueError, self.verifier.verify, "J")
        self.assertRaises(ValueError, self.verifier.verify, "\x01\x02")

    def test_malformed_assertions(self):
        # This one doesn't actually contain an assertion
        assertion = encode_json_bytes({})
        self.assertRaises(ValueError, self.verifier.verify, assertion)
        # This one has no certificates
        pub, priv = DummyVerifier._get_keypair("TEST")
        assertion = encode_json_bytes({
            "assertion": JWT.generate({"aud": "TEST"}, priv),
            "certificates": []
        })
        self.assertRaises(ValueError, self.verifier.verify, assertion)


class TestLocalVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("default")
            self.verifier = LocalVerifier()

    def test_expired_assertion(self):
        super(TestLocalVerifier, self).test_expired_assertion()
        # It'll verify OK if we wind back the clock.
        data = self.verifier.verify(EXPIRED_ASSERTION, now=0)
        self.assertEquals(data["audience"], "http://myfavoritebeer.org")
        # And will fail if we give the wrong audience.
        self.assertRaises(AudienceMismatchError,
                          self.verifier.verify, EXPIRED_ASSERTION, "h", 0)

    def test_expired_assertion_dev(self):
        super(TestLocalVerifier, self).test_expired_assertion_dev()
        # It'll verify OK if we wind back the clock.
        data = self.verifier.verify(EXPIRED_ASSERTION_DEV, now=0)
        self.assertEquals(data["audience"], "http://dev.myfavoritebeer.org")
        # And will fail if we give the wrong audience.
        self.assertRaises(AudienceMismatchError,
                          self.verifier.verify, EXPIRED_ASSERTION_DEV, "h", 0)

    def test_error_while_fetching_public_key(self):
        def fetch_public_key(hostname):
            raise RuntimeError("TESTING")
        self.verifier.fetch_public_key = fetch_public_key
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_missing_host_meta_document(self):
        def urlopen(url, data):
            raise RuntimeError("404 Not Found")
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_malformed_host_meta_document(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def read():
                    return "I AINT NO XML, FOOL!"
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_host_meta_with_no_key_link(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def read():
                    return "<Meta>"\
                           " <Link rel='not the key link' href='haha' />"\
                           "</Meta>"
            return response
        self.verifier.urlopen = urlopen
        self.assertRaises(ConnectionError,
                          self.verifier.verify, EXPIRED_ASSERTION, now=0)

    def test_host_meta_with_key_link(self):
        #  The browserid.org server doesn't currently have host-meta.
        #  This simulates it with a link to the known public key URL.
        called = []
        orig_urlopen = self.verifier.urlopen
        def urlopen(url, data):
            if called:
                return orig_urlopen("https://browserid.org/pk")
            called.append(True)
            class response(object):
                @staticmethod
                def read():
                    rel = self.verifier.HOST_META_REL_PUBKEY
                    return "<Meta>"\
                           " <Link rel='" + rel + "' href='haha' />"\
                           "</Meta>"
            return response
        self.verifier.urlopen = urlopen
        self.assertTrue(self.verifier.verify(EXPIRED_ASSERTION, now=0))

    def test_handling_of_invalid_content_length_header_from_server(self):
        def urlopen(url, data):
            class response(object):
                @staticmethod
                def info():
                    return {"Content-Length": "forty-two"}
                @staticmethod
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
        certs = [JWT.parse(cert) for cert in certs]
        self.assertRaises(ExpiredSignatureError,
                          self.verifier.verify_certificate_chain, certs)
        self.assertTrue(self.verifier.verify_certificate_chain(certs, 0))


class TestRemoteVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        self.verifier = RemoteVerifier()

    def test_expired_assertion_dev(self):
        self.verifier.verifier_url = "https://dev.diresworb.org/verify"
        super(TestRemoteVerifier, self).test_expired_assertion_dev()

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
                @staticmethod
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
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("default")
            self.verifier = DummyVerifier()

    def test_verification_of_valid_dummy_assertion(self):
        audience = "http://example.com"
        assertion = self.verifier.make_assertion("test@example.com", audience)
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


class TestJWT(unittest.TestCase):

    def test_error_jwt_with_no_algorithm(self):
        jwt = ".".join((
          encode_json_bytes({}),
          encode_json_bytes({}),
          encode_bytes("signature"),
        ))
        self.assertRaises(ValueError, JWT.parse, jwt)

    def test_error_jwt_with_mismatched_algorithm(self):
        pub, priv = DummyVerifier._get_keypair("TEST")
        jwt = JWT.generate({}, priv)
        jwt = JWT.parse(jwt)
        pub["algorithm"] = "RS"
        self.assertFalse(jwt.check_signature(pub))

    def test_loading_unknown_algorithms(self):
        self.assertRaises(ValueError, load_key, "os.unlink", {})
        self.assertRaises(ValueError, load_key, "EG", {})
        self.assertRaises(ValueError, load_key, "DS64", {})
