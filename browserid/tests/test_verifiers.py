# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import time
import warnings

from mock import Mock, patch

import browserid
from browserid.tests.support import (patched_supportdoc_fetching,
                                     get_keypair,
                                     make_assertion, unittest, callwith)
from browserid import jwt
from browserid import RemoteVerifier, LocalVerifier
from browserid.supportdoc import FIFOCache, SupportDocumentManager
from browserid.verifiers.workerpool import WorkerPoolVerifier
from browserid.tests.support import EXPIRED_ASSERTION
from browserid.utils import (encode_json_bytes,
                             normalize_timestamp,
                             bundle_certs_and_assertion,
                             unbundle_certs_and_assertion)
from browserid.errors import (TrustError,
                              ConnectionError,
                              ExpiredSignatureError,
                              InvalidSignatureError,
                              AudienceMismatchError)


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
        pub, priv = get_keypair("TEST")
        assertion = bundle_certs_and_assertion(
            [],
            jwt.generate({"aud": "TEST"}, priv),
        )
        self.assertRaises(errors, self.verifier.verify, assertion)
        # This one has too many certificates in the chain.
        assertion = bundle_certs_and_assertion(
            [jwt.generate({}, priv), jwt.generate({}, priv)],
            jwt.generate({"aud": "TEST"}, priv),
        )
        self.assertRaises(errors, self.verifier.verify, assertion)


class TestLocalVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            self.verifier = LocalVerifier(["*"])
        # There should be a warning about using this verifier.
        self.assertEquals(w[0].category, FutureWarning)

    def test_error_handling_in_verify_certificate_chain(self):
        self.assertRaises(ValueError,
                          self.verifier.verify_certificate_chain, [])
        certs = unbundle_certs_and_assertion(EXPIRED_ASSERTION)[0]
        certs = [jwt.parse(cert) for cert in certs]
        self.assertRaises(ExpiredSignatureError,
                          self.verifier.verify_certificate_chain, certs)

    @callwith(patched_supportdoc_fetching())
    def test_well_known_doc_with_public_key(self):
        assertion = make_assertion("t@m.com", "http://e.com")
        self.assertTrue(self.verifier.verify(assertion))

    @callwith(patched_supportdoc_fetching())
    def test_delegated_primary(self):
        assertion = make_assertion("t@redirect.org", "http://persona.org",
                issuer="delegated.org")
        self.assertTrue(self.verifier.verify(assertion))

    @callwith(patched_supportdoc_fetching())
    def test_double_delegated_primary(self):
        assertion = make_assertion("t@redirect-twice.org",
                "http://persona.org", issuer="delegated.org")
        self.assertTrue(self.verifier.verify(assertion))

    @callwith(patched_supportdoc_fetching())
    def test_audience_verification(self):

        # create an assertion with the audience set to http://persona.org for
        # the tests. This assertion is only valid for this audience.
        assertion = make_assertion("alexis@mozilla.com", "http://persona.org")

        # we don't set any audience explicitely here
        verifier = LocalVerifier(warning=False)

        # specifying the audience on verifier.verify uses it.
        self.assertRaises(AudienceMismatchError, verifier.verify, assertion,
                          audience="*.example.com")

        # if we change the audience to the expected one, the assertion is
        # considered valid
        self.assertTrue(verifier.verify(assertion, audience="persona.org"))

        # specifying the audience when creating the verifier AND when calling
        # verifier.verify.
        verifier = LocalVerifier(["*.example.com"], warning=False)
        self.assertRaises(AudienceMismatchError, verifier.verify, assertion,
                          audience="*.example.com")

        # specifying a different audience at instanciation and at verification,
        # only the last one is used.
        self.assertTrue(verifier.verify(assertion, audience="persona.org"))

        # overwritting the audience with an invalid one (we are waiting for
        # persona.org but getting example.com) raises an error
        self.assertRaises(AudienceMismatchError, verifier.verify,
                          audience="persona.org",
                          assertion=make_assertion("alexis@mozilla.com",
                                                   "http://example.com"))

        # the assertion is valid for http://persona.org; the verifier is
        # configured to accept this audience so it should validate
        verifier = LocalVerifier(["persona.org"], warning=False)
        self.assertTrue(verifier.verify(assertion))

        # but if we ask explicitely for a different audience (the assertion is
        # not accepted, even if the instance is configured so)
        self.assertRaises(AudienceMismatchError, verifier.verify,
                          assertion, audience="example.com")


class TestRemoteVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        self.verifier = RemoteVerifier(["*"])

    @patch('browserid.netutils.requests')
    def _verify(self, requests, response_text='', assertion=EXPIRED_ASSERTION,
                status_code=200):
        response = Mock()
        response.text = response_text
        response.status_code = status_code
        requests.request.return_value = response

        return self.verifier.verify(assertion)

    def test_handling_of_valid_response_from_server(self):
        response_text = ('{"email": "t@m.com", "status": "okay", '
                         '"audience": "http://myfavoritebeer.org"}')
        data = self._verify(response_text=response_text)
        self.assertEquals(data["email"], "t@m.com")

    def test_handling_of_invalid_json_from_server(self):
        with self.assertRaises(ConnectionError):
            self._verify(response_text='SERVER RETURNS INVALID JSON')

    @patch('browserid.netutils.requests')
    def test_handling_of_incorrect_audience_returned_by_server(self, requests):
        response_text = ('{"email": "t@m.com", "status": "okay", '
                         '"audience": "WRONG"}')
        with self.assertRaises(AudienceMismatchError):
            self._verify(response_text=response_text)

    @patch('browserid.netutils.requests')
    def test_handling_of_500_error_from_server(self, requests):
        with self.assertRaises(ValueError):
            self._verify(status_code=500)

    def test_handling_of_503_error_from_server(self):
        with self.assertRaises(ConnectionError):
            self._verify(status_code=503)


class TestDummyVerifier(unittest.TestCase, VerifierTestCases):

    def setUp(self):
        self.patched = patched_supportdoc_fetching()
        self.patched.__enter__()
        self.verifier = LocalVerifier(["*"], warning=False)

    def tearDown(self):
        self.patched.__exit__(None, None, None)

    def _make_assertion(self, *args, **kwds):
        return make_assertion(*args, **kwds)

    def test_verification_of_valid_dummy_assertion(self):
        audience = "http://example.com"
        assertion = self._make_assertion("test@example.com", audience)
        self.assertTrue(self.verifier.verify(assertion))
        self.assertTrue(self.verifier.verify(assertion, audience))
        self.assertRaises(AudienceMismatchError,
                          self.verifier.verify, assertion, "http://moz.com")

    def test_verification_with_extra_idp_claims(self):
        audience = "http://example.com"
        assertion = self._make_assertion("test@example.com", audience,
                                         idp_claims={"hello": "world"})
        info = self.verifier.verify(assertion)
        self.assertEquals(info["idpClaims"], {"hello": "world"})

    def test_verification_with_extra_user_claims(self):
        audience = "http://example.com"
        assertion = self._make_assertion("test@example.com", audience,
                                         user_claims={"hello": "world"})
        info = self.verifier.verify(assertion)
        self.assertEquals(info["userClaims"], {"hello": "world"})

    def test_verification_of_untrusted_issuer(self):
        audience = "http://example.com"
        issuer = "moz.com"
        # Assertions for @moz.com addresses can come from moz.com
        assertion = self._make_assertion("test@moz.com", audience,
                                         issuer=issuer)
        self.assertTrue(self.verifier.verify(assertion, audience))
        # But assertions for other addresses cannot (unless they delegated).
        assertion = self._make_assertion("test@example.com", audience,
                                         issuer=issuer)
        self.assertRaises(InvalidSignatureError, self.verifier.verify,
                          assertion, audience)

    def test_verification_of_expired_dummy_assertion(self):
        audience = "http://example.com"
        now = normalize_timestamp(None)
        assertion = self._make_assertion("test@example.com", audience,
                                         exp=now - 1)
        self.assertTrue(self.verifier.verify(assertion, now=now - 2))
        self.assertRaises(ExpiredSignatureError, self.verifier.verify,
                          assertion)

    def test_verification_of_future_issued_assertion(self):
        audience = "http://example.com"
        now = normalize_timestamp(None)
        assertion = self._make_assertion("test@example.com", audience,
                                         iat=now + 1)
        self.assertTrue(self.verifier.verify(assertion, now=now + 2))
        self.assertRaises(ExpiredSignatureError, self.verifier.verify,
                          assertion, now=now)

    def test_verification_of_dummy_assertion_with_bad_assertion_sig(self):
        audience = "http://example.com"
        assertion = self._make_assertion("test@example.com", audience,
                                         assertion_sig="BADTOTHEBONE")
        self.assertRaises(InvalidSignatureError, self.verifier.verify,
                          assertion)

    def test_verification_of_dummy_assertion_with_bad_certificate_sig(self):
        audience = "http://example.com"
        assertion = self._make_assertion("test@example.com", audience,
                                         certificate_sig="CORRUPTUS")
        self.assertRaises(InvalidSignatureError, self.verifier.verify,
                          assertion)

    def test_cache_eviction_based_on_time(self):
        supportdocs = SupportDocumentManager(FIFOCache(cache_timeout=0.1))
        verifier = LocalVerifier(["*"], supportdocs=supportdocs,
                warning=False)
        # Prime the cache by verifying an assertion.
        assertion = self._make_assertion("test@example.com", "")
        self.assertTrue(verifier.verify(assertion))
        # Make it error out if re-fetching the keys

        exc = RuntimeError("key fetch disabled")
        with patched_supportdoc_fetching(exc=exc):
            # It should be in the cache, so this works fine.
            self.assertTrue(verifier.verify(assertion))
            # But after sleeping it gets evicted and the error is triggered.
            time.sleep(0.1)
            self.assertRaises(RuntimeError, verifier.verify, assertion)

    def test_cache_eviction_based_on_size(self):
        supportdocs = SupportDocumentManager(max_size=2)
        verifier = LocalVerifier(["*"], supportdocs=supportdocs,
                warning=False)
        # Prime the cache by verifying some assertions.
        assertion1 = self._make_assertion("test@1.com", "", "1.com")
        self.assertTrue(verifier.verify(assertion1))
        assertion2 = self._make_assertion("test@2.com", "", "2.com")
        self.assertTrue(verifier.verify(assertion2))
        self.assertEquals(len(supportdocs.cache), 2)
        # Hitting a third host should evict the first public key.
        assertion3 = self._make_assertion("test@3.com", "", "3.com")
        self.assertTrue(verifier.verify(assertion3))
        self.assertEquals(len(supportdocs.cache), 2)
        # Make it error out if re-fetching any keys

        exc = RuntimeError("key fetch disabled")
        with patched_supportdoc_fetching(exc=exc):
            # It should have to re-fetch for 1, but not 2.
            self.assertTrue(verifier.verify(assertion2))
            self.assertRaises(RuntimeError, verifier.verify, assertion1)

    def test_cache_eviction_during_write(self):
        supportdocs = SupportDocumentManager(cache_timeout=0.1)
        verifier = LocalVerifier(["*"], supportdocs=supportdocs,
                warning=False)
        # Prime the cache by verifying an assertion.
        assertion1 = self._make_assertion("test@1.com", "", "1.com")
        self.assertTrue(verifier.verify(assertion1))
        self.assertEquals(len(supportdocs.cache), 1)
        # Let that cached key expire
        time.sleep(0.1)
        # Now grab a different key; caching it should purge the expired key.
        assertion2 = self._make_assertion("test@2.com", "", "2.com")
        self.assertTrue(verifier.verify(assertion2))
        self.assertEquals(len(supportdocs.cache), 1)
        # Check that only the second entry is in cache.

        exc = RuntimeError("key fetch disabled")
        with patched_supportdoc_fetching(exc=exc):
            self.assertTrue(verifier.verify(assertion2))
            self.assertRaises(RuntimeError, verifier.verify, assertion1)

    def test_audience_pattern_checking(self):
        verifier = LocalVerifier(["*.moz.com", "www.test.com"], warning=False)
        # Domains like *.moz.com should be valid audiences.
        # They will work with both the implicit patterns and explicit audience.
        assertion = self._make_assertion("test@example.com", "www.moz.com")
        self.assertTrue(verifier.verify(assertion))
        self.assertTrue(verifier.verify(assertion, "www.moz.com"))
        self.assertRaises(AudienceMismatchError,
                          verifier.verify, assertion, "www.test.com")
        # The specific domain www.test.com should be a valid audience.
        # It will work with both the implicit patterns and explicit audience.
        assertion = self._make_assertion("test@example.com", "www.test.com")
        self.assertTrue(verifier.verify(assertion))
        self.assertTrue(verifier.verify(assertion, "www.test.com"))
        self.assertTrue(verifier.verify(assertion, "*.test.com"))
        self.assertRaises(AudienceMismatchError,
                          verifier.verify, assertion, "www.moz.com")
        # Domains not matching any patterns should not be valid audiences.
        # They will fail unless given as an explicit argument.
        assertion = self._make_assertion("test@example.com", "www.evil.com")
        self.assertRaises(AudienceMismatchError, verifier.verify, assertion)
        self.assertTrue(verifier.verify(assertion, "www.evil.com"))
        self.assertTrue(verifier.verify(assertion, "*.evil.com"))


class TestDummyVerifierWithLegacyFormat(TestDummyVerifier):

    def _make_assertion(self, *args, **kwds):
        kwds.setdefault("legacy_format", True)
        return make_assertion(*args, **kwds)


class TestWorkerPoolVerifier(TestDummyVerifier):

    def setUp(self):
        super(TestWorkerPoolVerifier, self).setUp()
        self.verifier = WorkerPoolVerifier(
                verifier=LocalVerifier(["*"], warning=False)
        )

    def tearDown(self):
        super(TestWorkerPoolVerifier, self).tearDown()
        self.verifier.close()


class TestShortcutFunction(unittest.TestCase):

    def test_shortcut(self):
        self.assertRaises(TrustError, browserid.verify, EXPIRED_ASSERTION)
