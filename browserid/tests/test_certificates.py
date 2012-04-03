import json
import unittest

from mock import Mock, patch
from requests.exceptions import RequestException

from browserid.certificates import fetch_public_key
from browserid.errors import ConnectionError, InvalidIssuerError


# Retrieved from browserid.org on April 3rd 2012
BROWSERID_PK = (
    '{"public-key":{"algorithm":"RS","n":"175097498616944944948724600'
    '5376783505040424585022287992333285107040747762043794156382037076'
    '4990477086508806099113661589535215545809212436371869690217935480'
    '2753014948839838403516326408223252892569346143048785710656475684'
    '9535475273645907806528415369926171343773128172627893352378261396'
    '0153494025694829910802495907763077221584500090734186210456302804'
    '6884323084778492418923884368673543934239778647619964884232166051'
    '7909653959911229288600229842193433562918970249484466937121698566'
    '1583323059605724956419024024496484812121544425787678170853739436'
    '5238417167558546493512404073066199364247440288962324288605736789'
    '20055912798079","e":"65537"}}')
BROWSERID_PK_PY = json.loads(BROWSERID_PK)


class TestFetchPublicKey(unittest.TestCase):
    @patch('browserid.certificates.requests')
    def _fetch(self, hostname, requests, well_known_url=None,
               side_effect=None, response_text='', status_code=200):
        response = Mock()
        response.text = response_text
        response.status_code = status_code
        requests.get.side_effect = side_effect
        requests.get.return_value = response

        kwargs = {}
        if well_known_url is not None:
            kwargs['well_known_url'] = well_known_url

        return fetch_public_key(hostname, **kwargs)

    def test_connection_error(self):
        """If there is an error connecting, raise a ConnectionError."""
        with self.assertRaises(ConnectionError):
            self._fetch('test.com', side_effect=RequestException)

    @patch('browserid.certificates.fetch_public_key')
    def test_missing_well_known_document(self, fetch):
        with self.assertRaises(InvalidIssuerError):
            self._fetch('test.com', status_code=404)

    def test_malformed_well_known_document(self):
        response_text = 'I AINT NO JSON, FOOL!'
        with self.assertRaises(InvalidIssuerError):
            self._fetch('test.com', response_text=response_text)

    def test_malformed_pub_key_document(self):
        # We need the first request to raise a 404, so we replace
        # post with a custom function here.
        def post(url, data):
            response = Mock()
            if not post.called:
                response.status_code = 404
                post.called = True
            response.text = 'I AINT NO JSON, FOOL!'
            return response
        post.called = False

        with patch('browserid.certificates.requests') as requests:
            requests.post = post
            with self.assertRaises(InvalidIssuerError):
                fetch_public_key('test.com')

    def test_well_known_doc_with_no_public_key(self):
        with self.assertRaises(InvalidIssuerError):
            self._fetch('test.com', response_text='{}')

    def test_successful_fetch(self):
        key = self._fetch('test.com', response_text=BROWSERID_PK)
        self.assertEquals(key, BROWSERID_PK_PY['public-key'])
