# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file,
# You can obtain one at http://mozilla.org/MPL/2.0/.

import os
import tempfile
from binascii import hexlify

from browserid.tests.support import get_keypair, unittest
from browserid.utils import encode_json_bytes, encode_bytes, to_int, to_hex
from browserid import jwt

import browserid.crypto.fallback


# Define Key classes using the fallback crypto implementation.
# This will allow us to compare it against the default implementation,
# which may or may not be using M2Crypto.


class FALLBACK_RS64Key(browserid.crypto.fallback.RSKey):
    DIGESTSIZE = jwt.RS64Key.DIGESTSIZE
    HASHNAME = jwt.RS64Key.HASHNAME
    HASHMOD = jwt.RS64Key.HASHMOD


class FALLBACK_RS128Key(browserid.crypto.fallback.RSKey):
    DIGESTSIZE = jwt.RS128Key.DIGESTSIZE
    HASHNAME = jwt.RS128Key.HASHNAME
    HASHMOD = jwt.RS128Key.HASHMOD


class FALLBACK_RS256Key(browserid.crypto.fallback.RSKey):
    DIGESTSIZE = jwt.RS256Key.DIGESTSIZE
    HASHNAME = jwt.RS256Key.HASHNAME
    HASHMOD = jwt.RS256Key.HASHMOD


class FALLBACK_DS128Key(browserid.crypto.fallback.DSKey):
    BITLENGTH = jwt.DS128Key.BITLENGTH
    HASHMOD = jwt.DS128Key.HASHMOD


class FALLBACK_DS256Key(browserid.crypto.fallback.DSKey):
    BITLENGTH = jwt.DS256Key.BITLENGTH
    HASHMOD = jwt.DS256Key.HASHMOD


def _long(value):
    return long(value.replace(" ", "").replace("\n", "").strip())


def _hex(value):
    return hex(long(value.replace(" ", "").replace("\n", "").strip()))


# These are dummy key data that I generated via PyCrypto.
# M2Crypto doesn't seem to let me get at the individual parameters.
RS64_KEY_DATA = {
    "e": to_int("65537"),
    "n": to_int("""110897663942528265066856163966583557538666146275146
                569193074111045116764854772535689458732714049671807506
                396649306730328647317126800964431366624486416551078177
                528195103050868728550429561392842977259407335332582178
                624191611001106449477645116630750398871838788574825885
                770446686329706009000279629721965986677219"""),
    "d": to_int("""295278123166626215026113502482091502365034141401240
                159363282304307076544046230487782634982660202141239450
                481640966544735782181647417005558287318200095948234745
                214183393770321992676297531378428617531522265932631860
                693144704788708252936752025413728425562033678747736289
                64114133156747686886305629893015763517873"""),
}


RS128_KEY_DATA = {
    "e": to_int("65537"),
    "n": to_int("""160958612207243135258426337209518369415128632560962
                066401791898021454678997211087450105210547947807728611
                652933946951258167329358956700709816714036317375810470
                295243072899121642980878525431294161152733768117820786
                569297473986960477741293612092019304199208985214484495
                635828138197266407114616388786927399789052693146641529
                069121146860114587201869375057710054641012243913159747
                38123335501"""),
    "d": to_int("""585460335046807430656021335489952071366989081433116
                215097718123355575726373730549557594642574725703134816
                147006946827607640385928377837179091326914221524416740
                299068369282887792449789018299767810584728538698323452
                423624337154928370640186927280605226566015077893622723
                077261828396318498566620063942446210308001421635655021
                636812623887580632347545906321114237530430178148314396
                4796548361"""),
}


RS256_KEY_DATA = {
    "e": to_int("65537"),
    "n": to_int("""215157110954304992279368637802866269325596452629865
                395762774177857897276978877993223049183402424105773515
                201290613360308518627825054462116613364134614187172697
                697613069260343087878396452532793731462713531516304214
                014298822788246837398523211444942078088277812631990233
                605547678426218564011563878969467011295043595120351985
                983964933931846863837473460561785876645510646206349911
                224431000742182234603386145326243738136228530828331813
                878460203518442750258401437788566030271868538755030318
                166019192692586115555977516152130159519321313883015410
                981516435771312385629298791747259305672948565747771968
                86049733189121606135786757"""),
    "d": to_int("""207323904265915659359360496298103480082712690236486
                711442619468481988356783086258907621328120702575700798
                914761181078121416297141767464747032219333582869739887
                884736300667713296956049473944465827480687584552025991
                717914841355273754193114413628325025151484385088161118
                794329026966356844773094137980084703759603150591097278
                715178348827663152700571998676478162596562814192444939
                969198839004936798148664921543401849279637016264260100
                884799833350543315289267376119637531072279656873496164
                487439865534937842040868268534375254876875600122000071
                183491091196621992223116828762911412383078024328333659
                43400749509104482286419733"""),
}


DS128_KEY_DATA = {
    "p": to_hex("""6703904104057623261995085583676902361410672713749348
                7374515589871295072792250899011720632358392764362903244
                12395020783955234715731001076129344181463063193"""),
    "q": to_hex(1006478751418673383937866166434285354892250535133),
    "g": to_hex("""1801778249650423365253284139284406405780267098493217
                0320675876307450879812560049234773036938891018778074993
                01874343843218156663689824126183823813389886834"""),
    "y": to_hex("""4148629652526876030475847300836791685289385792662680
                5886292874741635965095055693693232436255359496594291250
                77637642734034732001089176915352691113947372211"""),
    "x": to_hex(487025797851506801093339352420308364866214860934),
}


DS256_KEY_DATA = {
    "p": to_hex("""2711208960741861745308573380095332404137549620315947
                9068314201104887216043109325809831713787118502848090805
                2228463296027517984389413560770548221144847537321410713
                8074399549655880082236367751525195289718555153570695993
                4224380627339855748223727813459783234859779494077922076
                2423249635721005869825686430544699608347754107215634565
                0851362198027654604098263036218122865439334485492711237
                7472573702145934807172291651114407077928143616198427467
                9024712979108597654982429182785275767581931174915877955
                8625488595268019518285615640075507205119180419487449520
                3351885796573964679038415257729743198142313033635959957
                575145555997697"""),
    "q": to_hex("""8046122811817605537462867507324490518169978963150408
                3583246408785452219083579"""),
    "g": to_hex("""1950500789762808721425847074198373330399312960690977
                1160933535007624517213905478669883399507508368338521633
                2881166557568518715829575709756655222088491096927714784
                1618984964751662360118527709652540461308920226876102831
                4488416628441521995648895965894383947550057509046815947
                1392302149913084594178988120406480953626294632398157968
                3741984194617175079084268273336793379485904195158809579
                2472952772187723597083481033010341517250868974535354067
                7871232161896789034355344095549389910486756770965490338
                1490047409769920957342222527693513462166949773339111782
                1219447658975257788692574807159800602790330174406663975
                472198869382895"""),
    "y": to_hex("""1844313351983285974903941411114978471875302034844347
                9309910762819517313278063007429408594387603575253884186
                3648060730951378199242013047419798060108439889755833993
                2031750895274219452721440959637292960848021659217255483
                2771816560590974483374297646898756307143275225321436946
                0145854288664549000343578411784121575679673340213606357
                4578366810179305454606979290196637109545956237197346610
                8119533805477978726092695832992236415542406488466869981
                2358953213068658732690528334500774162040495518320834071
                1235576074237884646058315005867297416669372302683866157
                4789578087953880832840470967725514057139092312253628735
                554039792987016"""),
    "x": to_hex(516894755741455110020515548698805157573799751826),
}


class TestJWT(unittest.TestCase):

    def test_error_jwt_with_no_algorithm(self):
        token = ".".join((
          encode_json_bytes({}),
          encode_json_bytes({}),
          encode_bytes("signature"),
        ))
        self.assertRaises(ValueError, jwt.parse, token)

    def test_error_jwt_with_mismatched_algorithm(self):
        pub, priv = get_keypair("TEST")
        token = jwt.generate({}, priv)
        token = jwt.parse(token)
        pub["algorithm"] = "RS"
        self.assertFalse(token.check_signature(pub))

    def test_loading_unknown_algorithms(self):
        self.assertRaises(ValueError, jwt.load_key, "os.unlink", {})
        self.assertRaises(ValueError, jwt.load_key, "EG", {})
        self.assertRaises(ValueError, jwt.load_key, "DS64", {})


class KeyPairTests(object):
    """Mixin providing a generic suite of tests for a KeyPair."""

    def _make_keypair(self):
        raise NotImplementedError

    def test_verification(self):
        key, pubkey = self._make_keypair()
        # This key should be able to sign and verify things to itself.
        self.assertTrue(pubkey.verify(b"hello", key.sign(b"hello")))
        self.assertFalse(pubkey.verify(b"HELLO", key.sign(b"hello")))
        self.assertRaises(Exception, pubkey.sign, b"hello")
        # It should be able to handle signing arbitrary strings.
        # In the past we've had issues with things like e.g. leading zero
        # bytes, odd-versus-even length strings, etc.
        self.assertTrue(pubkey.verify(b"", key.sign(b"")))
        self.assertTrue(pubkey.verify(b"\x00", key.sign(b"\x00")))
        self.assertTrue(pubkey.verify(b"\x00EST", key.sign(b"\x00EST")))
        for _ in range(20):
            size = int(hexlify(os.urandom(2)), 16)
            data = os.urandom(size)
            self.assertTrue(pubkey.verify(data, key.sign(data)))
        # And it should gracefully handle a variety of stupid input:
        #   - signature too long
        self.assertFalse(pubkey.verify(b"TEST", b"X" * 100))
        #   - "r" value too large
        self.assertFalse(pubkey.verify(b"TEST", (b"\xFF" * 20) + b"\x01" * 20))
        #   - "s" value too large
        self.assertFalse(pubkey.verify(b"TEST", b"\x01" + (b"\xFF" * 20)))

    def test_loading_from_pem_data(self):
        key, pubkey = self._make_keypair()
        try:
            data = key.to_pem_data()
            pubkey = pubkey.__class__.from_pem_data(data)
        except NotImplementedError:
            pass
        else:
            self.assertTrue(pubkey.verify(b"hello", key.sign(b"hello")))

    def test_loading_from_pem_data_filename(self):
        key, pubkey = self._make_keypair()
        try:
            data = key.to_pem_data()
            with tempfile.NamedTemporaryFile() as f:
                f.write(data)
                f.flush()
                pubkey = pubkey.__class__.from_pem_data(filename=f.name)
        except NotImplementedError:
            pass
        else:
            self.assertTrue(pubkey.verify(b"hello", key.sign(b"hello")))


# These classes test the behaviour of the default KeyPair implementations.
# Most likely this will be based on M2Crypto.

class TestRS64KeyPair(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS64_KEY_DATA.copy()
        key = jwt.RS64Key(data)
        data.pop("d")
        pubkey = jwt.RS64Key(data)
        return key, pubkey


class TestRS128KeyPair(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS128_KEY_DATA.copy()
        key = jwt.RS128Key(data)
        data.pop("d")
        pubkey = jwt.RS128Key(data)
        return key, pubkey


class TestRS256KeyPair(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS128_KEY_DATA.copy()
        key = jwt.RS128Key(data)
        data.pop("d")
        pubkey = jwt.RS128Key(data)
        return key, pubkey


class TestDS128KeyPair(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = DS128_KEY_DATA.copy()
        key = jwt.DS128Key(data)
        data.pop("x")
        pubkey = jwt.DS128Key(data)
        return key, pubkey


class TestDS256KeyPair(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = DS256_KEY_DATA.copy()
        key = jwt.DS256Key(data)
        data.pop("x")
        pubkey = jwt.DS256Key(data)
        return key, pubkey


# These classes test that the fallback KeyPair implementations are
# interoperable with the default implementations.  They're a little
# pointless then M2Crypto is not installed, but offer a good sanity
# checl when it is.

class TestFallbackRS64PrivateKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS64_KEY_DATA.copy()
        key = FALLBACK_RS64Key(data)
        data.pop("d")
        pubkey = jwt.RS64Key(data)
        return key, pubkey


class TestFallbackRS64PublicKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS64_KEY_DATA.copy()
        key = jwt.RS64Key(data)
        data.pop("d")
        pubkey = FALLBACK_RS64Key(data)
        return key, pubkey


class TestFallbackRS128PrivateKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS128_KEY_DATA.copy()
        key = FALLBACK_RS128Key(data)
        data.pop("d")
        pubkey = jwt.RS128Key(data)
        return key, pubkey


class TestFallbackRS128PublicKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS128_KEY_DATA.copy()
        key = jwt.RS128Key(data)
        data.pop("d")
        pubkey = FALLBACK_RS128Key(data)
        return key, pubkey


class TestFallbackRS256PrivateKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS256_KEY_DATA.copy()
        key = FALLBACK_RS256Key(data)
        data.pop("d")
        pubkey = jwt.RS256Key(data)
        return key, pubkey


class TestFallbackRS256PublicKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = RS256_KEY_DATA.copy()
        key = jwt.RS256Key(data)
        data.pop("d")
        pubkey = FALLBACK_RS256Key(data)
        return key, pubkey


class TestFallbackDS128PrivateKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = DS128_KEY_DATA.copy()
        key = FALLBACK_DS128Key(data)
        data.pop("x")
        pubkey = jwt.DS128Key(data)
        return key, pubkey


class TestFallbackDS128PublicKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = DS128_KEY_DATA.copy()
        key = jwt.DS128Key(data)
        data.pop("x")
        pubkey = FALLBACK_DS128Key(data)
        return key, pubkey


class TestFallbackDS256PrivateKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = DS256_KEY_DATA.copy()
        key = FALLBACK_DS256Key(data)
        data.pop("x")
        pubkey = jwt.DS256Key(data)
        return key, pubkey


class TestFallbackDS256PublicKey(KeyPairTests, unittest.TestCase):

    def _make_keypair(self):
        data = DS256_KEY_DATA.copy()
        key = jwt.DS256Key(data)
        data.pop("x")
        pubkey = FALLBACK_DS256Key(data)
        return key, pubkey
