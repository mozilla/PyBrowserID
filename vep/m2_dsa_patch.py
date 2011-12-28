#
#  This monkey-patches M2Crypto's DSA support to provide a method
#  for creating a key from given parameters.  It's based on the
#  following patch from the M2Crypt bugtracker:
#
#      https://bugzilla.osafoundation.org/show_bug.cgi?id=12981
#
#  We use ctypes to avoid recompiling the M2Crypto binaries.

import ctypes
from M2Crypto import DSA, m2, __m2crypto

_m2lib = ctypes.CDLL(__m2crypto.__file__)


class _DSA(ctypes.Structure):
    """OpenSSL struct representing a DSA key (struct dsa_st)."""
    _fields_ = [("pad", ctypes.c_int),
                ("version", ctypes.c_long),
                ("write_params", ctypes.c_int),
                ("p", ctypes.c_void_p),
                ("q", ctypes.c_void_p),
                ("g", ctypes.c_void_p),
                ("pub_key", ctypes.c_void_p),
                ("priv_key", ctypes.c_void_p)]
                # There are many more fields, but we don't need them.


def maybe_provide(obj):
    """Decorator to provide default implemenation of a function."""
    def decorator(func):
        if not hasattr(obj, func.__name__):
            setattr(obj, func.__name__, func)
        return func
    return decorator


@maybe_provide(m2)
def dsa_set_pub(dsa, value):
    """Set the public-key component of a DSA object."""
    bn = _m2lib.BN_mpi2bn(value, len(value), None)
    if not bn:
        raise DSA.DSAError("invalid public key data")
    dsa_p = ctypes.cast(ctypes.c_void_p(int(dsa)), ctypes.POINTER(_DSA))
    if dsa_p.contents.pub_key:
        _m2lib.BN_free(dsa_p.contents.pub_key)
    dsa_p.contents.pub_key = bn


@maybe_provide(m2)
def dsa_set_priv(dsa, value):
    """Set the private-key component of a DSA object."""
    bn = _m2lib.BN_mpi2bn(value, len(value), None)
    if not bn:
        raise DSA.DSAError("invalid public key data")
    dsa_p = ctypes.cast(ctypes.c_void_p(int(dsa)), ctypes.POINTER(_DSA))
    if dsa_p.contents.priv_key:
        _m2lib.BN_free(dsa_p.contents.priv_key)
    dsa_p.contents.priv_key = bn


@maybe_provide(DSA)
def load_pub_key_params(p, q, g, pub):
    """Create a DSA_pub object from parameters and key."""
    dsa = m2.dsa_new()
    m2.dsa_set_p(dsa, p)
    m2.dsa_set_q(dsa, q)
    m2.dsa_set_g(dsa, g)
    m2.dsa_set_pub(dsa, pub)
    return DSA.DSA_pub(dsa, 1)


@maybe_provide(DSA)
def load_key_params(p, q, g, pub, priv):
    """Create a DSA object from parameters and key."""
    dsa = m2.dsa_new()
    m2.dsa_set_p(dsa, p)
    m2.dsa_set_q(dsa, q)
    m2.dsa_set_g(dsa, g)
    m2.dsa_set_pub(dsa, pub)
    m2.dsa_set_priv(dsa, priv)
    return DSA.DSA(dsa, 1)
