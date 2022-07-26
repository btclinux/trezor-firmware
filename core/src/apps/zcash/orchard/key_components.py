#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from hashlib import blake2b

from ..ff1 import ff1_aes256_encrypt
from ..sapling.key_components import prf_expand

from .generators import NULLIFIER_K_BASE, SPENDING_KEY_BASE, group_hash
from .pallas import Fp, Scalar, Point
from . import poseidon
from .commitments import commit_ivk
from ..utils import i2leosp, i2lebsp, lebs2osp
from .utils import to_base, to_scalar

#
# PRFs and hashes
#

def diversify_hash(d):
    P = group_hash(b'z.cash:Orchard-gd', d)
    if P == Point.identity():
        P = group_hash(b'z.cash:Orchard-gd', b'')
    return P

def prf_nf_orchard(nk, rho):
    return poseidon.hash(nk, rho)

def derive_nullifier(nk, rho: Fp, psi: Fp, cm):
    scalar = prf_nf_orchard(nk, rho) + psi  # addition mod p
    point = NULLIFIER_K_BASE * Scalar(scalar.s) + cm
    return point.extract()

#
# Key components
#

class FullViewingKey:
    """Orchard Full Vieving Key."""
    def __init__(self, ak, nk, rivk):
        self.ak = ak
        self.nk = nk
        self.rivk = rivk

    @staticmethod
    def from_spending_key(sk: bytes):
        self.ask  = to_scalar(prf_expand(self.data, b'\x06'))
        self.nk   = to_base(prf_expand(self.data, b'\x07'))
        self.rivk = to_scalar(prf_expand(self.data, b'\x08'))

        if self.ask == Scalar.ZERO:
            raise ValueError("invalid spending key")

        self.akP = SPENDING_KEY_BASE * self.ask
        if bytes(self.akP)[-1] & 0x80 != 0:
            self.ask = -self.ask

        self.ak = self.akP.extract()
        assert commit_ivk(self.rivk, self.ak, self.nk) is not None

        return FullViewingKey(ask, nk, rivk)

    def raw(self) -> bytes:
        return

    def incoming_viewing_key(self, scope: Scope = Scope.EXTERNAL) -> bytes:
        return commit_ivk(self.rivk, self.ak, self.nk)

    def outgoing_viewing_key(self, scope: Scope = Scope.EXTERNAL) -> bytes:
        """Returns the Outgoing Vieving Key."""
        return orchardlib.derive_outgoing_viewing_key(self.fvk, scope)

    def internal(self):
        K = i2leosp_256(self.rivk.s)
        rivk_internal = to_scalar(prf_expand(K, b'\x83' + i2leosp_256(self.ak.s) + i2leosp_256(self.nk.s)))
        return FullViewingKey(self.ak, self.nk, rivk_internal)

    def address(self, diversifier: int = 0, scope: Scope = Scope.EXTERNAL) -> bytes:
        return orchardlib.derive_address(self.fvk, diversifier, scope)


class FullViewingKey(object):
    def __init__(self, rivk, ak, nk):
        (self.rivk, self.ak, self.nk) = (rivk, ak, nk)
        K = i2leosp(256, self.rivk.s)
        R = prf_expand(K, b'\x82' + i2leosp(256, self.ak.s) + i2leosp(256, self.nk.s))
        self.dk = R[:32]
        self.ovk = R[32:]

    @classmethod
    def from_spending_key(cls, sk):
        return cls(sk.rivk, sk.ak, sk.nk)

    def ivk(self):
        return commit_ivk(self.rivk, self.ak, self.nk)

    def diversifier(self, j):
        return lebs2osp(ff1_aes256_encrypt(self.dk, b'', i2lebsp(88, j)))

    def default_d(self):
        return self.diversifier(0)

    def g_d(self, j):
        return diversify_hash(self.diversifier(j))

    def pk_d(self, j):
        return self.g_d(j) * Scalar(self.ivk().s)

    def default_pkd(self):
        return self.pk_d(0)
