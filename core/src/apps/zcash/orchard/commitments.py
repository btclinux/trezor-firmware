#!/usr/bin/env python3

from .group_hash import group_hash
from .pallas import Fp, Scalar
from .sinsemilla import sinsemilla_hash_to_point
from ..utils import i2lebsp

# Commitment schemes used in Orchard https://zips.z.cash/protocol/nu5.pdf#concretecommit

# https://zips.z.cash/protocol/nu5.pdf#constants
L_ORCHARD_BASE = 255

# https://zips.z.cash/protocol/nu5.pdf#concretehomomorphiccommit
def homomorphic_pedersen_commitment(rcv: Scalar, D, v: Scalar):
    return group_hash(D, b"v") * v + group_hash(D, b"r") * rcv

def value_commit(rcv: Scalar, v: Scalar):
    return homomorphic_pedersen_commitment(rcv, b"z.cash:Orchard-cv", v)

def rcv_trapdoor():
    return Scalar.random()

# https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
def sinsemilla_commit(r: Scalar, D, M):
    assert isinstance(r, Scalar)
    return sinsemilla_hash_to_point(D + b"-M", M) + (
        group_hash(D + b"-r", b"") * r
    )

def sinsemilla_short_commit(r: Scalar, D, M):
    return sinsemilla_commit(r, D, M).extract()

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardnotecommit
def note_commit(rcm, g_d, pk_d, v, rho, psi):
    return sinsemilla_commit(
        rcm,
        b"z.cash:Orchard-NoteCommit",
        g_d + pk_d + i2lebsp(64, v) + i2lebsp(L_ORCHARD_BASE, rho.s) + i2lebsp(L_ORCHARD_BASE, psi.s)
    )

    h = sinsemilla(personal=b"z.cash:Orchard-NoteCommit")
    h.update(bytes(g_d), offset=256)
    h.update(bytes(pk_d), offset=256)
    h.update(i2lebsp(64, v), offset=64)
    h.update(i2lebsp(L_ORCHARD_BASE, rho.s), offset=255)
    h.update(i2lebsp(L_ORCHARD_BASE, psi.s), offset=255)
    return h.finalize()

def rcm_trapdoor():
    return Scalar.random()

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardnotecommit
def commit_ivk(rivk: Scalar, ak: Fp, nk: Fp):
    return sinsemilla_short_commit(
        rivk,
        b"z.cash:Orchard-CommitIvk",
        i2lebsp(L_ORCHARD_BASE, ak.s) + i2lebsp(L_ORCHARD_BASE, nk.s)
    )

def rivk_trapdoor():
    return Scalar.random()
