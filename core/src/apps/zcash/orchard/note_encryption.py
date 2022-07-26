from chacha20poly1305 import ChaCha20Poly1305
from hashlib import blake2b
import os
import struct

from ..transaction import MAX_MONEY
from ..output import render_args, render_tv
from ..rand import Rand

from .pallas import Point, Scalar
from .commitments import rcv_trapdoor, value_commit
from .key_components import diversify_hash, prf_expand, FullViewingKey, SpendingKey
from .note import OrchardNote, OrchardNotePlaintext
from .utils import to_scalar
from ..utils import leos2bsp

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardkdf
def kdf_orchard(shared_secret, ephemeral_key):
    digest = blake2b(digest_size=32, person=b'Zcash_OrchardKDF')
    digest.update(bytes(shared_secret))
    digest.update(ephemeral_key)
    return digest.digest()

# https://zips.z.cash/protocol/nu5.pdf#concreteprfs
def prf_ock_orchard(ovk, cv, cmx, ephemeral_key):
    digest = blake2b(digest_size=32, person=b'Zcash_Orchardock')
    digest.update(ovk)
    digest.update(cv)
    digest.update(cmx)
    digest.update(ephemeral_key)
    return digest.digest()

# https://zips.z.cash/protocol/nu5.pdf#concreteorchardkeyagreement
class OrchardKeyAgreement(object):
    @staticmethod
    def esk(rseed, rho):
        return to_scalar(prf_expand(rseed, b'\x04' + bytes(rho)))

    @staticmethod
    def derive_public(esk, g_d):
        return g_d * esk

    @staticmethod
    def agree(esk, pk_d):
        return pk_d * esk

# https://zips.z.cash/protocol/nu5.pdf#concretesym
class OrchardSym(object):
    @staticmethod
    def k(rand):
        return rand.b(32)

    @staticmethod
    def encrypt(key, plaintext):
        cip = ChaCha20Poly1305(key)
        return bytes(cip.encrypt(b'\x00' * 12, plaintext))

    @staticmethod
    def decrypt(key, ciphertext):
        cip = ChaCha20Poly1305(key)
        return bytes(cip.decrypt(b'\x00' * 12, ciphertext))

# https://zips.z.cash/protocol/nu5.pdf#saplingandorchardencrypt
class OrchardNoteEncryption(object):
    def encrypt(self, note: OrchardNote, memo, pk_d_new, g_d_new, cv_new, cm_new, ovk=None):
        np = note.note_plaintext(memo)
        esk = OrchardKeyAgreement.esk(np.rseed, note.rho)
        p_enc = bytes(np)

        epk = OrchardKeyAgreement.derive_public(esk, g_d_new)
        ephemeral_key = bytes(epk)
        shared_secret = OrchardKeyAgreement.agree(esk, pk_d_new)
        k_enc = kdf_orchard(shared_secret, ephemeral_key)
        c_enc = OrchardSym.encrypt(k_enc, p_enc)

        if ovk is None:
            ock = OrchardSym.k(self._rand)
            op = self._rand.b(64)
        else:
            cv = bytes(cv_new)
            cmx = bytes(cm_new.extract())
            ock = prf_ock_orchard(ovk, cv, cmx, ephemeral_key)
            op = bytes(pk_d_new) + bytes(esk)

        c_out = OrchardSym.encrypt(ock, op)

        return TransmittedNoteCipherText(
            epk, c_enc, c_out
        )

class TransmittedNoteCipherText(object):
    def __init__(self, epk, c_enc, c_out):
        self.epk = epk
        self.c_enc = c_enc
        self.c_out = c_out
