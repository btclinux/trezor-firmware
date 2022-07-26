from typing import *


# extmod/rustmods/modtrezororchardlib.c
def derive_full_viewing_key(spending_key: bytes) -> bytes:
"""Returns a raw Orchard Full Viewing Key."""


# extmod/rustmods/modtrezororchardlib.c
def derive_incoming_viewing_key(full_viewing_key: bytes, scope: bool) -> bytes:
"""Returns a raw Orchard Incoming Viewing Key."""


# extmod/rustmods/modtrezororchardlib.c
def derive_outgoing_viewing_key(full_viewing_key: bytes, scope: bool) -> bytes:
"""Returns a raw Orchard Outgoing Viewing Key."""


# extmod/rustmods/modtrezororchardlib.c
def derive_address(
    full_viewing_key: bytes,
    diversifier_index: int,
    scope: bool,
) -> bytes:
"""Returns a raw Orchard address."""


# extmod/rustmods/modtrezororchardlib.c
def shield_output(output_info: Dict[str, Any]):
"""Shields an output of an action.
   # Args:
   output_info = {
      "address": bytes,
      "amount": int,
      "memo": bytes | None,
      "ovk": bytes | None,
   }
   # Result:
   shielded_output = {
      "cmx": bytes,
      "epk": bytes,
      "enc_ciphertext": bytes,
      "out_ciphertext": bytes,
   }
"""


# extmod/rustmods/modtrezororchardlib.c
def sign(
    spending_key: bytes,
    alpha: bytes,
    sighash: bytes,
):
"""Reddsa spend signature of over the pallas
# Args:
    `spending_key` - spending key
    `alpha` - randomizer (pallas scalar)
    `sighash` - message digest
"""
