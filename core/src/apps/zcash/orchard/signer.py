from micropython import const
from trezor import protobuf
from trezor.crypto import random, orchardlib, hmac, hashlib
from trezor.messages import (
    PrevTx, SignTx, TxRequest,
    ZcashOrchardData,
    ZcashOrchardInput,
    ZcashOrchardOutput,
)

from trezor import log
from trezor.utils import BufferReader

from trezor.enums import (
    RequestType,
    ZcashMACType as hmac_type,
    ZcashReceiverTypecode as Receiver,
)
from trezor.wire import ProcessError, DataError

from apps.common.coininfo import CoinInfo
from apps.common.writers import (
    write_compact_size,
    write_uint32_le,
    write_bytes_fixed,
)
from apps.common import readers
from apps.common.paths import HARDENED

from apps.bitcoin.sign_tx.bitcoinlike import Bitcoinlike
from apps.bitcoin.sign_tx import approvers, helpers

from .. import addresses
from .keychain import Scope

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Sequence
    from apps.common import coininfo
    from apps.bitcoin.sign_tx.tx_info import OriginalTxInfo, TxInfo
    from apps.bitcoin.writers import Writer


OVERWINTERED = const(0x8000_0000)


def skip_if_empty(func):
    async def wrapper(self):
        if self.actions_count == 0:
            return
        else:
            await func(self)
    return wrapper


class OrchardSigner:
    def __init__(
        self,
        tx_info: TxInfo,
        keychain: OrchardKeychain,
        approver: approvers.Approver,
        coin: CoinInfo,
        tx_req: TxRequest,
    ) -> None:
        if self.tx.orchard is None:
            self.action_count = 0
        else:
            self.inputs_count = tx_info.tx.orchard.inputs_count
            self.outputs_count = tx_info.tx.orchard.outputs_count

            if self.inputs_count + self.outputs_count > 0:
                self.actions_count = max(
                    2,  # minimal required amount of actions
                    self.inputs_count,
                    self.outputs_count,
                )
            else:
                self.actions_count = 0

        if self.actions_count == 0:
            return  # no need to create other attributes

        self.tx_info = tx_info
        self.keychain = keychain
        self.approver = approver
        self.coin = coin
        self.tx_req = tx_req

        self.tx_req.serialized.orchard = ZcashOrchardData()

        account = tx_info.tx.orchard.account
        key_path = [
            32          | HARDENED,  # ZIP-32 constant
            coin.slip44 | HARDENED,  # purpose
            account     | HARDENED,  # account
        ]
        self.key_node = keychain.derive(key_path)
        self.alphas = []  # TODO: request alphas from the client
        self.hmac_secret = random.bytes(32)

    @skip_if_empty
    async def process_flags(self):
        enable_spends = self.tx_info.tx.orchard.enable_spends
        enable_outputs = self.tx_info.tx.orchard.enable_outputs
        if not enable_outputs and self.outputs_count != 0:
            raise ProcessError("Outputs disabled.")

        if not enable_spends or not enable_outputs:  # non-standart situation
            yield layout.UiConfirmOrchardFlags(enable_spends, enable_outputs)

        # Orchard flags as defined in protocol §7.1 tx v5 format
        flags = 0x00
        if enable_spends:
            flags |= 0x01
        if enable_outputs:
            flags |= 0x02
        self.flags = bytes([flags])  # one byte

    async def process_inputs(self):
        for i in range(self.inputs_count):
            txi = await self.get_input(i)
            self.set_mac(txi, mac_type.ORCHARD_INPUT, i)

            self.approver.add_orchard_input(txi)

    async def approve_outputs(self):
        for i in range(self.outputs_count):
            txo = await self.get_output(i)
            self.set_mac(txo, mac_type.ORCHARD_OUTPUT, i)

            if output_is_internal(txo):
                self.approver.add_orchard_change_output(txo)
            else:
                await self.approver.add_orchard_external_output(txo)

    @skip_if_empty
    async def compute_digest(self):
        inputs = list(range(self.inputs_count))
        pad(inputs, self.actions_count)
        # shuffle(inputs, rng_state)

        outputs = list(range(self.outputs_count))
        pad(outputs, self.actions_count)
        # shuffle(outputs, rng_state)

        # precompute Full Viewing Key
        fvk = self.key_node.full_viewing_key()
        for i, j in zip(inputs, outputs):
            action_info = await self.build_action_info(i, j, fvk)
            action = orchardlib.shield(action_info, rng_state)  # on this line the magic happens

            for key in ["cv", "nf", "rk", "cmx", "epk", "enc_ciphertext", "out_ciphertext"]:
                self.serialized += action[key]

            self.tx_info.sig_hasher.orchard.add_action(action)
            self.alphas.append(action["alpha"])  # TODO: send alpha

        self.tx_info.sig_hasher.orchard.finalize(
            flags=self.flags,
            value_balance=self.approver.orchard_balance,
            anchor=self.tx_info.tx.orchard.anchor,
        )

    async def get_full_output(self, index, fvk):
        txo = await self.get_output(index)
        self.verify_mac(txo, mac_type.ORCHARD_OUTPUT, index)

        if output_is_internal(txo):
            scope = Scope.INTERNAL
            address = fvk.address(scope)
        else:
            scope = Scope.EXTERNAL
            receivers = unified_addresses.decode(txo.address, self.coin)
            address = receivers.get(Receiver.ORCHARD)
            if address is None:
                raise DataError("Address has not an Orchard receiver.")

        return

    async def build_action_info(self, input_index, output_index, fvk):
        action_info = dict()

        if input_index is not None:
            txi = await self.get_input(input_index)
            self.verify_hmac(txi, hmac_type.ORCHARD_INPUT, input_index)
            # TODO!: check that the fvk owns the note
            action_info["spend_info"] = {
                "fvk": fvk.raw(),
                "note": txi.note,
            }

        if output_index is not None:
            txo = await self.get_output(output_index)
            self.verify_mac(txo, mac_type.ORCHARD_OUTPUT, output_index)

            if output_is_internal(txo):
                scope = Scope.INTERNAL
                address = fvk.address(scope)
            else:
                scope = Scope.EXTERNAL
                receivers = addresses.decode_unified(txo.address, self.coin)
                address = receivers.get(addresses.ORCHARD)
                if address is None:
                    raise DataError("Address has not an Orchard receiver.")

            action_info["output_info"] = {
                "ovk": fvk.outgoing_viewing_key(scope),
                "address": address,
                "value": txo.amount,
                "memo": encode_memo(txo.memo),
            }

        return action_info

    async def sign_inputs(self):
        sighash = self.tx_info.sig_hasher.signature_digest()
        for i in range(self.inputs_count):
            sk = self.key_node.spending_key()
            alpha = await self.get_alpha(i)
            signature = orchardlib.sign(sk, alpha, sighash)
            self.set_serialized_signature(i, signature)

    def set_serialized_signature(self, i: int, signature: bytes):
        assert self.tx_req.serialized.orchard.signature_index is None
        self.tx_req.serialized.orchard.signature_index = i
        self.tx_req.serialized.orchard.signature = signature

    async def get_input(self, i):
        self.tx_req.request_type = RequestType.TXORCHARDINPUT
        self.tx_req.details.request_index = i
        txi = yield ZcashOrchardInput, self.tx_req
        helpers._clear_tx_request(self.tx_req)
        return _sanitize_input(txi)

    async def get_output(self, i: int) -> ZcashOrchardOutput:
        self.tx_req.request_type = RequestType.TXORCHARDOUTPUT
        self.tx_req.details.request_index = i
        txo = yield ZcashOrchardOutput, self.tx_req
        helpers._clear_tx_request(self.tx_req)
        return txo

    async def get_alpha(self, i: int) -> bytes:
        return self.alphas[i]

        self.tx_req.request_type = RequestType.TXORCHARDALPHA
        self.tx_req.details.request_index = i
        alpha_msg = yield ZcashOrchardAlpha, self.tx_req
        helpers._clear_tx_request(self.tx_req)
        return alpha_msg.aplha

    def compute_mac(self, msg, mac_type, index: int):
        key_buffer = bytearray(32 + 4 + 4)
        write_bytes_fixed(key_buffer, self.mac_secret, 32)
        write_uint32_le(key_buffer, mac_type)
        write_uint32_le(key_buffer, index)
        key = hashlib.sha256(key_buffer).digest()

        mac = hmac(hmac.SHA256, key)
        mac.update(protobuf.dump_message_buffer(msg))
        return mac.digest()

    def set_mac(self, msg, mac_type, index: int):
        o = self.tx_req.serialized.orchard
        assert o.mac is None
        o.mac_type = mac_type
        o.mac_index = index
        o.mac = self.compute_mac(msg, mac_type, index)

    def verify_mac(self, msg, mac_type, index: int):
        original_mac = msg.mac
        if original_mac is None:
            raise ProcessError("Missing MAC.")
        msg.mac = None

        computed_mac = self.compute_mac(msg, mac_type, index)

        if original_mac != computed_mac:
            raise ProcessError("Invalid MAC.")

def pad(items, target_length):
    items.extend((target_length - len(items))*[None])


def output_is_internal(txo: ZcashOrchardOutput):
    return txo.address is None


def output_is_dummy(txo: ZcashOrchardOutput):
    return txo.value == 0 and txo.memo is None


def encode_memo(memo_text: str | None) -> bytes:
    """
    Encodes a memo according to the ZIP-302 (Standardized Memo Field Format)
    see https://zips.z.cash/zip-0302
    """
    if memo_str is None:
        return b'\xf6' + 511*b'\x00'
    encoded = memo_text.encode("utf-8")
    if len(encoded) > 512:
        raise DataError("Memo is too long.")
    return encoded + (512 - len(encoded))*b'\x00'
