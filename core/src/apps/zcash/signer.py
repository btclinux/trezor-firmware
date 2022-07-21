from micropython import const
from typing import TYPE_CHECKING

from trezor.enums import OutputScriptType, ZcashReceiverTypecode as Receiver
from trezor.messages import SignTx
from trezor.utils import ensure
from trezor.wire import DataError, ProcessError

from apps.bitcoin import scripts
from apps.bitcoin.common import ecdsa_sign
from apps.bitcoin.sign_tx.bitcoinlike import Bitcoinlike
from apps.common.writers import write_compact_size, write_uint32_le

from . import unified_addresses
from .hasher import ZcashHasher

if TYPE_CHECKING:
    from typing import Sequence
    from apps.common.coininfo import CoinInfo
    from apps.bitcoin.sign_tx.tx_info import OriginalTxInfo, TxInfo
    from apps.bitcoin.writers import Writer
    from apps.bitcoin.sign_tx.approvers import Approver
    from trezor.utils import HashWriter
    from trezor.messages import (
        PrevTx,
        TxInput,
        TxOutput,
    )
    from apps.bitcoin.keychain import Keychain

OVERWINTERED = const(0x8000_0000)


class Zcash(Bitcoinlike):
    def __init__(
        self,
        tx: SignTx,
        keychain: Keychain,
        coin: CoinInfo,
        approver: Approver | None,
    ) -> None:
        ensure(coin.overwintered)
        if tx.version != 5:
            raise DataError("Expected transaction version 5.")

        super().__init__(tx, keychain, coin, approver)

        self.orchard = OrchardSigner(
            self.tx_info,
            None, #keychain[1], # TODO
            approver,
            coin,
            self.tx_req,
        )

    def create_sig_hasher(self, tx: SignTx | PrevTx) -> ZcashHasher:
        return ZcashHasher(tx)

    def create_hash_writer(self) -> HashWriter:
        # Replacement transactions are not supported
        # so this should never be called.
        raise NotImplementedError

    async def step1_process_inputs(self):
        await super().step1_process_inputs()
        await self.orchard.process_flags()
        await self.orchard.process_inputs()

    async def step2_approve_outputs(self):
        await super().step2_approve_outputs()
        await self.orchard.approve_outputs()

    async def step3_verify_inputs(self) -> None:
        # Replacement transactions are not supported.

        # We don't check prevouts, because BIP-341 techniques
        # were adapted in ZIP-244 sighash algorithm.
        # see: https://github.com/zcash/zips/issues/574
        self.taproot_only = True  # turn on taproot behavior
        await super().step3_verify_inputs()
        self.taproot_only = False  # turn off taproot behavior

    async def step4_serialize_inputs(self):
        # shield actions first to get a sighash
        await self.orchard.compute_digest()

        await super().step4_serialize_inputs()

    async def step5_serialize_outputs(self):
        # transparent
        await super().step5_serialize_outputs()

        # Sapling
        write_compact_size(self.serialized_tx, 0)  # nSpendsSapling
        write_compact_size(self.serialized_tx, 0)  # nOutputsSapling

        # Orchard serialization is up to the client

    async def step6_sign_segwit_inputs(self):
        # transparent inputs were signed in step 4
        await self.orchard.sign_inputs()

    async def sign_nonsegwit_input(self, i_sign: int) -> None:
        await self.sign_nonsegwit_bip143_input(i_sign)

    def sign_bip143_input(self, i: int, txi: TxInput) -> tuple[bytes, bytes]:
        signature_digest = self.tx_info.sig_hasher.hash_zip244(
            txi, self.input_derive_script(txi)
        )
        node = self.keychain.derive(txi.address_n)
        signature = ecdsa_sign(node, signature_digest)
        return node.public_key(), signature

    async def process_original_input(self, txi: TxInput, script_pubkey: bytes) -> None:
        raise ProcessError("Replacement transactions are not supported.")
        # Zcash transaction fees are very low
        # so there is no need to bump the fee.

    async def get_tx_digest(
        self,
        i: int,
        txi: TxInput,
        tx_info: TxInfo | OriginalTxInfo,
        public_keys: Sequence[bytes | memoryview],
        threshold: int,
        script_pubkey: bytes,
        tx_hash: bytes | None = None,
    ) -> bytes:
        return self.tx_info.sig_hasher.hash_zip244(txi, script_pubkey)

    def write_tx_header(
        self, w: Writer, tx: SignTx | PrevTx, witness_marker: bool
    ) -> None:
        # defined in ZIP-225 (see https://zips.z.cash/zip-0225)
        assert tx.version_group_id is not None
        assert tx.branch_id is not None  # checked in sanitize_*
        assert tx.expiry is not None

        write_uint32_le(w, tx.version | OVERWINTERED)  # nVersion | fOverwintered
        write_uint32_le(w, tx.version_group_id)  # nVersionGroupId
        write_uint32_le(w, tx.branch_id)  # nConsensusBranchId
        write_uint32_le(w, tx.lock_time)  # lock_time
        write_uint32_le(w, tx.expiry)  # expiryHeight

    def write_tx_footer(self, w: Writer, tx: SignTx | PrevTx) -> None:
        pass  # there is no footer for v5 Zcash transactions

    def output_derive_script(self, txo: TxOutput) -> bytes:
        # unified addresses
<<<<<<< HEAD
        if txo.address is not None and txo.address[0] == "u":
            assert txo.script_type is OutputScriptType.PAYTOADDRESS

            receivers = unified_addresses.decode(txo.address, self.coin)
            if Receiver.P2PKH in receivers:
                pubkeyhash = receivers[Receiver.P2PKH]
                return scripts.output_script_p2pkh(pubkeyhash)
            if Receiver.P2SH in receivers:
                scripthash = receivers[Receiver.P2SH]
                return scripts.output_script_p2sh(scripthash)
            raise DataError("Unified address does not include a transparent receiver.")
=======
        if utils.USE_ZCASH:
            if txo.address is not None and txo.address[0] == "u":
                assert txo.script_type is OutputScriptType.PAYTOADDRESS

                receivers = addresses.decode_unified(txo.address, self.coin)
                if Receiver.P2PKH in receivers:
                    pubkeyhash = receivers[Receiver.P2PKH]
                    return scripts.output_script_p2pkh(pubkeyhash)
                if Receiver.P2SH in receivers:
                    scripthash = receivers[Receiver.P2SH]
                    return scripts.output_script_p2sh(scripthash)
                raise DataError(
                    "Unified address does not include a transparent receiver."
                )
>>>>>>> 1a387302b (backup changes)

        # transparent addresses
        return super().output_derive_script(txo)

class ZcashApprover(approvers.BasicApprover):
    def __init__(self, *args, **kwargs):
        self.orchard_out = 0
        super().__init__(*args, **kwargs)

    """
    def add_orchard_input(self, txi: ZcashOrchardInput) -> None:
        self.total_in += txi.amount
        self.orchard_ += txi.amount
    """

    def add_orchard_change_output(self, txo: ZcashOrchardOutput) -> None:
        self.change_count += 1
        self.total_out += txo.amount
        self.change_out += txo.amount
        self.orchard_out += txo.amount

    async def add_orchard_external_output(self, txo: ZcashOrchardOutput) -> None:
        self.total_out += txo.amount
        self.orchard_out += txo.amount
        yield UiConfirmOrchardOutput(txo)
