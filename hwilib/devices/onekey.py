"""
OneKey
******
"""

from ..common import AddressType, Chain
from ..descriptor import MultisigDescriptor
from ..hwwclient import HardwareWalletClient
from ..errors import (
    ActionCanceledError,
    BadArgumentError,
    DeviceAlreadyInitError,
    DeviceAlreadyUnlockedError,
    DeviceConnectionError,
    DEVICE_NOT_INITIALIZED,
    DeviceNotReadyError,
    NoPasswordError,
    UnavailableActionError,
    common_err_msgs,
    handle_errors,
)
from .trezorlib.client import TrezorClient as TransportClient, PASSPHRASE_ON_DEVICE
from .trezorlib.exceptions import Cancelled, TrezorFailure as TransportFailure
from .trezorlib.transport import (
    hid,
    webusb,
)
from .trezorlib import (
    btc,
    device,
)
from .trezorlib import messages
from .._base58 import (
    get_xpub_fingerprint,
    to_address,
)
from .. import _base58 as base58
from ..key import ExtendedKey
from ..key import parse_path
from .._script import (
    is_p2pkh,
    is_p2sh,
    is_p2wsh,
    is_witness,
)
from ..psbt import (
    PSBT,
    PartiallySignedInput,
    PartiallySignedOutput,
    KeyOriginInfo,
)
from ..tx import CTxOut
from .._serialize import ser_uint256
from ..common import hash256
from .. import _bech32 as bech32
from mnemonic import Mnemonic
from usb1 import USBErrorNoDevice
from types import MethodType

from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    List,
    NoReturn,
    Optional,
    Sequence,
    Tuple,
    Union,
)

import base64
import builtins
import getpass
import sys

ONEKEY_HID_IDS = {
    (0x1209, 0x53C0),
    (0x1209, 0x53C1),
    (0x1209, 0x4F4A),
    (0x1209, 0x4F4B),
}
ONEKEY_WEBUSB_IDS = ONEKEY_HID_IDS.copy()
ONEKEY_EXCLUSIVE_USB_IDS = {
    (0x1209, 0x4F4A),
    (0x1209, 0x4F4B),
}

ONEKEY_HOST_PIN_MODELS = {
    "1",
    "classic",
    "classic1s",
    "classicpure",
}

PIN_MATRIX_DESCRIPTION = """
Use the numeric keypad to describe number positions. The layout is:
    7 8 9
    4 5 6
    1 2 3
""".strip()

Device = Union[hid.HidTransport, webusb.WebUsbTransport]

ECDSA_SCRIPT_TYPES = [
    messages.InputScriptType.SPENDADDRESS,
    messages.InputScriptType.SPENDMULTISIG,
    messages.InputScriptType.SPENDWITNESS,
    messages.InputScriptType.SPENDP2SHWITNESS,
]
SCHNORR_SCRIPT_TYPES = [
    messages.InputScriptType.SPENDTAPROOT,
]


def _get_usb_id(device: Any) -> Optional[Tuple[int, int]]:
    if hasattr(device, "device"):
        raw_device = device.device
        if isinstance(raw_device, dict):
            vendor_id = raw_device.get("vendor_id")
            product_id = raw_device.get("product_id")
            if vendor_id is not None and product_id is not None:
                return (vendor_id, product_id)

        if hasattr(raw_device, "getVendorID") and hasattr(raw_device, "getProductID"):
            return (raw_device.getVendorID(), raw_device.getProductID())

    return None


def _is_onekey_device(usb_id: Optional[Tuple[int, int]], label: str, vendor: str) -> bool:
    if usb_id in ONEKEY_HID_IDS:
        return True

    label_lower = label.lower()
    vendor_lower = vendor.lower()
    return "onekey" in label_lower or "onekey" in vendor_lower


def _contains_onekey_marker(value: Any) -> bool:
    if not value:
        return False
    if isinstance(value, bytes):
        value = value.decode(errors="ignore")
    return "onekey" in str(value).lower()


def _is_onekey_transport(device: Any, usb_id: Optional[Tuple[int, int]]) -> bool:
    if usb_id in ONEKEY_EXCLUSIVE_USB_IDS:
        return True

    if hasattr(device, "device"):
        raw_device = device.device

        if isinstance(raw_device, dict):
            return _contains_onekey_marker(raw_device.get("product_string")) or _contains_onekey_marker(
                raw_device.get("manufacturer_string")
            )

        if hasattr(raw_device, "getProduct") and hasattr(raw_device, "getManufacturer"):
            try:
                return _contains_onekey_marker(raw_device.getProduct()) or _contains_onekey_marker(
                    raw_device.getManufacturer()
                )
            except Exception:
                return False

    return False


def _normalize_model(model: Optional[str]) -> str:
    return (model or "").lower().replace("_", "").replace("-", "")


def _uses_host_pin(model: Optional[str]) -> bool:
    return _normalize_model(model) in ONEKEY_HOST_PIN_MODELS


def _locked_instructions(model: Optional[str]) -> str:
    if _uses_host_pin(model):
        return "OneKey is locked. Unlock by using 'promptpin' and then 'sendpin'."
    return "OneKey is locked. Please unlock it on the device and try again."


def parse_multisig(
    script: bytes,
    tx_xpubs: Dict[bytes, KeyOriginInfo],
    psbt_scope: Union[PartiallySignedInput, PartiallySignedOutput],
) -> Tuple[bool, Optional[messages.MultisigRedeemScriptType]]:
    # at least OP_M pub OP_N OP_CHECKMULTISIG
    if len(script) < 37:
        return (False, None)
    m = script[0] - 80
    if m < 1 or m > 15:
        return (False, None)

    pubkeys = []
    offset = 1
    while True:
        pubkey_len = script[offset]
        if pubkey_len != 33:
            break
        offset += 1
        key = script[offset:offset + 33]
        offset += 33

        hd_node = messages.HDNodeType(
            depth=0,
            fingerprint=0,
            child_num=0,
            chain_code=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            public_key=key,
        )
        pubkeys.append(messages.HDNodePathType(node=hd_node, address_n=[]))

    n = script[offset] - 80
    if n != len(pubkeys):
        return (False, None)
    offset += 1
    if script[offset] != 174:
        return (False, None)

    for pub in pubkeys:
        if pub.node.public_key in psbt_scope.hd_keypaths:
            derivation = psbt_scope.hd_keypaths[pub.node.public_key]
            for xpub in tx_xpubs:
                hd = ExtendedKey.deserialize(base58.encode(xpub + hash256(xpub)[:4]))
                origin = tx_xpubs[xpub]
                if (origin.fingerprint == derivation.fingerprint) and (
                    origin.path == derivation.path[: len(origin.path)]
                ):
                    pub.address_n = list(derivation.path[len(origin.path):])
                    pub.node = messages.HDNodeType(
                        depth=hd.depth,
                        fingerprint=int.from_bytes(hd.parent_fingerprint, "big"),
                        child_num=hd.child_num,
                        chain_code=hd.chaincode,
                        public_key=hd.pubkey,
                    )
                    break
    multisig = messages.MultisigRedeemScriptType(
        m=m, signatures=[b""] * n, pubkeys=pubkeys
    )
    return (True, multisig)


def onekey_exception(f: Callable[..., Any]) -> Any:
    @wraps(f)
    def func(*args: Any, **kwargs: Any) -> Any:
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            raise BadArgumentError(str(e))
        except Cancelled:
            raise ActionCanceledError("{} canceled".format(f.__name__))
        except USBErrorNoDevice:
            raise DeviceConnectionError("Device disconnected")

    return func


def interactive_get_pin(self: object, code: Optional[int] = None) -> str:
    if code == messages.PinMatrixRequestType.Current:
        desc = "current PIN"
    elif code == messages.PinMatrixRequestType.NewFirst:
        desc = "new PIN"
    elif code == messages.PinMatrixRequestType.NewSecond:
        desc = "new PIN again"
    else:
        desc = "PIN"

    print(PIN_MATRIX_DESCRIPTION, file=sys.stderr)

    while True:
        pin = getpass.getpass(f"Please enter {desc}:\n")
        if not pin.isdigit():
            print("Non-numerical PIN provided, please try again", file=sys.stderr)
        else:
            return pin


def mnemonic_words(
    expand: bool = False, language: str = "english"
) -> Callable[[Any], str]:
    wordlist: Sequence[str] = []
    if expand:
        wordlist = Mnemonic(language).wordlist

    def expand_word(word: str) -> str:
        if not expand:
            return word
        if word in wordlist:
            return word
        matches = [w for w in wordlist if w.startswith(word)]
        if len(matches) == 1:
            return matches[0]
        print("Choose one of: " + ", ".join(matches), file=sys.stderr)
        raise KeyError(word)

    def get_word(type: messages.WordRequestType) -> str:
        assert type == messages.WordRequestType.Plain
        while True:
            try:
                word = input("Enter one word of mnemonic:\n")
                return expand_word(word)
            except KeyError:
                pass
            except Exception:
                raise Cancelled from None

    return get_word


class PassphraseUI:
    def __init__(self, passphrase: str) -> None:
        self.passphrase = passphrase
        self.prompt_shown = False
        self.always_prompt = False
        self.return_passphrase = True

    def button_request(self, code: Optional[int]) -> None:
        if not self.prompt_shown:
            print("Please confirm action on your OneKey device", file=sys.stderr)
        if not self.always_prompt:
            self.prompt_shown = True

    def get_pin(self, code: Optional[int] = None) -> NoReturn:
        raise NotImplementedError("get_pin is not needed")

    def disallow_passphrase(self) -> None:
        self.return_passphrase = False

    def get_passphrase(self, available_on_device: bool) -> object:
        if available_on_device:
            return PASSPHRASE_ON_DEVICE
        if self.return_passphrase:
            return self.passphrase
        raise ValueError("Passphrase from Host is not allowed for this device")


def get_path_transport(path: str) -> Device:
    devs = hid.HidTransport.enumerate(usb_ids=ONEKEY_HID_IDS)
    devs.extend(webusb.WebUsbTransport.enumerate(usb_ids=ONEKEY_WEBUSB_IDS))
    for dev in devs:
        if path == dev.get_path():
            return dev
    raise BadArgumentError(f"Could not find device by path: {path}")


class OneKeyClient(HardwareWalletClient):
    def __init__(
        self,
        path: str,
        password: Optional[str] = None,
        expert: bool = False,
        chain: Chain = Chain.MAIN,
    ) -> None:
        if password is None:
            password = ""
        super(OneKeyClient, self).__init__(path, password, expert, chain)
        transport = get_path_transport(path)
        self.client = TransportClient(transport=transport, ui=PassphraseUI(password), _init_device=False)
        self.password = password
        self.type = "OneKey"

    def _prepare_device(self) -> None:
        self.coin_name = "Bitcoin" if self.chain == Chain.MAIN else "Testnet"
        resp = self.client.refresh_features()
        if resp.model == "1":
            self.client.init_device()
        else:
            try:
                self.client.ensure_unlocked()
            except TransportFailure:
                self.client.init_device()

    def _check_unlocked(self) -> None:
        self._prepare_device()
        if messages.Capability.PassphraseEntry in self.client.features.capabilities and isinstance(self.client.ui, PassphraseUI):
            self.client.ui.disallow_passphrase()
        if self.client.features.pin_protection and not self.client.features.unlocked:
            raise DeviceNotReadyError(_locked_instructions(self.client.features.model))
        if self.client.features.passphrase_protection and self.password is None:
            raise NoPasswordError("Passphrase protection is enabled, passphrase must be provided")

    def _supports_external(self) -> bool:
        if self.client.features.model == "1" and self.client.version <= (1, 10, 5):
            return True
        if self.client.features.model == "T" and self.client.version <= (2, 4, 3):
            return True
        return False

    @onekey_exception
    def get_pubkey_at_path(self, path: str) -> ExtendedKey:
        self._check_unlocked()
        expanded_path = parse_path(path)
        output = btc.get_public_node(self.client, expanded_path, coin_name=self.coin_name)
        xpub = ExtendedKey.deserialize(output.xpub)
        if self.chain != Chain.MAIN:
            xpub.version = ExtendedKey.TESTNET_PUBLIC
        return xpub

    @onekey_exception
    def sign_tx(self, tx: PSBT) -> PSBT:
        self._check_unlocked()
        master_key = btc.get_public_node(self.client, [0x80000000], coin_name="Bitcoin")
        master_fp = get_xpub_fingerprint(master_key.xpub)

        passes = 1
        p = 0
        while p < passes:
            inputs = []
            to_ignore = []
            for input_num, psbt_in in builtins.enumerate(tx.inputs):
                assert psbt_in.prev_txid is not None
                assert psbt_in.prev_out is not None
                assert psbt_in.sequence is not None
                txinputtype = messages.TxInputType(
                    prev_hash=psbt_in.prev_txid[::-1],
                    prev_index=psbt_in.prev_out,
                    sequence=psbt_in.sequence,
                )

                utxo = psbt_in.witness_utxo
                if psbt_in.non_witness_utxo:
                    if psbt_in.prev_txid != psbt_in.non_witness_utxo.hash:
                        raise BadArgumentError(
                            "Input {} has a non_witness_utxo with the wrong hash".format(input_num)
                        )
                    utxo = psbt_in.non_witness_utxo.vout[psbt_in.prev_out]
                if utxo is None:
                    continue
                scriptcode = utxo.scriptPubKey

                p2sh = False
                if is_p2sh(scriptcode):
                    if len(psbt_in.redeem_script) == 0:
                        continue
                    scriptcode = psbt_in.redeem_script
                    p2sh = True

                is_wit, wit_ver, _ = is_witness(scriptcode)
                if is_wit:
                    if wit_ver == 0:
                        if p2sh:
                            txinputtype.script_type = messages.InputScriptType.SPENDP2SHWITNESS
                        else:
                            txinputtype.script_type = messages.InputScriptType.SPENDWITNESS
                    elif wit_ver == 1:
                        txinputtype.script_type = messages.InputScriptType.SPENDTAPROOT
                else:
                    txinputtype.script_type = messages.InputScriptType.SPENDADDRESS
                txinputtype.amount = utxo.nValue

                p2wsh = False
                if is_p2wsh(scriptcode):
                    if len(psbt_in.witness_script) == 0:
                        continue
                    scriptcode = psbt_in.witness_script
                    p2wsh = True

                def ignore_input() -> None:
                    txinputtype.address_n = [0x80000000 | 84, 0x80000000 | (0 if self.chain == Chain.MAIN else 1), 0x80000000, 0, 0]
                    txinputtype.multisig = None
                    txinputtype.script_type = messages.InputScriptType.SPENDWITNESS
                    inputs.append(txinputtype)
                    to_ignore.append(input_num)

                is_ms, multisig = parse_multisig(scriptcode, tx.xpub, psbt_in)
                if is_ms:
                    txinputtype.multisig = multisig
                    if not is_wit:
                        if utxo.is_p2sh():
                            txinputtype.script_type = messages.InputScriptType.SPENDMULTISIG
                        else:
                            if not self._supports_external():
                                raise BadArgumentError("Cannot sign bare multisig")
                            ignore_input()
                            continue
                elif not is_ms and not is_wit and not is_p2pkh(scriptcode):
                    if not self._supports_external():
                        raise BadArgumentError("Cannot sign unknown scripts")
                    ignore_input()
                    continue
                elif not is_ms and is_wit and p2wsh:
                    if not self._supports_external():
                        raise BadArgumentError("Cannot sign unknown witness versions")
                    ignore_input()
                    continue

                found = False
                found_in_sigs = False
                our_keys = 0
                path_last_ours = None
                if txinputtype.script_type in ECDSA_SCRIPT_TYPES:
                    for key in psbt_in.hd_keypaths.keys():
                        keypath = psbt_in.hd_keypaths[key]
                        if keypath.fingerprint == master_fp:
                            path_last_ours = keypath.path
                            if key in psbt_in.partial_sigs:
                                found_in_sigs = True
                                continue
                            if not found:
                                txinputtype.address_n = keypath.path
                                found = True
                            our_keys += 1
                elif txinputtype.script_type in SCHNORR_SCRIPT_TYPES:
                    found_in_sigs = len(psbt_in.tap_key_sig) > 0
                    for key, (leaf_hashes, origin) in psbt_in.tap_bip32_paths.items():
                        if key == psbt_in.tap_internal_key and origin.fingerprint == master_fp:
                            path_last_ours = origin.path
                            txinputtype.address_n = origin.path
                            found = True
                            our_keys += 1
                            break

                if our_keys > passes:
                    passes = our_keys

                if not found and not found_in_sigs:
                    if not self._supports_external():
                        raise BadArgumentError("Cannot sign external inputs")
                    ignore_input()
                    continue
                elif not found and found_in_sigs:
                    assert path_last_ours is not None
                    txinputtype.address_n = path_last_ours
                    to_ignore.append(input_num)

                inputs.append(txinputtype)

            if self.chain != Chain.MAIN:
                p2pkh_version = b"\x6f"
                p2sh_version = b"\xc4"
                bech32_hrp = "tb"
            else:
                p2pkh_version = b"\x00"
                p2sh_version = b"\x05"
                bech32_hrp = "bc"

            outputs = []
            for psbt_out in tx.outputs:
                out = psbt_out.get_txout()
                txoutput = messages.TxOutputType(amount=out.nValue)
                txoutput.script_type = messages.OutputScriptType.PAYTOADDRESS
                wit, ver, prog = out.is_witness()
                if wit:
                    txoutput.address = bech32.encode(bech32_hrp, ver, prog)
                elif out.is_p2pkh():
                    txoutput.address = to_address(out.scriptPubKey[3:23], p2pkh_version)
                elif out.is_p2sh():
                    txoutput.address = to_address(out.scriptPubKey[2:22], p2sh_version)
                elif out.is_opreturn():
                    txoutput.script_type = messages.OutputScriptType.PAYTOOPRETURN
                    txoutput.op_return_data = out.scriptPubKey[2:]
                else:
                    raise BadArgumentError("Output is not an address")

                if not wit or (wit and ver == 0):
                    for _, keypath in psbt_out.hd_keypaths.items():
                        if keypath.fingerprint != master_fp:
                            continue
                        wit, ver, prog = out.is_witness()
                        if out.is_p2pkh():
                            txoutput.address_n = keypath.path
                            txoutput.address = None
                        elif wit:
                            txoutput.script_type = messages.OutputScriptType.PAYTOWITNESS
                            txoutput.address_n = keypath.path
                            txoutput.address = None
                        elif out.is_p2sh() and psbt_out.redeem_script:
                            wit, ver, prog = CTxOut(0, psbt_out.redeem_script).is_witness()
                            if wit and len(prog) in [20, 32]:
                                txoutput.script_type = messages.OutputScriptType.PAYTOP2SHWITNESS
                                txoutput.address_n = keypath.path
                                txoutput.address = None
                elif wit and ver == 1:
                    for key, (leaf_hashes, origin) in psbt_out.tap_bip32_paths.items():
                        if key == psbt_out.tap_internal_key and origin.fingerprint == master_fp:
                            txoutput.address_n = origin.path
                            txoutput.script_type = messages.OutputScriptType.PAYTOTAPROOT
                            txoutput.address = None
                            break

                if psbt_out.witness_script or psbt_out.redeem_script:
                    is_ms, multisig = parse_multisig(
                        psbt_out.witness_script or psbt_out.redeem_script,
                        tx.xpub,
                        psbt_out,
                    )
                    if is_ms:
                        txoutput.multisig = multisig
                        if not wit:
                            txoutput.script_type = messages.OutputScriptType.PAYTOMULTISIG
                outputs.append(txoutput)

            prevtxs = {}
            for psbt_in in tx.inputs:
                if psbt_in.non_witness_utxo:
                    prev = psbt_in.non_witness_utxo
                    t = messages.TransactionType()
                    t.version = prev.nVersion
                    t.lock_time = prev.nLockTime
                    for vin in prev.vin:
                        i = messages.TxInputType(
                            prev_hash=ser_uint256(vin.prevout.hash)[::-1],
                            prev_index=vin.prevout.n,
                            script_sig=vin.scriptSig,
                            sequence=vin.nSequence,
                        )
                        t.inputs.append(i)
                    for vout in prev.vout:
                        o = messages.TxOutputBinType(amount=vout.nValue, script_pubkey=vout.scriptPubKey)
                        t.bin_outputs.append(o)
                    assert psbt_in.non_witness_utxo.sha256 is not None
                    prevtxs[ser_uint256(psbt_in.non_witness_utxo.sha256)[::-1]] = t

            assert tx.tx_version is not None
            signed_tx = btc.sign_tx(
                client=self.client,
                coin_name=self.coin_name,
                inputs=inputs,
                outputs=outputs,
                prev_txes=prevtxs,
                version=tx.tx_version,
                lock_time=tx.compute_lock_time(),
                serialize=False,
            )

            for input_num, (psbt_in, sig) in builtins.enumerate(list(zip(tx.inputs, signed_tx[0]))):
                if input_num in to_ignore:
                    continue
                for pubkey in psbt_in.hd_keypaths.keys():
                    fp = psbt_in.hd_keypaths[pubkey].fingerprint
                    if fp == master_fp and pubkey not in psbt_in.partial_sigs:
                        psbt_in.partial_sigs[pubkey] = sig + b"\x01"
                        break
                if len(psbt_in.tap_internal_key) > 0 and len(psbt_in.tap_key_sig) == 0:
                    psbt_in.tap_key_sig = sig

            p += 1

        return tx

    @onekey_exception
    def sign_message(self, message: Union[str, bytes], keypath: str) -> str:
        self._check_unlocked()
        path = parse_path(keypath)
        result = btc.sign_message(self.client, self.coin_name, path, message)
        return base64.b64encode(result.signature).decode("utf-8")

    @onekey_exception
    def display_singlesig_address(
        self,
        keypath: str,
        addr_type: AddressType,
    ) -> str:
        self._check_unlocked()
        if addr_type == AddressType.SH_WIT:
            script_type = messages.InputScriptType.SPENDP2SHWITNESS
        elif addr_type == AddressType.WIT:
            script_type = messages.InputScriptType.SPENDWITNESS
        elif addr_type == AddressType.LEGACY:
            script_type = messages.InputScriptType.SPENDADDRESS
        elif addr_type == AddressType.TAP:
            if not self.can_sign_taproot():
                raise UnavailableActionError("This device does not support displaying Taproot addresses")
            script_type = messages.InputScriptType.SPENDTAPROOT
        else:
            raise BadArgumentError("Unknown address type")

        expanded_path = parse_path(keypath)
        try:
            address = btc.get_address(
                self.client,
                self.coin_name,
                expanded_path,
                show_display=True,
                script_type=script_type,
                multisig=None,
            )
            assert isinstance(address, str)
            return address
        except Exception:
            raise BadArgumentError("No path supplied matched device keys")

    @onekey_exception
    def display_multisig_address(
        self,
        addr_type: AddressType,
        multisig: MultisigDescriptor,
    ) -> str:
        self._check_unlocked()
        der_pks = list(zip([p.get_pubkey_bytes(0) for p in multisig.pubkeys], multisig.pubkeys))
        if multisig.is_sorted:
            der_pks = sorted(der_pks)

        pubkey_objs = []
        for pk, p in der_pks:
            if p.extkey is not None:
                xpub = p.extkey
                hd_node = messages.HDNodeType(
                    depth=xpub.depth,
                    fingerprint=int.from_bytes(xpub.parent_fingerprint, "big"),
                    child_num=xpub.child_num,
                    chain_code=xpub.chaincode,
                    public_key=xpub.pubkey,
                )
                pubkey_objs.append(
                    messages.HDNodePathType(node=hd_node, address_n=parse_path("m" + p.deriv_path if p.deriv_path is not None else ""))
                )
            else:
                hd_node = messages.HDNodeType(
                    depth=0,
                    fingerprint=0,
                    child_num=0,
                    chain_code=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                    public_key=pk,
                )
                pubkey_objs.append(messages.HDNodePathType(node=hd_node, address_n=[]))

        onekey_ms = messages.MultisigRedeemScriptType(
            m=multisig.thresh,
            signatures=[b""] * len(pubkey_objs),
            pubkeys=pubkey_objs,
        )

        if addr_type == AddressType.SH_WIT:
            script_type = messages.InputScriptType.SPENDP2SHWITNESS
        elif addr_type == AddressType.WIT:
            script_type = messages.InputScriptType.SPENDWITNESS
        elif addr_type == AddressType.LEGACY:
            script_type = messages.InputScriptType.SPENDMULTISIG
        else:
            raise BadArgumentError("Unknown address type")

        for p in multisig.pubkeys:
            keypath = p.origin.get_derivation_path() if p.origin is not None else "m/"
            keypath += p.deriv_path if p.deriv_path is not None else ""
            path = parse_path(keypath)
            try:
                address = btc.get_address(
                    self.client,
                    self.coin_name,
                    path,
                    show_display=True,
                    script_type=script_type,
                    multisig=onekey_ms,
                )
                assert isinstance(address, str)
                return address
            except Exception:
                pass
        raise BadArgumentError("No path supplied matched device keys")

    @onekey_exception
    def setup_device(self, label: str = "", passphrase: str = "") -> bool:
        self._prepare_device()
        self.client.ui.get_pin = MethodType(interactive_get_pin, self.client.ui)
        if self.client.features.initialized:
            raise DeviceAlreadyInitError("Device is already initialized. Use wipe first and try again")
        device.reset(self.client, label=label or None, passphrase_protection=bool(self.password))
        return True

    @onekey_exception
    def wipe_device(self) -> bool:
        self._check_unlocked()
        device.wipe(self.client)
        return True

    @onekey_exception
    def restore_device(self, label: str = "", word_count: int = 24) -> bool:
        self._prepare_device()
        self.client.ui.get_pin = MethodType(interactive_get_pin, self.client.ui)
        device.recover(
            self.client,
            word_count=word_count,
            label=label or None,
            input_callback=mnemonic_words(),
            passphrase_protection=bool(self.password),
        )
        return True

    def backup_device(self, label: str = "", passphrase: str = "") -> bool:
        raise UnavailableActionError("The {} does not support creating a backup via software".format(self.type))

    @onekey_exception
    def close(self) -> None:
        self.client.close()

    @onekey_exception
    def prompt_pin(self) -> bool:
        self.coin_name = "Bitcoin" if self.chain == Chain.MAIN else "Testnet"
        self.client.open()
        self._prepare_device()
        if not self.client.features.pin_protection:
            raise DeviceAlreadyUnlockedError("This device does not need a PIN")
        if self.client.features.unlocked:
            raise DeviceAlreadyUnlockedError("The PIN has already been sent to this device")
        print("Use 'sendpin' to provide the number positions for the PIN as displayed on your device's screen", file=sys.stderr)
        print(PIN_MATRIX_DESCRIPTION, file=sys.stderr)
        self.client.call_raw(
            messages.GetPublicKey(
                address_n=[0x8000002C, 0x80000001, 0x80000000],
                ecdsa_curve_name=None,
                show_display=False,
                coin_name=self.coin_name,
                script_type=messages.InputScriptType.SPENDADDRESS,
            )
        )
        return True

    @onekey_exception
    def send_pin(self, pin: str) -> bool:
        self.client.open()
        if not pin.isdigit():
            raise BadArgumentError("Non-numeric PIN provided")
        resp = self.client.call_raw(messages.PinMatrixAck(pin=pin))
        if isinstance(resp, messages.Failure):
            self.client.features = self.client.call_raw(messages.GetFeatures())
            if isinstance(self.client.features, messages.Features):
                if not self.client.features.pin_protection:
                    raise DeviceAlreadyUnlockedError("This device does not need a PIN")
                if self.client.features.unlocked:
                    raise DeviceAlreadyUnlockedError("The PIN has already been sent to this device")
            return False
        elif isinstance(resp, messages.PassphraseRequest):
            pass_resp = self.client.call(
                messages.PassphraseAck(
                    passphrase=self.client.ui.get_passphrase(available_on_device=False),
                    on_device=False,
                ),
                check_fw=False,
            )
            if isinstance(pass_resp, messages.Deprecated_PassphraseStateRequest):
                self.client.call_raw(messages.Deprecated_PassphraseStateAck())
        return True

    @onekey_exception
    def toggle_passphrase(self) -> bool:
        self._check_unlocked()
        device.apply_settings(
            self.client,
            use_passphrase=not self.client.features.passphrase_protection,
        )
        return True

    @onekey_exception
    def can_sign_taproot(self) -> bool:
        self._prepare_device()
        if self.client.features.model == "T":
            return bool(self.client.version >= (2, 4, 3))
        if self.client.features.model == "1":
            return bool(self.client.version >= (1, 10, 4))
        return True


# Keep backward compatibility with existing dynamic loader naming.
OnekeyClient = OneKeyClient


def enumerate(
    password: Optional[str] = None,
    expert: bool = False,
    chain: Chain = Chain.MAIN,
    allow_emulators: bool = False,
) -> List[Dict[str, Any]]:
    del allow_emulators
    results = []
    devs = hid.HidTransport.enumerate(usb_ids=ONEKEY_HID_IDS)
    devs.extend(webusb.WebUsbTransport.enumerate(usb_ids=ONEKEY_WEBUSB_IDS))
    for dev in devs:
        d_data: Dict[str, Any] = {}

        d_data["type"] = "onekey"
        d_data["model"] = "onekey"
        d_data["path"] = dev.get_path()

        client = None
        usb_id = _get_usb_id(dev)

        if not _is_onekey_transport(dev, usb_id):
            continue

        with handle_errors(common_err_msgs["enumerate"], d_data):
            client = OnekeyClient(d_data["path"], password, expert, chain)
            try:
                client.client.refresh_features()
            except TypeError:
                continue

            label = client.client.features.label or ""
            vendor = client.client.features.vendor or ""
            if not _is_onekey_device(usb_id, label, vendor):
                continue

            d_data["label"] = label
            model = (client.client.features.model or "unknown").lower()
            d_data["model"] = f"onekey_{model}"

            d_data["needs_pin_sent"] = (
                client.client.features.pin_protection and not client.client.features.unlocked
            )
            if client.client.features.model == "1":
                d_data["needs_passphrase_sent"] = bool(
                    client.client.features.passphrase_protection
                )
            else:
                d_data["needs_passphrase_sent"] = False

            if d_data["needs_pin_sent"]:
                d_data["warnings"] = [[_locked_instructions(client.client.features.model)]]

            if d_data["needs_passphrase_sent"] and password is None:
                d_data.setdefault("warnings", []).append([
                    "Passphrase protection enabled but passphrase was not provided. "
                    "Using default passphrase of the empty string (\"\")"
                ])

            if client.client.features.initialized and not d_data["needs_pin_sent"]:
                d_data["fingerprint"] = client.get_master_fingerprint().hex()
                d_data["needs_passphrase_sent"] = False
            elif client.client.features.initialized and d_data["needs_pin_sent"]:
                d_data["fingerprint"] = None
            else:
                d_data["error"] = "Not initialized"
                d_data["code"] = DEVICE_NOT_INITIALIZED

        if client:
            client.close()

        results.append(d_data)
    return results
