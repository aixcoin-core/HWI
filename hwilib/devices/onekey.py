"""
OneKey
******
"""

from ..common import Chain
from ..errors import (
    DEVICE_NOT_INITIALIZED,
    common_err_msgs,
    handle_errors,
)
from .trezor import TrezorClient
from .trezorlib.transport import (
    hid,
    webusb,
)

from typing import (
    Any,
    Dict,
    List,
    Optional,
    Tuple,
)

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


class OnekeyClient(TrezorClient):
    def __init__(
        self,
        path: str,
        password: Optional[str] = None,
        expert: bool = False,
        chain: Chain = Chain.MAIN,
    ) -> None:
        """
        The `OnekeyClient` is a `HardwareWalletClient` for interacting with
        OneKey devices.
        """
        super(OnekeyClient, self).__init__(
            path,
            password,
            expert,
            chain,
            ONEKEY_HID_IDS,
            ONEKEY_WEBUSB_IDS,
            "127.0.0.1:21324",
            None,
        )
        self.type = "OneKey"

    def _prepare_device(self) -> None:
        # Use the shared unlock/session flow implemented by the base client.
        super(OnekeyClient, self)._prepare_device()


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
