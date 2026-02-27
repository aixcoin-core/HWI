#! /usr/bin/env python3

import unittest
from unittest import mock

from hwilib.devices import onekey
from hwilib.devices import trezor


class _DictTransport:
    def __init__(self, raw_device):
        self.device = raw_device


class _RawUsbDevice:
    def __init__(self, vendor_id=0x1209, product_id=0x53C0, product="", manufacturer=""):
        self._vendor_id = vendor_id
        self._product_id = product_id
        self._product = product
        self._manufacturer = manufacturer

    def getVendorID(self):
        return self._vendor_id

    def getProductID(self):
        return self._product_id

    def getProduct(self):
        return self._product

    def getManufacturer(self):
        return self._manufacturer


class _FailingRawUsbDevice(_RawUsbDevice):
    def getProduct(self):
        raise RuntimeError("device query failed")


class _WebUsbTransport:
    def __init__(self, raw_device):
        self.device = raw_device


class _EnumerateTransport(_DictTransport):
    def __init__(self, raw_device, path="hid:onekey"):
        super().__init__(raw_device)
        self._path = path

    def get_path(self):
        return self._path


class _FakeFeatures:
    def __init__(
        self,
        model="1",
        pin_protection=True,
        unlocked=False,
        passphrase_protection=False,
        initialized=True,
        label="OneKey",
        vendor="OneKey",
    ):
        self.model = model
        self.pin_protection = pin_protection
        self.unlocked = unlocked
        self.passphrase_protection = passphrase_protection
        self.initialized = initialized
        self.label = label
        self.vendor = vendor


class _FakeInnerClient:
    def __init__(self, features):
        self.features = features

    def refresh_features(self):
        return None


class _FakeOnekeyClient:
    def __init__(self, features):
        self.client = _FakeInnerClient(features)

    def get_master_fingerprint(self):
        return bytes.fromhex("f23f9fd2")

    def close(self):
        return None


class TestOnekeyHelpers(unittest.TestCase):
    def test_contains_onekey_marker(self):
        self.assertTrue(onekey._contains_onekey_marker("OneKey Pro"))
        self.assertTrue(onekey._contains_onekey_marker(b"ONEKEY Mini"))
        self.assertFalse(onekey._contains_onekey_marker("Trezor"))
        self.assertFalse(onekey._contains_onekey_marker(None))

    def test_get_usb_id(self):
        dict_device = _DictTransport({"vendor_id": 0x1209, "product_id": 0x53C0})
        self.assertEqual(onekey._get_usb_id(dict_device), (0x1209, 0x53C0))

        raw_device = _RawUsbDevice(vendor_id=0x1209, product_id=0x4F4A)
        self.assertEqual(onekey._get_usb_id(_DictTransport(raw_device)), (0x1209, 0x4F4A))

        self.assertIsNone(onekey._get_usb_id(object()))

    def test_is_onekey_device(self):
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x4F4A), "", ""))
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C1), "Wallet", "Vendor"))
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C0), "OneKey Touch", "Unknown"))
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C0), "Wallet", "OneKey"))
        self.assertFalse(onekey._is_onekey_device((0x0001, 0x0002), "Wallet", "Vendor"))

    def test_is_onekey_transport_with_dict_device(self):
        one_key_dict = _DictTransport({"product_string": "OneKey Pro", "manufacturer_string": "Unknown"})
        self.assertTrue(onekey._is_onekey_transport(one_key_dict, (0x1209, 0x53C0)))

        one_key_manufacturer = _DictTransport({"product_string": "Wallet", "manufacturer_string": "OneKey"})
        self.assertTrue(onekey._is_onekey_transport(one_key_manufacturer, (0x1209, 0x53C0)))

        exclusive_id = _DictTransport({"product_string": "Wallet", "manufacturer_string": "Vendor"})
        self.assertTrue(onekey._is_onekey_transport(exclusive_id, (0x1209, 0x4F4A)))

        not_onekey = _DictTransport({"product_string": "Wallet", "manufacturer_string": "Vendor"})
        self.assertFalse(onekey._is_onekey_transport(not_onekey, (0x1209, 0x53C0)))

    def test_is_onekey_transport_with_webusb_device(self):
        raw_device = _RawUsbDevice(product="OneKey Touch", manufacturer="Unknown")
        self.assertTrue(onekey._is_onekey_transport(_DictTransport(raw_device), (0x1209, 0x53C0)))

        failing = _FailingRawUsbDevice(product="OneKey Touch", manufacturer="Unknown")
        self.assertFalse(onekey._is_onekey_transport(_DictTransport(failing), (0x1209, 0x53C0)))

    def test_locked_instructions_by_model(self):
        self.assertIn("sendpin", onekey._locked_instructions("1"))
        self.assertIn("sendpin", onekey._locked_instructions("classic1s"))
        self.assertNotIn("sendpin", onekey._locked_instructions("pro"))
        self.assertNotIn("sendpin", onekey._locked_instructions("touch"))


class TestOnekeyEnumerate(unittest.TestCase):
    def _run_enumerate_with_features(self, features, path="hid:onekey"):
        transport = _EnumerateTransport(
            {
                "vendor_id": 0x1209,
                "product_id": 0x53C0,
                "product_string": "OneKey",
                "manufacturer_string": "OneKey",
            },
            path=path,
        )

        with mock.patch.object(onekey.hid.HidTransport, "enumerate", return_value=[transport]), mock.patch.object(
            onekey.webusb.WebUsbTransport, "enumerate", return_value=[]
        ), mock.patch.object(onekey, "OnekeyClient", return_value=_FakeOnekeyClient(features)):
            return onekey.enumerate()

    def test_enumerate_keeps_locked_classic_device(self):
        results = self._run_enumerate_with_features(_FakeFeatures(model="1", unlocked=False))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["type"], "onekey")
        self.assertEqual(results[0]["model"], "onekey_1")
        self.assertTrue(results[0]["needs_pin_sent"])
        self.assertIsNone(results[0]["fingerprint"])
        self.assertIn("warnings", results[0])
        self.assertIn("sendpin", results[0]["warnings"][0][0])

    def test_enumerate_keeps_locked_pro_device(self):
        results = self._run_enumerate_with_features(_FakeFeatures(model="pro", unlocked=False))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["model"], "onekey_pro")
        self.assertTrue(results[0]["needs_pin_sent"])
        self.assertIsNone(results[0]["fingerprint"])
        self.assertIn("warnings", results[0])
        self.assertNotIn("sendpin", results[0]["warnings"][0][0])

    def test_enumerate_sets_fingerprint_when_unlocked(self):
        results = self._run_enumerate_with_features(_FakeFeatures(model="pro", unlocked=True))

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]["needs_pin_sent"])
        self.assertEqual(results[0]["fingerprint"], "f23f9fd2")


class TestTrezorOnekeyFilterHelpers(unittest.TestCase):
    def test_trezor_is_onekey_transport_hid(self):
        class FakeHidTransport:
            def __init__(self, raw_device):
                self.device = raw_device

        with mock.patch.object(trezor.hid, "HidTransport", FakeHidTransport):
            one_key = FakeHidTransport({"product_string": "OneKey Pro", "manufacturer_string": "Vendor"})
            self.assertTrue(trezor._is_onekey_transport(one_key))

            not_onekey = FakeHidTransport({"product_string": "Wallet", "manufacturer_string": "Vendor"})
            self.assertFalse(trezor._is_onekey_transport(not_onekey))

    def test_trezor_is_onekey_transport_webusb(self):
        class FakeWebUsbTransport:
            def __init__(self, raw_device):
                self.device = raw_device

        with mock.patch.object(trezor.webusb, "WebUsbTransport", FakeWebUsbTransport):
            one_key = FakeWebUsbTransport(_RawUsbDevice(product="OneKey Pro", manufacturer="Vendor"))
            self.assertTrue(trezor._is_onekey_transport(one_key))

            failing = FakeWebUsbTransport(_FailingRawUsbDevice(product="OneKey Pro", manufacturer="Vendor"))
            self.assertFalse(trezor._is_onekey_transport(failing))

    def test_trezor_is_onekey_transport_unknown_type(self):
        self.assertFalse(trezor._is_onekey_transport(_WebUsbTransport(_RawUsbDevice())))


if __name__ == "__main__":
    unittest.main()
