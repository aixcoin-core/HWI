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
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C0), "OneKey Touch", "Unknown"))
        self.assertTrue(onekey._is_onekey_device((0x1209, 0x53C0), "Wallet", "OneKey"))
        self.assertFalse(onekey._is_onekey_device((0x1209, 0x53C0), "Wallet", "Vendor"))

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
