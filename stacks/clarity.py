#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2025 The Electrum Developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
Pure-Python Clarity value serialization and SIP-005 Post-Condition serialization.
"""

from dataclasses import dataclass
import struct
from typing import Optional

from .c32 import c32_address_decode, parse_principal


# Clarity Value Type Prefixes (SIP-005 / Clarity wire format)
CV_INT = 0x00
CV_UINT = 0x01
CV_BUFFER = 0x02
CV_BOOL_TRUE = 0x03
CV_BOOL_FALSE = 0x04
CV_PRINCIPAL_STANDARD = 0x05
CV_PRINCIPAL_CONTRACT = 0x06
CV_RESPONSE_OK = 0x07
CV_RESPONSE_ERR = 0x08
CV_OPTIONAL_NONE = 0x09
CV_OPTIONAL_SOME = 0x0A
CV_LIST = 0x0B
CV_TUPLE = 0x0C
CV_STRING_ASCII = 0x0D
CV_STRING_UTF8 = 0x0E

# Post-condition types (SIP-005)
PC_TYPE_STX = 0x00
PC_TYPE_FUNGIBLE = 0x01
PC_TYPE_NON_FUNGIBLE = 0x02

# Post-condition principal types
PC_PRINCIPAL_ORIGIN = 0x01
PC_PRINCIPAL_STANDARD = 0x02
PC_PRINCIPAL_CONTRACT = 0x03

# Fungible / STX condition codes
FUNGIBLE_COND_EQ = 0x01
FUNGIBLE_COND_GT = 0x02
FUNGIBLE_COND_GTE = 0x03
FUNGIBLE_COND_LT = 0x04
FUNGIBLE_COND_LTE = 0x05


def serialize_uint(value: int) -> bytes:
    """Serialize a Clarity uint (128-bit unsigned big-endian)."""
    if value < 0 or value >= (1 << 128):
        raise ValueError(f"uint128 out of range: {value}")
    return bytes([CV_UINT]) + value.to_bytes(16, "big", signed=False)


def serialize_int(value: int) -> bytes:
    """Serialize a Clarity int (128-bit signed big-endian)."""
    if value < -(1 << 127) or value >= (1 << 127):
        raise ValueError(f"int128 out of range: {value}")
    return bytes([CV_INT]) + value.to_bytes(16, "big", signed=True)


def serialize_buffer(data: bytes) -> bytes:
    """Serialize a Clarity (buff N) value."""
    return bytes([CV_BUFFER]) + struct.pack(">I", len(data)) + data


def serialize_bool(value: bool) -> bytes:
    """Serialize a Clarity bool."""
    return bytes([CV_BOOL_TRUE if value else CV_BOOL_FALSE])


def serialize_standard_principal(address: str) -> bytes:
    """Serialize a Clarity standard principal."""
    version, h160 = c32_address_decode(address)
    return bytes([CV_PRINCIPAL_STANDARD, version]) + h160


def serialize_contract_principal(address: str, contract_name: str) -> bytes:
    """Serialize a Clarity contract principal."""
    version, h160 = c32_address_decode(address)
    name_bytes = contract_name.encode("ascii")
    if len(name_bytes) > 128:
        raise ValueError("contract_name exceeds 128 bytes")
    return bytes([CV_PRINCIPAL_CONTRACT, version]) + h160 + bytes([len(name_bytes)]) + name_bytes


def serialize_principal(principal: str) -> bytes:
    """Serialize either a standard principal ('SP...') or contract principal ('SP....name')."""
    version, h160, contract_name = parse_principal(principal)
    if contract_name is None:
        return bytes([CV_PRINCIPAL_STANDARD, version]) + h160
    name_bytes = contract_name.encode("ascii")
    return bytes([CV_PRINCIPAL_CONTRACT, version]) + h160 + bytes([len(name_bytes)]) + name_bytes


def serialize_none() -> bytes:
    """Serialize Clarity none."""
    return bytes([CV_OPTIONAL_NONE])


def serialize_some(inner_serialized: bytes) -> bytes:
    """Serialize Clarity (some <inner>)."""
    return bytes([CV_OPTIONAL_SOME]) + inner_serialized


def serialize_optional_buff(data: Optional[bytes]) -> bytes:
    """Serialize Clarity (optional (buff N)) — used for SIP-010 transfer memo."""
    if data is None or len(data) == 0:
        return serialize_none()
    return serialize_some(serialize_buffer(data))


def serialize_string_ascii(value: str) -> bytes:
    encoded = value.encode("ascii")
    return bytes([CV_STRING_ASCII]) + struct.pack(">I", len(encoded)) + encoded


def serialize_string_utf8(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return bytes([CV_STRING_UTF8]) + struct.pack(">I", len(encoded)) + encoded


def _serialize_length_prefixed_ascii(s: str) -> bytes:
    b = s.encode("ascii")
    if len(b) > 255:
        raise ValueError(f"ASCII identifier too long ({len(b)} bytes): {s!r}")
    return bytes([len(b)]) + b


@dataclass(frozen=True)
class STXPostCondition:
    """SIP-005 STX post-condition for a standard principal."""
    principal_address: str
    condition_code: int
    amount_ustx: int

    def serialize(self) -> bytes:
        version, h160 = c32_address_decode(self.principal_address)
        return (
            bytes([PC_TYPE_STX, PC_PRINCIPAL_STANDARD, version])
            + h160
            + bytes([self.condition_code])
            + struct.pack(">Q", self.amount_ustx)
        )


@dataclass(frozen=True)
class FungiblePostCondition:
    """SIP-005 Fungible Token (SIP-010, e.g., sBTC) post-condition for a standard principal."""
    principal_address: str
    contract_address: str
    contract_name: str
    asset_name: str
    condition_code: int
    amount: int

    def serialize(self) -> bytes:
        p_ver, p_h160 = c32_address_decode(self.principal_address)
        c_ver, c_h160 = c32_address_decode(self.contract_address)
        return (
            bytes([PC_TYPE_FUNGIBLE, PC_PRINCIPAL_STANDARD, p_ver])
            + p_h160
            + bytes([c_ver])
            + c_h160
            + _serialize_length_prefixed_ascii(self.contract_name)
            + _serialize_length_prefixed_ascii(self.asset_name)
            + bytes([self.condition_code])
            + struct.pack(">Q", self.amount)
        )
