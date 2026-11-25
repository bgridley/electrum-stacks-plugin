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
Pure-Python c32check & Stacks address encoding/decoding.

Implements the Stacks c32check specification:
- Crockford Base32 alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ
- Address version bytes:
    22 -> 'P' -> SP... (Mainnet Single-Sig P2PKH)
    20 -> 'M' -> SM... (Mainnet Multi-Sig P2SH)
    26 -> 'T' -> ST... (Testnet Single-Sig P2PKH)
    21 -> 'N' -> SN... (Testnet Multi-Sig P2SH)
"""

import hashlib
from typing import Tuple, Optional

C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_C32_DECODE_MAP = {ch: idx for idx, ch in enumerate(C32_ALPHABET)}
# Crockford Base32 normalization aliases
_C32_NORMALIZE = str.maketrans({
    "O": "0",
    "o": "0",
    "I": "1",
    "i": "1",
    "L": "1",
    "l": "1",
})

# Stacks address version bytes
ADDR_VERSION_MAINNET_SINGLE_SIG = 22  # 'P' -> SP
ADDR_VERSION_MAINNET_MULTI_SIG = 20   # 'M' -> SM
ADDR_VERSION_TESTNET_SINGLE_SIG = 26  # 'T' -> ST
ADDR_VERSION_TESTNET_MULTI_SIG = 21   # 'N' -> SN

VALID_ADDRESS_VERSIONS = {
    ADDR_VERSION_MAINNET_SINGLE_SIG,
    ADDR_VERSION_MAINNET_MULTI_SIG,
    ADDR_VERSION_TESTNET_SINGLE_SIG,
    ADDR_VERSION_TESTNET_MULTI_SIG,
}

MAINNET_ADDRESS_VERSIONS = {
    ADDR_VERSION_MAINNET_SINGLE_SIG,
    ADDR_VERSION_MAINNET_MULTI_SIG,
}

TESTNET_ADDRESS_VERSIONS = {
    ADDR_VERSION_TESTNET_SINGLE_SIG,
    ADDR_VERSION_TESTNET_MULTI_SIG,
}


class C32Error(ValueError):
    """Raised on invalid c32 or c32check input."""


def _sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _c32_checksum(version: int, data: bytes) -> bytes:
    if not (0 <= version < 32):
        raise C32Error(f"Invalid c32check version: {version}")
    return _sha256d(bytes([version]) + data)[:4]


def c32_encode(data: bytes) -> str:
    """Encode arbitrary bytes into Crockford Base32 (c32) per Stacks c32check spec."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    if not data:
        return ""

    # Count leading zero bytes
    leading_zeros = 0
    for b in data:
        if b == 0:
            leading_zeros += 1
        else:
            break

    # Convert byte sequence to base-32 digits from LSB to MSB
    val = int.from_bytes(data, "big")
    chars = []
    while val > 0:
        val, rem = divmod(val, 32)
        chars.append(C32_ALPHABET[rem])
    chars.reverse()

    # Preserve leading zero bytes as leading '0' characters
    return ("0" * leading_zeros) + "".join(chars)


def c32_decode(c32_str: str, min_length: Optional[int] = None) -> bytes:
    """Decode a c32 string into raw bytes."""
    if not isinstance(c32_str, str):
        raise TypeError("c32_str must be str")
    if not c32_str:
        return b""

    normalized = c32_str.translate(_C32_NORMALIZE).upper()

    # Count leading '0' characters (represent leading zero bytes)
    leading_zeros = 0
    for ch in normalized:
        if ch == "0":
            leading_zeros += 1
        else:
            break

    val = 0
    for ch in normalized:
        if ch not in _C32_DECODE_MAP:
            raise C32Error(f"Invalid c32 character: {ch!r}")
        val = (val << 5) | _C32_DECODE_MAP[ch]

    if val == 0:
        raw = b""
    else:
        byte_len = (val.bit_length() + 7) // 8
        raw = val.to_bytes(byte_len, "big")

    result = (b"\x00" * leading_zeros) + raw
    if min_length is not None and len(result) < min_length:
        result = (b"\x00" * (min_length - len(result))) + result
    return result


def c32check_encode(version: int, data: bytes) -> str:
    """Encode (version, data) using c32check."""
    if not (0 <= version < 32):
        raise C32Error(f"Invalid version byte: {version}")
    checksum = _c32_checksum(version, data)
    encoded = c32_encode(data + checksum)
    return C32_ALPHABET[version] + encoded


def c32check_decode(c32_str: str) -> Tuple[int, bytes]:
    """Decode a c32check string into (version, data) and verify its 4-byte checksum."""
    if not c32_str or len(c32_str) < 2:
        raise C32Error("c32check string too short")
    normalized = c32_str.translate(_C32_NORMALIZE).upper()
    version_char = normalized[0]
    if version_char not in _C32_DECODE_MAP:
        raise C32Error(f"Invalid version character: {version_char!r}")
    version = _C32_DECODE_MAP[version_char]
    payload_and_checksum = c32_decode(normalized[1:])
    if len(payload_and_checksum) < 4:
        raise C32Error("c32check payload too short for checksum")
    data = payload_and_checksum[:-4]
    checksum = payload_and_checksum[-4:]
    expected = _c32_checksum(version, data)
    if checksum != expected:
        raise C32Error("Invalid c32check checksum")
    return version, data


def hash160_bytes(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))."""
    sha = hashlib.sha256(data).digest()
    h = hashlib.new("ripemd160")
    h.update(sha)
    return h.digest()


def c32_address(version: int, hash160: bytes) -> str:
    """Encode a Stacks address ('S' + c32check(version, hash160))."""
    if version not in VALID_ADDRESS_VERSIONS:
        raise C32Error(f"Unsupported Stacks address version: {version}")
    if len(hash160) != 20:
        raise C32Error(f"hash160 must be 20 bytes, got {len(hash160)}")
    return "S" + c32check_encode(version, hash160)


def c32_address_decode(address: str) -> Tuple[int, bytes]:
    """Decode a Stacks address ('SP...', 'SM...', 'ST...', 'SN...') into (version, hash160)."""
    if not isinstance(address, str) or len(address) < 3:
        raise C32Error("Invalid Stacks address")
    addr = address.strip()
    if not addr or addr[0].upper() != "S":
        raise C32Error("Stacks address must start with 'S'")
    version, data = c32check_decode(addr[1:])
    if version not in VALID_ADDRESS_VERSIONS:
        raise C32Error(f"Invalid Stacks address version: {version}")
    # Leading zero bytes in hash160 may need padding if c32_decode stripped any
    if len(data) < 20:
        data = (b"\x00" * (20 - len(data))) + data
    if len(data) != 20:
        raise C32Error(f"Invalid Stacks address hash160 length: {len(data)}")
    return version, data


def pubkey_to_stacks_address(pubkey_bytes: bytes, *, testnet: bool = False) -> str:
    """Derive a standard single-sig Stacks address (SP... or ST...) from a 33-byte compressed pubkey."""
    if len(pubkey_bytes) not in (33, 65):
        raise ValueError(f"Expected 33-byte compressed (or 65-byte uncompressed) pubkey, got {len(pubkey_bytes)}")
    version = ADDR_VERSION_TESTNET_SINGLE_SIG if testnet else ADDR_VERSION_MAINNET_SINGLE_SIG
    return c32_address(version, hash160_bytes(pubkey_bytes))


def is_valid_stacks_address(address: str, *, testnet: Optional[bool] = None) -> bool:
    """Return True if address is a valid Stacks standard/multisig address (optionally checking network)."""
    try:
        version, _ = c32_address_decode(address)
    except C32Error:
        return False
    if testnet is True:
        return version in TESTNET_ADDRESS_VERSIONS
    if testnet is False:
        return version in MAINNET_ADDRESS_VERSIONS
    return True


def parse_principal(principal: str) -> Tuple[int, bytes, Optional[str]]:
    """
    Parse a Stacks principal string into (version, hash160, contract_name_or_None).
    Accepts either a standard principal ('SP...') or contract principal ('SP....contract-name').
    """
    principal = principal.strip()
    if "." in principal:
        addr_part, contract_name = principal.split(".", 1)
        if not contract_name or len(contract_name) > 128:
            raise C32Error(f"Invalid contract name: {contract_name!r}")
        version, h160 = c32_address_decode(addr_part)
        return version, h160, contract_name
    version, h160 = c32_address_decode(principal)
    return version, h160, None
