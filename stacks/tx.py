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
Pure-Python Stacks SIP-005 Transaction Builder & Local Signer.

Supports:
- Native STX token transfers (PayloadType.TokenTransfer = 0x00)
- Smart contract calls (PayloadType.ContractCall = 0x02), including sBTC SIP-010 transfers
- Fungible & STX post-conditions
- SHA-512/256 sighash & presign-sighash computation
- Recoverable secp256k1 VRS signing via electrum_ecc
"""

from dataclasses import dataclass, field
import hashlib
import struct
from typing import List, Optional, Sequence, Union

from .c32 import (
    c32_address_decode,
    hash160_bytes,
    pubkey_to_stacks_address,
)
from .clarity import (
    FUNGIBLE_COND_EQ,
    FungiblePostCondition,
    STXPostCondition,
    serialize_optional_buff,
    serialize_principal,
    serialize_uint,
)


# SIP-005 Wire Format Constants
TX_VERSION_MAINNET = 0x00
TX_VERSION_TESTNET = 0x80

CHAIN_ID_MAINNET = 0x00000001
CHAIN_ID_TESTNET = 0x80000000

AUTH_TYPE_STANDARD = 0x04
AUTH_TYPE_SPONSORED = 0x05

HASH_MODE_SINGLESIG_P2PKH = 0x00

PUBKEY_ENCODING_COMPRESSED = 0x00
PUBKEY_ENCODING_UNCOMPRESSED = 0x01

ANCHOR_MODE_ON_CHAIN_ONLY = 0x01
ANCHOR_MODE_OFF_CHAIN_ONLY = 0x02
ANCHOR_MODE_ANY = 0x03

POST_CONDITION_MODE_ALLOW = 0x01
POST_CONDITION_MODE_DENY = 0x02

PAYLOAD_TYPE_TOKEN_TRANSFER = 0x00
PAYLOAD_TYPE_CONTRACT_CALL = 0x02

MEMO_MAX_BYTES = 34
EMPTY_SIGNATURE = b"\x00" * 65

# Official sBTC SIP-010 Token Contracts
SBTC_MAINNET_CONTRACT_ADDRESS = "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4"
SBTC_MAINNET_CONTRACT_NAME = "sbtc-token"
SBTC_MAINNET_ASSET_NAME = "sbtc-token"

SBTC_TESTNET_CONTRACT_ADDRESS = "SN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1"
SBTC_TESTNET_CONTRACT_NAME = "sbtc-token"
SBTC_TESTNET_ASSET_NAME = "sbtc-token"

# Official stBTC (Stacking DAO) SIP-010 Token Contracts
STBTC_MAINNET_CONTRACT_ADDRESS = "SP4SZE494VC2YC5JYG7AYFQ44F5Q4PYV7DVMDPBG"
STBTC_MAINNET_CONTRACT_NAME = "stbtc-token"
STBTC_MAINNET_ASSET_NAME = "stbtc"

STBTC_TESTNET_CONTRACT_ADDRESS = "ST4SZE494VC2YC5JYG7AYFQ44F5Q4PYV7E4Y1TDV"
STBTC_TESTNET_CONTRACT_NAME = "stbtc-token"
STBTC_TESTNET_ASSET_NAME = "stbtc"


def sha512_256(data: bytes) -> bytes:
    """Compute SHA-512/256 digest (used by Stacks SIP-005 for txid and sighashes)."""
    return hashlib.new("sha512_256", data).digest()


def _serialize_len_ascii(s: str) -> bytes:
    b = s.encode("ascii")
    if len(b) > 128:
        raise ValueError(f"Identifier too long ({len(b)} bytes): {s!r}")
    return bytes([len(b)]) + b


@dataclass
class TokenTransferPayload:
    """SIP-005 native STX token transfer payload."""
    recipient: str
    amount_ustx: int
    memo: str = ""

    def serialize(self) -> bytes:
        if self.amount_ustx < 0 or self.amount_ustx >= (1 << 64):
            raise ValueError(f"amount_ustx out of uint64 range: {self.amount_ustx}")
        memo_bytes = self.memo.encode("utf-8")
        if len(memo_bytes) > MEMO_MAX_BYTES:
            raise ValueError(f"Memo exceeds {MEMO_MAX_BYTES} bytes ({len(memo_bytes)} bytes)")
        memo_padded = memo_bytes.ljust(MEMO_MAX_BYTES, b"\x00")
        return (
            bytes([PAYLOAD_TYPE_TOKEN_TRANSFER])
            + serialize_principal(self.recipient)
            + struct.pack(">Q", self.amount_ustx)
            + memo_padded
        )


@dataclass
class ContractCallPayload:
    """SIP-005 Clarity smart contract call payload."""
    contract_address: str
    contract_name: str
    function_name: str
    function_args: List[bytes] = field(default_factory=list)

    def serialize(self) -> bytes:
        version, h160 = c32_address_decode(self.contract_address)
        parts = [
            bytes([PAYLOAD_TYPE_CONTRACT_CALL, version]),
            h160,
            _serialize_len_ascii(self.contract_name),
            _serialize_len_ascii(self.function_name),
            struct.pack(">I", len(self.function_args)),
        ]
        parts.extend(self.function_args)
        return b"".join(parts)


@dataclass
class SingleSigSpendingCondition:
    """SIP-005 Standard Single-Sig P2PKH Spending Condition."""
    signer_hash160: bytes
    nonce: int = 0
    fee_ustx: int = 0
    key_encoding: int = PUBKEY_ENCODING_COMPRESSED
    signature: bytes = EMPTY_SIGNATURE

    def serialize(self) -> bytes:
        if len(self.signer_hash160) != 20:
            raise ValueError("signer_hash160 must be 20 bytes")
        if len(self.signature) != 65:
            raise ValueError("signature must be 65 bytes")
        return (
            bytes([HASH_MODE_SINGLESIG_P2PKH])
            + self.signer_hash160
            + struct.pack(">Q", self.nonce)
            + struct.pack(">Q", self.fee_ustx)
            + bytes([self.key_encoding])
            + self.signature
        )

    def cleared(self) -> "SingleSigSpendingCondition":
        """Return a copy with nonce=0, fee=0, and zeroed 65-byte signature for initial sighash."""
        return SingleSigSpendingCondition(
            signer_hash160=self.signer_hash160,
            nonce=0,
            fee_ustx=0,
            key_encoding=self.key_encoding,
            signature=EMPTY_SIGNATURE,
        )


PostCondition = Union[STXPostCondition, FungiblePostCondition]
TxPayload = Union[TokenTransferPayload, ContractCallPayload]


@dataclass
class StacksTransaction:
    """SIP-005 Stacks Transaction (Standard Single-Sig)."""
    version: int
    chain_id: int
    spending_condition: SingleSigSpendingCondition
    payload: TxPayload
    anchor_mode: int = ANCHOR_MODE_ANY
    post_condition_mode: int = POST_CONDITION_MODE_DENY
    post_conditions: List[PostCondition] = field(default_factory=list)
    auth_type: int = AUTH_TYPE_STANDARD

    def serialize(self) -> bytes:
        parts = [
            bytes([self.version]),
            struct.pack(">I", self.chain_id),
            bytes([self.auth_type]),
            self.spending_condition.serialize(),
            bytes([self.anchor_mode, self.post_condition_mode]),
            struct.pack(">I", len(self.post_conditions)),
        ]
        for pc in self.post_conditions:
            parts.append(pc.serialize())
        parts.append(self.payload.serialize())
        return b"".join(parts)

    def txid(self) -> str:
        """Return the transaction ID (SHA-512/256 of serialized transaction) as lowercase hex."""
        return sha512_256(self.serialize()).hex()

    def sighash_initial(self) -> bytes:
        """Compute initial sighash with nonce=0, fee=0, signature=0x00*65."""
        cleared_tx = StacksTransaction(
            version=self.version,
            chain_id=self.chain_id,
            spending_condition=self.spending_condition.cleared(),
            payload=self.payload,
            anchor_mode=self.anchor_mode,
            post_condition_mode=self.post_condition_mode,
            post_conditions=self.post_conditions,
            auth_type=self.auth_type,
        )
        return sha512_256(cleared_tx.serialize())

    def presign_sighash(self) -> bytes:
        """
        Compute SIP-005 presign-sighash:
        SHA-512/256(initial_sighash || auth_type (1B) || fee (8B BE) || nonce (8B BE))
        """
        init_hash = self.sighash_initial()
        return sha512_256(
            init_hash
            + bytes([self.auth_type])
            + struct.pack(">Q", self.spending_condition.fee_ustx)
            + struct.pack(">Q", self.spending_condition.nonce)
        )

    def sign(self, privkey_bytes: bytes) -> bytes:
        """
        Sign this transaction in-place with a 32-byte secp256k1 private key using electrum_ecc.
        Produces a 65-byte recoverable VRS signature: [recid (1B: 0..3) || r (32B) || s (32B)].
        """
        import electrum_ecc as ecc

        if len(privkey_bytes) != 32:
            raise ValueError(f"Expected 32-byte private key, got {len(privkey_bytes)}")
        privkey = ecc.ECPrivkey(privkey_bytes)
        compressed_pub = privkey.get_public_key_bytes(compressed=True)
        pub_h160 = hash160_bytes(compressed_pub)
        if pub_h160 != self.spending_condition.signer_hash160:
            raise ValueError("Private key does not match transaction signer hash160")

        digest = self.presign_sighash()
        # electrum_ecc returns [27 + recid || r (32B) || s (32B)] when is_compressed=False
        sig65_btc = privkey.ecdsa_sign_recoverable(digest, is_compressed=False)
        recid = sig65_btc[0] - 27
        if not (0 <= recid <= 3):
            raise ValueError(f"Unexpected recovery ID: {recid}")
        vrs_sig = bytes([recid]) + sig65_btc[1:]
        self.spending_condition.signature = vrs_sig
        self.spending_condition.key_encoding = PUBKEY_ENCODING_COMPRESSED
        return vrs_sig


def build_stx_transfer_tx(
    *,
    sender_pubkey: bytes,
    recipient: str,
    amount_ustx: int,
    nonce: int,
    fee_ustx: int,
    memo: str = "",
    testnet: bool = False,
) -> StacksTransaction:
    """Build an unsigned native STX token transfer transaction."""
    if amount_ustx <= 0:
        raise ValueError("Transfer amount must be positive")
    signer_h160 = hash160_bytes(sender_pubkey)
    return StacksTransaction(
        version=TX_VERSION_TESTNET if testnet else TX_VERSION_MAINNET,
        chain_id=CHAIN_ID_TESTNET if testnet else CHAIN_ID_MAINNET,
        spending_condition=SingleSigSpendingCondition(
            signer_hash160=signer_h160,
            nonce=nonce,
            fee_ustx=fee_ustx,
        ),
        payload=TokenTransferPayload(
            recipient=recipient,
            amount_ustx=amount_ustx,
            memo=memo,
        ),
        anchor_mode=ANCHOR_MODE_ANY,
        post_condition_mode=POST_CONDITION_MODE_DENY,
        post_conditions=[],
    )


def build_sip010_transfer_tx(
    *,
    sender_pubkey: bytes,
    recipient: str,
    amount: int,
    nonce: int,
    fee_ustx: int,
    contract_address: str,
    contract_name: str,
    asset_name: str,
    memo: str = "",
    testnet: bool = False,
) -> StacksTransaction:
    """
    Build an unsigned SIP-010 `transfer` contract-call transaction (used by sBTC, stBTC, etc.).

    SIP-010 signature:
      (transfer (amount uint) (sender principal) (recipient principal) (memo (optional (buff 34))))

    Includes an exact FungiblePostCondition (SentEq) with PostConditionMode.Deny for safety.
    """
    if amount <= 0:
        raise ValueError("Transfer amount must be positive")
    memo_bytes = memo.encode("utf-8") if memo else b""
    if len(memo_bytes) > MEMO_MAX_BYTES:
        raise ValueError(f"Memo exceeds {MEMO_MAX_BYTES} bytes ({len(memo_bytes)} bytes)")

    sender_address = pubkey_to_stacks_address(sender_pubkey, testnet=testnet)
    signer_h160 = hash160_bytes(sender_pubkey)

    fn_args = [
        serialize_uint(amount),
        serialize_principal(sender_address),
        serialize_principal(recipient),
        serialize_optional_buff(memo_bytes if memo_bytes else None),
    ]

    pc = FungiblePostCondition(
        principal_address=sender_address,
        contract_address=contract_address,
        contract_name=contract_name,
        asset_name=asset_name,
        condition_code=FUNGIBLE_COND_EQ,
        amount=amount,
    )

    return StacksTransaction(
        version=TX_VERSION_TESTNET if testnet else TX_VERSION_MAINNET,
        chain_id=CHAIN_ID_TESTNET if testnet else CHAIN_ID_MAINNET,
        spending_condition=SingleSigSpendingCondition(
            signer_hash160=signer_h160,
            nonce=nonce,
            fee_ustx=fee_ustx,
        ),
        payload=ContractCallPayload(
            contract_address=contract_address,
            contract_name=contract_name,
            function_name="transfer",
            function_args=fn_args,
        ),
        anchor_mode=ANCHOR_MODE_ANY,
        post_condition_mode=POST_CONDITION_MODE_DENY,
        post_conditions=[pc],
    )


def build_sbtc_transfer_tx(
    *,
    sender_pubkey: bytes,
    recipient: str,
    amount_sats: int,
    nonce: int,
    fee_ustx: int,
    memo: str = "",
    testnet: bool = False,
    contract_address: Optional[str] = None,
    contract_name: Optional[str] = None,
    asset_name: Optional[str] = None,
) -> StacksTransaction:
    """Build an unsigned sBTC SIP-010 `transfer` contract-call transaction."""
    return build_sip010_transfer_tx(
        sender_pubkey=sender_pubkey,
        recipient=recipient,
        amount=amount_sats,
        nonce=nonce,
        fee_ustx=fee_ustx,
        memo=memo,
        testnet=testnet,
        contract_address=contract_address or (
            SBTC_TESTNET_CONTRACT_ADDRESS if testnet else SBTC_MAINNET_CONTRACT_ADDRESS
        ),
        contract_name=contract_name or (
            SBTC_TESTNET_CONTRACT_NAME if testnet else SBTC_MAINNET_CONTRACT_NAME
        ),
        asset_name=asset_name or (
            SBTC_TESTNET_ASSET_NAME if testnet else SBTC_MAINNET_ASSET_NAME
        ),
    )


def build_stbtc_transfer_tx(
    *,
    sender_pubkey: bytes,
    recipient: str,
    amount_sats: int,
    nonce: int,
    fee_ustx: int,
    memo: str = "",
    testnet: bool = False,
    contract_address: Optional[str] = None,
    contract_name: Optional[str] = None,
    asset_name: Optional[str] = None,
) -> StacksTransaction:
    """Build an unsigned stBTC SIP-010 `transfer` contract-call transaction."""
    return build_sip010_transfer_tx(
        sender_pubkey=sender_pubkey,
        recipient=recipient,
        amount=amount_sats,
        nonce=nonce,
        fee_ustx=fee_ustx,
        memo=memo,
        testnet=testnet,
        contract_address=contract_address or (
            STBTC_TESTNET_CONTRACT_ADDRESS if testnet else STBTC_MAINNET_CONTRACT_ADDRESS
        ),
        contract_name=contract_name or (
            STBTC_TESTNET_CONTRACT_NAME if testnet else STBTC_MAINNET_CONTRACT_NAME
        ),
        asset_name=asset_name or (
            STBTC_TESTNET_ASSET_NAME if testnet else STBTC_MAINNET_ASSET_NAME
        ),
    )
