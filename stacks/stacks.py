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
Core Stacks (STX) & sBTC Electrum plugin.

Handles:
- Deterministic Stacks key derivation (BIP44 m/44'/5757'/0'/0/<index>) from Electrum
  BIP39 or native seeds, plus optional watch-only address storage per wallet.
- Fetching STX and sBTC balances and transaction history via Stacks Blockchain API.
- Building, locally signing, and broadcasting native STX transfers and sBTC SIP-010 transfers.
"""

from decimal import Decimal, InvalidOperation
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union, TYPE_CHECKING

from electrum import constants
from electrum.bip32 import BIP32Node
from electrum.keystore import BIP32_KeyStore, bip39_to_seed
from electrum.mnemonic import Mnemonic
from electrum.plugin import BasePlugin
from electrum.util import UserFacingException

from .api import (
    DEFAULT_CONTRACT_CALL_FEE_USTX,
    DEFAULT_MAINNET_API_URL,
    DEFAULT_STX_TRANSFER_FEE_USTX,
    DEFAULT_TESTNET_API_URL,
    StacksAPIClient,
    StacksBalances,
    StacksPrices,
)
from .c32 import (
    is_valid_stacks_address,
    pubkey_to_stacks_address,
)
from .tx import (
    SBTC_MAINNET_ASSET_NAME,
    SBTC_MAINNET_CONTRACT_ADDRESS,
    SBTC_MAINNET_CONTRACT_NAME,
    SBTC_TESTNET_ASSET_NAME,
    SBTC_TESTNET_CONTRACT_ADDRESS,
    SBTC_TESTNET_CONTRACT_NAME,
    STBTC_MAINNET_ASSET_NAME,
    STBTC_MAINNET_CONTRACT_ADDRESS,
    STBTC_MAINNET_CONTRACT_NAME,
    STBTC_TESTNET_ASSET_NAME,
    STBTC_TESTNET_CONTRACT_ADDRESS,
    STBTC_TESTNET_CONTRACT_NAME,
    build_sbtc_transfer_tx,
    build_stbtc_transfer_tx,
    build_stx_transfer_tx,
)

if TYPE_CHECKING:
    from electrum.wallet import Abstract_Wallet


STACKS_COIN_TYPE = 5757
STX_DECIMALS = 6
SBTC_DECIMALS = 8
STBTC_DECIMALS = 8
USTX_PER_STX = 10 ** STX_DECIMALS
SATS_PER_SBTC = 10 ** SBTC_DECIMALS
SATS_PER_STBTC = 10 ** STBTC_DECIMALS

# Per-wallet DB keys (namespaced to avoid collisions with core Electrum)
DB_KEY_PUBKEY_HEX = "stacks_pubkey_hex"
DB_KEY_DERIVED_PUBKEYS = "stacks_derived_pubkeys"
DB_KEY_WATCH_ADDRESS = "stacks_watch_address"
DB_KEY_WATCH_ADDRESSES = "stacks_watch_addresses"
DB_KEY_ACCOUNT_INDEX = "stacks_account_index"


def format_stx(ustx: int) -> str:
    """Format microSTX as a human-readable STX string."""
    val = Decimal(ustx) / Decimal(USTX_PER_STX)
    return f"{val:.6f} STX"


def format_sbtc(sats: int) -> str:
    """Format sBTC satoshis as a human-readable sBTC string."""
    val = Decimal(sats) / Decimal(SATS_PER_SBTC)
    return f"{val:.8f} sBTC"


def format_stbtc(sats: int) -> str:
    """Format stBTC base units (8 decimals) as a human-readable stBTC string."""
    val = Decimal(sats) / Decimal(SATS_PER_STBTC)
    return f"{val:.8f} stBTC"


def parse_stx_to_ustx(amount: Any) -> int:
    """Parse an STX decimal amount (str, float, Decimal, int) into microSTX."""
    try:
        dec = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError) as e:
        raise UserFacingException(f"Invalid STX amount: {amount!r}") from e
    if dec <= 0:
        raise UserFacingException("STX amount must be greater than zero.")
    ustx = int((dec * Decimal(USTX_PER_STX)).to_integral_exact())
    return ustx


def parse_sbtc_to_sats(amount: Any) -> int:
    """Parse an sBTC decimal amount (str, float, Decimal, int) into satoshis."""
    try:
        dec = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError) as e:
        raise UserFacingException(f"Invalid sBTC amount: {amount!r}") from e
    if dec <= 0:
        raise UserFacingException("sBTC amount must be greater than zero.")
    sats = int((dec * Decimal(SATS_PER_SBTC)).to_integral_exact())
    return sats


def parse_stbtc_to_sats(amount: Any) -> int:
    """Parse an stBTC decimal amount (str, float, Decimal, int) into base units (8 decimals)."""
    try:
        dec = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError) as e:
        raise UserFacingException(f"Invalid stBTC amount: {amount!r}") from e
    if dec <= 0:
        raise UserFacingException("stBTC amount must be greater than zero.")
    sats = int((dec * Decimal(SATS_PER_STBTC)).to_integral_exact())
    return sats


def parse_sbtc_contract_spec(spec: str) -> Tuple[str, str, str]:
    """
    Parse a contract specification of the form:
      '<address>.<contract-name>::<asset-name>' or '<address>.<contract-name>'
    into (contract_address, contract_name, asset_name).
    """
    spec = spec.strip()
    if "::" in spec:
        contract_part, asset_name = spec.split("::", 1)
    else:
        contract_part, asset_name = spec, None
    if "." not in contract_part:
        raise UserFacingException(
            f"Invalid sBTC contract specification {spec!r}; expected '<address>.<contract_name>[::<asset_name>]'"
        )
    contract_address, contract_name = contract_part.split(".", 1)
    if not is_valid_stacks_address(contract_address):
        raise UserFacingException(f"Invalid Stacks contract address: {contract_address!r}")
    if not asset_name:
        asset_name = contract_name
    return contract_address, contract_name, asset_name


class StacksPlugin(BasePlugin):

    def __init__(self, parent, config, name):
        BasePlugin.__init__(self, parent, config, name)
        self.wallets: Dict[str, 'Abstract_Wallet'] = {}

    def is_testnet(self) -> bool:
        return bool(constants.net.TESTNET)

    def get_network_name(self) -> str:
        return "Testnet" if self.is_testnet() else "Mainnet"

    def get_default_api_url(self) -> str:
        return DEFAULT_TESTNET_API_URL if self.is_testnet() else DEFAULT_MAINNET_API_URL

    def get_api_url(self) -> str:
        configured = self.config.get("plugins.stacks.api_url")
        if configured and isinstance(configured, str) and configured.strip():
            return configured.strip().rstrip("/")
        return self.get_default_api_url()

    def set_api_url(self, url: Optional[str]) -> None:
        cleaned = (url or "").strip().rstrip("/")
        self.config.set_key("plugins.stacks.api_url", cleaned or None, save=True)

    def get_default_sbtc_contract(self) -> Tuple[str, str, str]:
        if self.is_testnet():
            return (
                SBTC_TESTNET_CONTRACT_ADDRESS,
                SBTC_TESTNET_CONTRACT_NAME,
                SBTC_TESTNET_ASSET_NAME,
            )
        return (
            SBTC_MAINNET_CONTRACT_ADDRESS,
            SBTC_MAINNET_CONTRACT_NAME,
            SBTC_MAINNET_ASSET_NAME,
        )

    def get_sbtc_contract(self) -> Tuple[str, str, str]:
        configured = self.config.get("plugins.stacks.sbtc_contract")
        if configured and isinstance(configured, str) and configured.strip():
            return parse_sbtc_contract_spec(configured)
        return self.get_default_sbtc_contract()

    def set_sbtc_contract(self, spec: Optional[str]) -> None:
        cleaned = (spec or "").strip()
        if cleaned:
            # Validate before saving
            parse_sbtc_contract_spec(cleaned)
        self.config.set_key("plugins.stacks.sbtc_contract", cleaned or None, save=True)

    def get_sbtc_asset_identifier(self) -> str:
        c_addr, c_name, a_name = self.get_sbtc_contract()
        return f"{c_addr}.{c_name}::{a_name}"

    def get_default_stbtc_contract(self) -> Tuple[str, str, str]:
        if self.is_testnet():
            return (
                STBTC_TESTNET_CONTRACT_ADDRESS,
                STBTC_TESTNET_CONTRACT_NAME,
                STBTC_TESTNET_ASSET_NAME,
            )
        return (
            STBTC_MAINNET_CONTRACT_ADDRESS,
            STBTC_MAINNET_CONTRACT_NAME,
            STBTC_MAINNET_ASSET_NAME,
        )

    def get_stbtc_contract(self) -> Tuple[str, str, str]:
        configured = self.config.get("plugins.stacks.stbtc_contract")
        if configured and isinstance(configured, str) and configured.strip():
            return parse_sbtc_contract_spec(configured)
        return self.get_default_stbtc_contract()

    def set_stbtc_contract(self, spec: Optional[str]) -> None:
        cleaned = (spec or "").strip()
        if cleaned:
            parse_sbtc_contract_spec(cleaned)
        self.config.set_key("plugins.stacks.stbtc_contract", cleaned or None, save=True)

    def get_stbtc_asset_identifier(self) -> str:
        c_addr, c_name, a_name = self.get_stbtc_contract()
        return f"{c_addr}.{c_name}::{a_name}"

    def get_api_client(self) -> StacksAPIClient:
        return StacksAPIClient(self.get_api_url())

    def get_account_index(self, wallet: 'Abstract_Wallet') -> int:
        idx = wallet.db.get(DB_KEY_ACCOUNT_INDEX)
        return int(idx) if idx is not None else 0

    def set_account_index(self, wallet: 'Abstract_Wallet', index: int) -> None:
        if index < 0:
            raise UserFacingException("Account index must be non-negative.")
        wallet.db.put(DB_KEY_ACCOUNT_INDEX, int(index))
        # Update active cached pubkey from derived map if already cached, else clear
        derived = self._get_derived_pubkeys_map(wallet)
        wallet.db.put(DB_KEY_PUBKEY_HEX, derived.get(str(int(index))))
        wallet.save_db()

    def _get_derived_pubkeys_map(self, wallet: 'Abstract_Wallet') -> Dict[str, str]:
        raw = wallet.db.get(DB_KEY_DERIVED_PUBKEYS)
        if isinstance(raw, dict):
            return {str(k): str(v) for k, v in raw.items() if isinstance(v, str)}
        # Migrate legacy single cached pubkey if present
        legacy = wallet.db.get(DB_KEY_PUBKEY_HEX)
        if isinstance(legacy, str) and len(legacy) == 66:
            idx = str(self.get_account_index(wallet))
            return {idx: legacy}
        return {}

    def can_derive_signing_key(self, wallet: 'Abstract_Wallet') -> bool:
        """Return True if this wallet's keystore can derive a Stacks signing key."""
        ks = getattr(wallet, "keystore", None)
        if ks is None:
            return False
        if ks.has_seed():
            return True
        if isinstance(ks, BIP32_KeyStore) and ks.xprv:
            return True
        return False

    def derive_stacks_keypair(
        self,
        wallet: 'Abstract_Wallet',
        password: Optional[str],
        account_index: Optional[int] = None,
    ) -> Tuple[bytes, bytes, str]:
        """
        Derive (privkey32, pubkey33, stacks_address) for the wallet using BIP44 m/44'/5757'/0'/0/<index>.

        - BIP39 seeds use standard PBKDF2-HMAC-SHA512 (compatible with Leather/Xverse/Hiro).
        - Native Electrum seeds use Electrum's Mnemonic.mnemonic_to_seed.
        - Imported xprv wallets without a seed derive from their master xprv.
        """
        ks = getattr(wallet, "keystore", None)
        if ks is None:
            raise UserFacingException("This wallet has no keystore.")

        idx = self.get_account_index(wallet) if account_index is None else int(account_index)
        if idx < 0:
            raise UserFacingException("Account index must be non-negative.")

        derivation_path = f"m/44'/{STACKS_COIN_TYPE}'/0'/0/{idx}"

        if ks.has_seed():
            seed = ks.get_seed(password)
            passphrase = ks.get_passphrase(password) or ""
            seed_type = ks.get_seed_type() if hasattr(ks, "get_seed_type") else None
            if seed_type in ("standard", "segwit"):
                rootseed = Mnemonic.mnemonic_to_seed(seed, passphrase=passphrase)
            else:
                rootseed = bip39_to_seed(seed, passphrase=passphrase)
            root_node = BIP32Node.from_rootseed(rootseed, xtype="standard")
            child = root_node.subkey_at_private_derivation(derivation_path)
        elif isinstance(ks, BIP32_KeyStore) and ks.xprv:
            xprv = ks.get_master_private_key(password)
            node = BIP32Node.from_xkey(xprv)
            if node.depth == 0:
                child = node.subkey_at_private_derivation(derivation_path)
            else:
                child = node.subkey_at_private_derivation(f"m/{STACKS_COIN_TYPE}'/0/{idx}")
        else:
            raise UserFacingException(
                "This wallet is watch-only or does not expose a seed/xprv for Stacks signing. "
                "You can still configure a watch-only Stacks address."
            )

        privkey = child.eckey.get_secret_bytes()
        pubkey = child.eckey.get_public_key_bytes(compressed=True)
        address = pubkey_to_stacks_address(pubkey, testnet=self.is_testnet())

        # Cache compressed pubkey in wallet DB so address can be shown without unlocking
        derived = self._get_derived_pubkeys_map(wallet)
        derived[str(idx)] = pubkey.hex()
        wallet.db.put(DB_KEY_DERIVED_PUBKEYS, derived)
        if account_index is None or idx == self.get_account_index(wallet):
            wallet.db.put(DB_KEY_PUBKEY_HEX, pubkey.hex())
            wallet.db.put(DB_KEY_ACCOUNT_INDEX, idx)
        wallet.save_db()

        return privkey, pubkey, address

    def derive_next_stacks_address(
        self,
        wallet: 'Abstract_Wallet',
        password: Optional[str],
    ) -> Tuple[int, str]:
        """Derive and cache the next unused BIP44 account index (0, 1, 2, ...)."""
        derived = self._get_derived_pubkeys_map(wallet)
        next_idx = 0
        while str(next_idx) in derived:
            next_idx += 1
        _, _, address = self.derive_stacks_keypair(wallet, password, account_index=next_idx)
        return next_idx, address

    def add_watch_address(self, wallet: 'Abstract_Wallet', address: str) -> None:
        addr = (address or "").strip()
        if not is_valid_stacks_address(addr, testnet=self.is_testnet()):
            expected = "ST.../SN... (testnet)" if self.is_testnet() else "SP.../SM... (mainnet)"
            raise UserFacingException(f"Invalid Stacks address for {self.get_network_name()}: expected {expected}")
        watches = self.get_watch_addresses(wallet)
        if addr not in watches:
            watches.append(addr)
        wallet.db.put(DB_KEY_WATCH_ADDRESSES, watches)
        if not wallet.db.get(DB_KEY_WATCH_ADDRESS):
            wallet.db.put(DB_KEY_WATCH_ADDRESS, addr)
        wallet.save_db()

    def import_watch_addresses(
        self,
        wallet: 'Abstract_Wallet',
        addresses: Union[str, Iterable[str]],
    ) -> Dict[str, List[str]]:
        """
        Import one or more watch-only Stacks addresses.
        Accepts a list/iterable of addresses or a string separated by newlines, commas, semicolons, or whitespace.
        Returns {'added': [...], 'duplicates': [...], 'invalid': [...]}.
        """
        if isinstance(addresses, str):
            candidates = [tok.strip() for tok in re.split(r"[\s,;]+", addresses) if tok.strip()]
        else:
            candidates = []
            for item in addresses:
                if isinstance(item, str):
                    candidates.extend(tok.strip() for tok in re.split(r"[\s,;]+", item) if tok.strip())

        watches = self.get_watch_addresses(wallet)
        existing_set = set(watches)
        added: List[str] = []
        duplicates: List[str] = []
        invalid: List[str] = []

        for addr in candidates:
            if not is_valid_stacks_address(addr, testnet=self.is_testnet()):
                invalid.append(addr)
                continue
            if addr in existing_set:
                duplicates.append(addr)
                continue
            watches.append(addr)
            existing_set.add(addr)
            added.append(addr)

        if added:
            wallet.db.put(DB_KEY_WATCH_ADDRESSES, watches)
            if not wallet.db.get(DB_KEY_WATCH_ADDRESS):
                wallet.db.put(DB_KEY_WATCH_ADDRESS, added[0])
            wallet.save_db()

        return {
            "added": added,
            "duplicates": duplicates,
            "invalid": invalid,
        }

    def remove_watch_address(self, wallet: 'Abstract_Wallet', address: str) -> None:
        addr = (address or "").strip()
        watches = [a for a in self.get_watch_addresses(wallet) if a != addr]
        wallet.db.put(DB_KEY_WATCH_ADDRESSES, watches)
        if wallet.db.get(DB_KEY_WATCH_ADDRESS) == addr:
            wallet.db.put(DB_KEY_WATCH_ADDRESS, watches[0] if watches else None)
        wallet.save_db()

    def get_watch_addresses(self, wallet: 'Abstract_Wallet') -> List[str]:
        raw = wallet.db.get(DB_KEY_WATCH_ADDRESSES)
        watches: List[str] = []
        if isinstance(raw, list):
            for a in raw:
                if isinstance(a, str) and a.strip() and a.strip() not in watches:
                    watches.append(a.strip())
        legacy = self.get_watch_address(wallet)
        if legacy and legacy not in watches:
            watches.insert(0, legacy)
        return watches

    def get_all_stacks_addresses(self, wallet: 'Abstract_Wallet') -> List[Dict[str, Any]]:
        """
        Return all known Stacks addresses for this wallet (derived + watch-only) as dicts:
        {
            'address': str,
            'type': 'derived' | 'watch',
            'account_index': Optional[int],
            'path': str,
            'is_active': bool,
        }
        """
        active_addr = self.get_stacks_address(wallet)
        active_idx = self.get_account_index(wallet)
        entries: List[Dict[str, Any]] = []
        seen = set()

        derived = self._get_derived_pubkeys_map(wallet)
        for idx_str in sorted(derived.keys(), key=lambda s: int(s)):
            pub_hex = derived[idx_str]
            try:
                pub = bytes.fromhex(pub_hex)
                if len(pub) != 33:
                    continue
                addr = pubkey_to_stacks_address(pub, testnet=self.is_testnet())
            except Exception:
                continue
            idx = int(idx_str)
            seen.add(addr)
            entries.append({
                "address": addr,
                "type": "derived",
                "account_index": idx,
                "path": f"m/44'/{STACKS_COIN_TYPE}'/0'/0/{idx}",
                "is_active": (idx == active_idx and addr == active_addr),
            })

        for addr in self.get_watch_addresses(wallet):
            if addr in seen:
                continue
            if not is_valid_stacks_address(addr, testnet=self.is_testnet()):
                continue
            seen.add(addr)
            entries.append({
                "address": addr,
                "type": "watch",
                "account_index": None,
                "path": "Watch-only",
                "is_active": (addr == active_addr),
            })

        return entries

    def get_cached_pubkey(self, wallet: 'Abstract_Wallet') -> Optional[bytes]:
        hex_str = wallet.db.get(DB_KEY_PUBKEY_HEX)
        if hex_str and isinstance(hex_str, str):
            try:
                raw = bytes.fromhex(hex_str)
                if len(raw) == 33:
                    return raw
            except ValueError:
                pass
        return None

    def set_watch_address(self, wallet: 'Abstract_Wallet', address: Optional[str]) -> None:
        if not address or not address.strip():
            wallet.db.put(DB_KEY_WATCH_ADDRESS, None)
            wallet.save_db()
            return
        addr = address.strip()
        if not is_valid_stacks_address(addr, testnet=self.is_testnet()):
            expected = "ST.../SN... (testnet)" if self.is_testnet() else "SP.../SM... (mainnet)"
            raise UserFacingException(f"Invalid Stacks address for {self.get_network_name()}: expected {expected}")
        wallet.db.put(DB_KEY_WATCH_ADDRESS, addr)
        wallet.save_db()

    def get_watch_address(self, wallet: 'Abstract_Wallet') -> Optional[str]:
        addr = wallet.db.get(DB_KEY_WATCH_ADDRESS)
        return addr if isinstance(addr, str) and addr.strip() else None

    def get_stacks_address(
        self,
        wallet: 'Abstract_Wallet',
        password: Optional[str] = None,
    ) -> Optional[str]:
        """
        Return the wallet's Stacks address:
        1. Cached derived pubkey -> SP.../ST... address
        2. If not cached and wallet can derive without password (or password provided), derive & cache
        3. Fallback to watch-only address if configured
        """
        pubkey = self.get_cached_pubkey(wallet)
        if pubkey is not None:
            return pubkey_to_stacks_address(pubkey, testnet=self.is_testnet())

        if self.can_derive_signing_key(wallet) and (password is not None or not wallet.has_password()):
            _, _, addr = self.derive_stacks_keypair(wallet, password)
            return addr

        return self.get_watch_address(wallet)

    def start_wallet(self, wallet: 'Abstract_Wallet') -> None:
        self.wallets[wallet.storage.path] = wallet
        # Auto-derive and cache pubkey if wallet is unencrypted
        if self.get_cached_pubkey(wallet) is None and self.can_derive_signing_key(wallet) and not wallet.has_password():
            try:
                self.derive_stacks_keypair(wallet, password=None)
            except Exception as e:
                self.logger.warning(f"Could not auto-derive Stacks address: {e}")

    def stop_wallet(self, wallet: 'Abstract_Wallet') -> None:
        self.wallets.pop(wallet.storage.path, None)

    async def fetch_balances(self, address: str) -> StacksBalances:
        if not is_valid_stacks_address(address, testnet=self.is_testnet()):
            raise UserFacingException(f"Invalid Stacks address for {self.get_network_name()}: {address}")
        client = self.get_api_client()
        return await client.get_balances(
            address,
            self.get_sbtc_asset_identifier(),
            self.get_stbtc_asset_identifier(),
        )

    async def fetch_all_balances(self, wallet: 'Abstract_Wallet') -> StacksBalances:
        """Sum STX, sBTC, and stBTC balances across all derived and watch-only addresses."""
        entries = self.get_all_stacks_addresses(wallet)
        total_stx = 0
        total_locked = 0
        total_sbtc = 0
        total_stbtc = 0
        for entry in entries:
            bal = await self.fetch_balances(entry["address"])
            total_stx += bal.stx_balance_ustx
            total_locked += bal.stx_locked_ustx
            total_sbtc += bal.sbtc_balance_sats
            total_stbtc += bal.stbtc_balance_sats
        return StacksBalances(
            address="all",
            stx_balance_ustx=total_stx,
            stx_locked_ustx=total_locked,
            sbtc_balance_sats=total_sbtc,
            sbtc_contract_id=self.get_sbtc_asset_identifier(),
            stbtc_balance_sats=total_stbtc,
            stbtc_contract_id=self.get_stbtc_asset_identifier(),
        )

    async def fetch_live_prices(self, fallback_btc_usd: Optional[Decimal] = None) -> StacksPrices:
        client = self.get_api_client()
        return await client.get_live_prices(fallback_btc_usd=fallback_btc_usd)

    async def fetch_transactions(self, address: str, limit: int = 25) -> List[Dict[str, Any]]:
        if not is_valid_stacks_address(address, testnet=self.is_testnet()):
            raise UserFacingException(f"Invalid Stacks address for {self.get_network_name()}: {address}")
        client = self.get_api_client()
        return await client.get_transactions(
            address,
            limit=limit,
            sbtc_asset_identifier=self.get_sbtc_asset_identifier(),
            stbtc_asset_identifier=self.get_stbtc_asset_identifier(),
        )

    async def send_stx(
        self,
        wallet: 'Abstract_Wallet',
        recipient: str,
        amount_stx: Any,
        password: Optional[str],
        *,
        memo: str = "",
        fee_ustx: Optional[int] = None,
        nonce: Optional[int] = None,
        broadcast: bool = True,
    ) -> Dict[str, Any]:
        """Build, locally sign, and optionally broadcast a native STX transfer."""
        recipient = recipient.strip()
        if not is_valid_stacks_address(recipient, testnet=self.is_testnet()):
            raise UserFacingException(f"Invalid recipient Stacks address for {self.get_network_name()}: {recipient}")

        amount_ustx = parse_stx_to_ustx(amount_stx)
        privkey, pubkey, sender_address = self.derive_stacks_keypair(wallet, password)
        client = self.get_api_client()

        if nonce is None:
            acct = await client.get_account_info(sender_address)
            nonce = acct.nonce

        # Build draft tx for fee estimation if fee not specified
        draft_tx = build_stx_transfer_tx(
            sender_pubkey=pubkey,
            recipient=recipient,
            amount_ustx=amount_ustx,
            nonce=nonce,
            fee_ustx=fee_ustx if fee_ustx is not None else DEFAULT_STX_TRANSFER_FEE_USTX,
            memo=memo,
            testnet=self.is_testnet(),
        )
        if fee_ustx is None:
            estimated = await client.estimate_fee(
                draft_tx.payload.serialize(),
                len(draft_tx.serialize()),
                fallback_ustx=DEFAULT_STX_TRANSFER_FEE_USTX,
            )
            draft_tx.spending_condition.fee_ustx = estimated

        draft_tx.sign(privkey)
        raw_tx = draft_tx.serialize()
        txid = draft_tx.txid()

        if broadcast:
            txid = await client.broadcast_transaction(raw_tx)

        return {
            "txid": txid,
            "sender": sender_address,
            "recipient": recipient,
            "amount_ustx": amount_ustx,
            "amount_stx": str(Decimal(amount_ustx) / Decimal(USTX_PER_STX)),
            "fee_ustx": draft_tx.spending_condition.fee_ustx,
            "nonce": nonce,
            "broadcast": broadcast,
            "raw_tx_hex": raw_tx.hex(),
        }

    async def send_sbtc(
        self,
        wallet: 'Abstract_Wallet',
        recipient: str,
        amount_sbtc: Any,
        password: Optional[str],
        *,
        memo: str = "",
        fee_ustx: Optional[int] = None,
        nonce: Optional[int] = None,
        broadcast: bool = True,
    ) -> Dict[str, Any]:
        """Build, locally sign, and optionally broadcast an sBTC SIP-010 `transfer` transaction."""
        recipient = recipient.strip()
        if not is_valid_stacks_address(recipient, testnet=self.is_testnet()):
            raise UserFacingException(f"Invalid recipient Stacks address for {self.get_network_name()}: {recipient}")

        amount_sats = parse_sbtc_to_sats(amount_sbtc)
        privkey, pubkey, sender_address = self.derive_stacks_keypair(wallet, password)
        c_addr, c_name, a_name = self.get_sbtc_contract()
        client = self.get_api_client()

        if nonce is None:
            acct = await client.get_account_info(sender_address)
            nonce = acct.nonce

        draft_tx = build_sbtc_transfer_tx(
            sender_pubkey=pubkey,
            recipient=recipient,
            amount_sats=amount_sats,
            nonce=nonce,
            fee_ustx=fee_ustx if fee_ustx is not None else DEFAULT_CONTRACT_CALL_FEE_USTX,
            memo=memo,
            testnet=self.is_testnet(),
            contract_address=c_addr,
            contract_name=c_name,
            asset_name=a_name,
        )
        if fee_ustx is None:
            estimated = await client.estimate_fee(
                draft_tx.payload.serialize(),
                len(draft_tx.serialize()),
                fallback_ustx=DEFAULT_CONTRACT_CALL_FEE_USTX,
            )
            draft_tx.spending_condition.fee_ustx = estimated

        draft_tx.sign(privkey)
        raw_tx = draft_tx.serialize()
        txid = draft_tx.txid()

        if broadcast:
            txid = await client.broadcast_transaction(raw_tx)

        return {
            "txid": txid,
            "sender": sender_address,
            "recipient": recipient,
            "amount_sats": amount_sats,
            "amount_sbtc": str(Decimal(amount_sats) / Decimal(SATS_PER_SBTC)),
            "contract": f"{c_addr}.{c_name}::{a_name}",
            "fee_ustx": draft_tx.spending_condition.fee_ustx,
            "nonce": nonce,
            "broadcast": broadcast,
            "raw_tx_hex": raw_tx.hex(),
        }

    async def send_stbtc(
        self,
        wallet: 'Abstract_Wallet',
        recipient: str,
        amount_stbtc: Any,
        password: Optional[str],
        *,
        memo: str = "",
        fee_ustx: Optional[int] = None,
        nonce: Optional[int] = None,
        broadcast: bool = True,
    ) -> Dict[str, Any]:
        """Build, locally sign, and optionally broadcast an stBTC SIP-010 `transfer` transaction."""
        recipient = recipient.strip()
        if not is_valid_stacks_address(recipient, testnet=self.is_testnet()):
            raise UserFacingException(f"Invalid recipient Stacks address for {self.get_network_name()}: {recipient}")

        amount_sats = parse_stbtc_to_sats(amount_stbtc)
        privkey, pubkey, sender_address = self.derive_stacks_keypair(wallet, password)
        c_addr, c_name, a_name = self.get_stbtc_contract()
        client = self.get_api_client()

        if nonce is None:
            acct = await client.get_account_info(sender_address)
            nonce = acct.nonce

        draft_tx = build_stbtc_transfer_tx(
            sender_pubkey=pubkey,
            recipient=recipient,
            amount_sats=amount_sats,
            nonce=nonce,
            fee_ustx=fee_ustx if fee_ustx is not None else DEFAULT_CONTRACT_CALL_FEE_USTX,
            memo=memo,
            testnet=self.is_testnet(),
            contract_address=c_addr,
            contract_name=c_name,
            asset_name=a_name,
        )
        if fee_ustx is None:
            estimated = await client.estimate_fee(
                draft_tx.payload.serialize(),
                len(draft_tx.serialize()),
                fallback_ustx=DEFAULT_CONTRACT_CALL_FEE_USTX,
            )
            draft_tx.spending_condition.fee_ustx = estimated

        draft_tx.sign(privkey)
        raw_tx = draft_tx.serialize()
        txid = draft_tx.txid()

        if broadcast:
            txid = await client.broadcast_transaction(raw_tx)

        return {
            "txid": txid,
            "sender": sender_address,
            "recipient": recipient,
            "amount_sats": amount_sats,
            "amount_stbtc": str(Decimal(amount_sats) / Decimal(SATS_PER_STBTC)),
            "contract": f"{c_addr}.{c_name}::{a_name}",
            "fee_ustx": draft_tx.spending_condition.fee_ustx,
            "nonce": nonce,
            "broadcast": broadcast,
            "raw_tx_hex": raw_tx.hex(),
        }
