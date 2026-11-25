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

from decimal import Decimal
from typing import Optional, TYPE_CHECKING

from electrum.commands import plugin_command
from electrum.simple_config import SimpleConfig, ConfigVar
from electrum.util import UserFacingException

if TYPE_CHECKING:
    from electrum.commands import Commands
    from electrum.wallet import Abstract_Wallet
    from .stacks import StacksPlugin


plugin_name = "stacks"

SimpleConfig.STACKS_API_URL = ConfigVar(
    key="plugins.stacks.api_url",
    default="",
    type_=str,
    plugin=plugin_name,
)

SimpleConfig.STACKS_SBTC_CONTRACT = ConfigVar(
    key="plugins.stacks.sbtc_contract",
    default="",
    type_=str,
    plugin=plugin_name,
)

SimpleConfig.STACKS_STBTC_CONTRACT = ConfigVar(
    key="plugins.stacks.stbtc_contract",
    default="",
    type_=str,
    plugin=plugin_name,
)


@plugin_command("w", plugin_name)
async def get_address(
    self: "Commands",
    wallet: "Abstract_Wallet" = None,
    password: Optional[str] = None,
    plugin: "StacksPlugin" = None,
) -> dict:
    """
    Return the Stacks (STX) address for the active wallet.
    Derives from BIP44 m/44'/5757'/0'/0/<index> or returns the configured watch-only address.
    """
    address = plugin.get_stacks_address(wallet, password=password)
    if not address:
        raise UserFacingException(
            "Stacks address not initialized. Provide your wallet password to derive it, "
            "or set a watch-only address via stacks_set_watch_address."
        )
    return {
        "network": plugin.get_network_name(),
        "address": address,
        "account_index": plugin.get_account_index(wallet),
        "can_sign": plugin.can_derive_signing_key(wallet),
    }


@plugin_command("w", plugin_name)
async def set_watch_address(
    self: "Commands",
    address: str,
    wallet: "Abstract_Wallet" = None,
    plugin: "StacksPlugin" = None,
) -> dict:
    """
    Configure a watch-only Stacks (STX) address for the active wallet.

    arg:str:address:Stacks address (SP.../SM... on mainnet, ST.../SN... on testnet)
    """
    plugin.set_watch_address(wallet, address)
    return {
        "network": plugin.get_network_name(),
        "watch_address": plugin.get_watch_address(wallet),
    }


@plugin_command("w", plugin_name)
async def import_watch_addresses(
    self: "Commands",
    addresses: str,
    wallet: "Abstract_Wallet" = None,
    plugin: "StacksPlugin" = None,
) -> dict:
    """
    Import one or more watch-only Stacks (STX) addresses (newline-, comma-, or space-separated).

    arg:str:addresses:One or more Stacks addresses separated by commas, spaces, or newlines
    """
    result = plugin.import_watch_addresses(wallet, addresses)
    return {
        "network": plugin.get_network_name(),
        **result,
    }


@plugin_command("w", plugin_name)
async def list_addresses(
    self: "Commands",
    wallet: "Abstract_Wallet" = None,
    plugin: "StacksPlugin" = None,
) -> list:
    """
    List all derived and imported watch-only Stacks (STX) addresses for the active wallet.
    """
    return plugin.get_all_stacks_addresses(wallet)


@plugin_command("w", plugin_name)
async def get_balance(
    self: "Commands",
    address: Optional[str] = None,
    wallet: "Abstract_Wallet" = None,
    plugin: "StacksPlugin" = None,
) -> dict:
    """
    Fetch STX and sBTC balances for the wallet's Stacks address (or a specified address).

    arg:str:address:Optional Stacks address to query instead of the wallet address
    """
    target = address or plugin.get_stacks_address(wallet)
    if not target:
        raise UserFacingException("No Stacks address available. Run stacks_get_address first or pass an address.")
    bal = await plugin.fetch_balances(target)
    return {
        "network": plugin.get_network_name(),
        "address": bal.address,
        "stx_balance_ustx": bal.stx_balance_ustx,
        "stx_available_ustx": bal.stx_available_ustx,
        "stx_locked_ustx": bal.stx_locked_ustx,
        "stx_balance": str(Decimal(bal.stx_balance_ustx) / Decimal(1_000_000)),
        "sbtc_balance_sats": bal.sbtc_balance_sats,
        "sbtc_balance": str(Decimal(bal.sbtc_balance_sats) / Decimal(100_000_000)),
        "sbtc_contract": bal.sbtc_contract_id,
        "stbtc_balance_sats": bal.stbtc_balance_sats,
        "stbtc_balance": str(Decimal(bal.stbtc_balance_sats) / Decimal(100_000_000)),
        "stbtc_contract": bal.stbtc_contract_id,
    }


@plugin_command("w", plugin_name)
async def get_history(
    self: "Commands",
    address: Optional[str] = None,
    limit: int = 25,
    wallet: "Abstract_Wallet" = None,
    plugin: "StacksPlugin" = None,
) -> list:
    """
    Fetch recent Stacks / sBTC transactions for the wallet's Stacks address (or a specified address).

    arg:str:address:Optional Stacks address to query
    arg:int:limit:Maximum number of transactions to return (default 25)
    """
    target = address or plugin.get_stacks_address(wallet)
    if not target:
        raise UserFacingException("No Stacks address available. Run stacks_get_address first or pass an address.")
    return await plugin.fetch_transactions(target, limit=int(limit))


@plugin_command("wp", plugin_name)
async def send_stx(
    self: "Commands",
    recipient: str,
    amount_stx: str,
    memo: str = "",
    fee_ustx: Optional[int] = None,
    broadcast: bool = True,
    wallet: "Abstract_Wallet" = None,
    password: Optional[str] = None,
    plugin: "StacksPlugin" = None,
) -> dict:
    """
    Send native STX tokens from the active wallet.

    arg:str:recipient:Recipient Stacks address
    arg:str:amount_stx:Amount to send in STX (e.g. "1.5")
    arg:str:memo:Optional memo (max 34 UTF-8 bytes)
    arg:int:fee_ustx:Optional fee in microSTX (auto-estimated if omitted)
    arg:bool:broadcast:Whether to broadcast to the Stacks network (default True)
    """
    return await plugin.send_stx(
        wallet=wallet,
        recipient=recipient,
        amount_stx=amount_stx,
        password=password,
        memo=memo or "",
        fee_ustx=int(fee_ustx) if fee_ustx is not None else None,
        broadcast=bool(broadcast),
    )


@plugin_command("wp", plugin_name)
async def send_sbtc(
    self: "Commands",
    recipient: str,
    amount_sbtc: str,
    memo: str = "",
    fee_ustx: Optional[int] = None,
    broadcast: bool = True,
    wallet: "Abstract_Wallet" = None,
    password: Optional[str] = None,
    plugin: "StacksPlugin" = None,
) -> dict:
    """
    Send sBTC (SIP-010) tokens from the active wallet.

    arg:str:recipient:Recipient Stacks address
    arg:str:amount_sbtc:Amount to send in sBTC (e.g. "0.001")
    arg:str:memo:Optional memo (max 34 UTF-8 bytes)
    arg:int:fee_ustx:Optional transaction fee in microSTX (auto-estimated if omitted)
    arg:bool:broadcast:Whether to broadcast to the Stacks network (default True)
    """
    return await plugin.send_sbtc(
        wallet=wallet,
        recipient=recipient,
        amount_sbtc=amount_sbtc,
        password=password,
        memo=memo or "",
        fee_ustx=int(fee_ustx) if fee_ustx is not None else None,
        broadcast=bool(broadcast),
    )


@plugin_command("wp", plugin_name)
async def send_stbtc(
    self: "Commands",
    recipient: str,
    amount_stbtc: str,
    memo: str = "",
    fee_ustx: Optional[int] = None,
    broadcast: bool = True,
    wallet: "Abstract_Wallet" = None,
    password: Optional[str] = None,
    plugin: "StacksPlugin" = None,
) -> dict:
    """
    Send stBTC (Stacking DAO SIP-010) tokens from the active wallet.

    arg:str:recipient:Recipient Stacks address
    arg:str:amount_stbtc:Amount to send in stBTC (e.g. "0.001")
    arg:str:memo:Optional memo (max 34 UTF-8 bytes)
    arg:int:fee_ustx:Optional transaction fee in microSTX (auto-estimated if omitted)
    arg:bool:broadcast:Whether to broadcast to the Stacks network (default True)
    """
    return await plugin.send_stbtc(
        wallet=wallet,
        recipient=recipient,
        amount_stbtc=amount_stbtc,
        password=password,
        memo=memo or "",
        fee_ustx=int(fee_ustx) if fee_ustx is not None else None,
        broadcast=bool(broadcast),
    )
