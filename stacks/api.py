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
Async HTTP client for the Stacks Blockchain API (Hiro API / self-hosted Stacks node).
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from electrum.network import Network
from electrum.util import make_aiohttp_session


DEFAULT_MAINNET_API_URL = "https://api.mainnet.hiro.so"
DEFAULT_TESTNET_API_URL = "https://api.testnet.hiro.so"

# Fallback fees in uSTX if fee estimation endpoint is unavailable
DEFAULT_STX_TRANSFER_FEE_USTX = 2000
DEFAULT_CONTRACT_CALL_FEE_USTX = 10000


class StacksAPIError(Exception):
    """Raised when the Stacks Blockchain API returns an error."""


@dataclass(frozen=True)
class StacksBalances:
    address: str
    stx_balance_ustx: int
    stx_locked_ustx: int
    sbtc_balance_sats: int
    sbtc_contract_id: str
    stbtc_balance_sats: int = 0
    stbtc_contract_id: str = ""

    @property
    def stx_available_ustx(self) -> int:
        return max(0, self.stx_balance_ustx - self.stx_locked_ustx)


@dataclass(frozen=True)
class StacksAccountInfo:
    address: str
    balance_ustx: int
    locked_ustx: int
    nonce: int


@dataclass(frozen=True)
class StacksPrices:
    btc_usd: Optional[Decimal] = None
    stx_usd: Optional[Decimal] = None
    sbtc_usd: Optional[Decimal] = None
    stbtc_usd: Optional[Decimal] = None


def calculate_portfolio_usd(
    *,
    btc_sats: int,
    stx_ustx: int,
    sbtc_sats: int,
    stbtc_sats: int,
    prices: StacksPrices,
) -> Dict[str, Optional[Decimal]]:
    """
    Calculate USD values for BTC, STX, sBTC, stBTC, Stacks subtotal, and grand total.
    sBTC and stBTC fall back to btc_usd (1:1 peg) when not separately quoted.
    """
    btc_rate = prices.btc_usd
    stx_rate = prices.stx_usd
    sbtc_rate = prices.sbtc_usd if prices.sbtc_usd is not None else btc_rate
    stbtc_rate = prices.stbtc_usd if prices.stbtc_usd is not None else btc_rate

    btc_val = (Decimal(btc_sats) / Decimal(100_000_000) * btc_rate) if btc_rate is not None else None
    stx_val = (Decimal(stx_ustx) / Decimal(1_000_000) * stx_rate) if stx_rate is not None else None
    sbtc_val = (Decimal(sbtc_sats) / Decimal(100_000_000) * sbtc_rate) if sbtc_rate is not None else None
    stbtc_val = (Decimal(stbtc_sats) / Decimal(100_000_000) * stbtc_rate) if stbtc_rate is not None else None

    stacks_parts = [v for v in (stx_val, sbtc_val, stbtc_val) if v is not None]
    stacks_total = sum(stacks_parts, Decimal(0)) if stacks_parts else None

    all_parts = [v for v in (btc_val, stx_val, sbtc_val, stbtc_val) if v is not None]
    grand_total = sum(all_parts, Decimal(0)) if all_parts else None

    return {
        "btc_usd": btc_val,
        "stx_usd": stx_val,
        "sbtc_usd": sbtc_val,
        "stbtc_usd": stbtc_val,
        "stacks_total_usd": stacks_total,
        "grand_total_usd": grand_total,
    }


def _safe_int(val: Any, default: int = 0) -> int:
    """Safely parse an int from a string, int, None, or v3 nested dict (e.g. {'amount': ...} or {'net': ...})."""
    if val is None:
        return default
    if isinstance(val, bool):
        return int(val)
    if isinstance(val, int):
        return val
    if isinstance(val, dict):
        for key in ("net", "amount", "balance", "total", "value"):
            if key in val and val[key] is not None:
                return _safe_int(val[key], default)
        return default
    try:
        s = str(val).strip()
        if not s:
            return default
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return default


def _extract_ft_balance_v3(ft_data: Dict[str, Any], asset_identifier: str) -> int:
    """Extract an FT balance from v3 `/extended/v3/principals/{principal}/balances/ft` JSON."""
    if not asset_identifier or not ft_data:
        return 0
    prefix = asset_identifier.split("::", 1)[0]

    # v3 paginated list format: {"results": [{"asset_identifier": "...", "balance": "..."}]}
    results = ft_data.get("results")
    if isinstance(results, list):
        for entry in results:
            key = entry.get("asset_identifier") or entry.get("token") or ""
            if key == asset_identifier or key.startswith(prefix + "::"):
                return _safe_int(entry.get("balance"))

    # Single-asset endpoint format: {"balance": "..."}
    if "balance" in ft_data and not isinstance(results, list):
        return _safe_int(ft_data.get("balance"))

    return 0


def parse_v3_balances_response(
    address: str,
    stx_data: Dict[str, Any],
    ft_data: Optional[Dict[str, Any]],
    sbtc_asset_identifier: str,
    stbtc_asset_identifier: str = "",
) -> StacksBalances:
    """
    Parse Stacks Blockchain API v3 balance responses:
    - GET /extended/v3/principals/{principal}/balances/stx
    - GET /extended/v3/principals/{principal}/balances/ft
    """
    stx_balance = _safe_int(stx_data.get("balance") if stx_data.get("balance") is not None else stx_data.get("total"))
    stx_locked = _safe_int(stx_data.get("locked"))

    sbtc_balance = _extract_ft_balance_v3(ft_data or {}, sbtc_asset_identifier)
    stbtc_balance = _extract_ft_balance_v3(ft_data or {}, stbtc_asset_identifier)

    return StacksBalances(
        address=address,
        stx_balance_ustx=stx_balance,
        stx_locked_ustx=stx_locked,
        sbtc_balance_sats=sbtc_balance,
        sbtc_contract_id=sbtc_asset_identifier,
        stbtc_balance_sats=stbtc_balance,
        stbtc_contract_id=stbtc_asset_identifier,
    )


def _format_signed_delta(
    stx_delta_ustx: int,
    sbtc_delta_sats: int,
    stbtc_delta_sats: int = 0,
) -> str:
    parts: List[str] = []
    if sbtc_delta_sats != 0:
        sign = "+" if sbtc_delta_sats > 0 else "-"
        parts.append(f"{sign}{abs(sbtc_delta_sats) / 100_000_000:.8f} sBTC")
    if stbtc_delta_sats != 0:
        sign = "+" if stbtc_delta_sats > 0 else "-"
        parts.append(f"{sign}{abs(stbtc_delta_sats) / 100_000_000:.8f} stBTC")
    if stx_delta_ustx != 0 or not parts:
        sign = "+" if stx_delta_ustx > 0 else ("-" if stx_delta_ustx < 0 else "")
        parts.append(f"{sign}{abs(stx_delta_ustx) / 1_000_000:.6f} STX")
    return ", ".join(parts)


def _extract_iso_time(item: Dict[str, Any]) -> str:
    block = item.get("block") or {}
    if isinstance(block, dict):
        if block.get("time_iso"):
            return str(block["time_iso"])
        if isinstance(block.get("time"), (int, float)) and block["time"] > 0:
            return datetime.fromtimestamp(block["time"], tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    btc_block = item.get("bitcoin_block") or {}
    if isinstance(btc_block, dict) and btc_block.get("time_iso"):
        return str(btc_block["time_iso"])
    iso = item.get("burn_block_time_iso")
    if iso:
        return str(iso)
    ts = item.get("burn_block_time") or item.get("parent_burn_block_time")
    if isinstance(ts, (int, float)) and ts > 0:
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return ""


def _summarize_tx(item: Dict[str, Any]) -> str:
    tx_type = item.get("type") or item.get("tx_type") or "unknown"
    if tx_type == "token_transfer":
        tt = item.get("token_transfer") or item.get("native_token_transfer") or {}
        recipient = tt.get("recipient") or tt.get("recipient_address") or ""
        return f"STX -> {recipient}"
    if tx_type == "contract_call":
        cc = item.get("contract_call") or {}
        cid = cc.get("contract_id", "")
        fn = cc.get("function_name", "")
        short_cid = cid.split(".", 1)[-1] if "." in cid else cid
        return f"{short_cid}.{fn}()"
    return tx_type


def _matches_asset(asset_id: str, target_identifier: str) -> bool:
    if not target_identifier or not asset_id:
        return False
    if asset_id == target_identifier:
        return True
    prefix = target_identifier.split("::", 1)[0]
    return asset_id.startswith(prefix + "::")


def parse_v3_transactions_response(
    address: str,
    tx_data: Dict[str, Any],
    ft_balance_changes_by_tx: Optional[Dict[str, Dict[str, Any]]] = None,
    sbtc_asset_identifier: str = "",
    stbtc_asset_identifier: str = "",
) -> List[Dict[str, Any]]:
    """
    Normalize Stacks Blockchain API v3 responses:
    - GET /extended/v3/principals/{principal}/transactions
    - GET /extended/v3/principals/{principal}/balance-changes?tx_id={tx_id} (for FT-affecting txs)

    Extracts exact per-tx net STX delta (uSTX), sBTC delta (sats), and stBTC delta (sats).
    """
    ft_changes_map = ft_balance_changes_by_tx or {}
    results = tx_data.get("results") or []
    normalized: List[Dict[str, Any]] = []

    for entry in results:
        # v3 wraps each tx under entry["transaction"]; support direct dict too
        item = entry.get("transaction") or entry.get("tx") or entry
        txid = item.get("tx_id", "")
        tx_type = item.get("type") or item.get("tx_type") or "unknown"
        tx_status = item.get("status") or item.get("tx_status") or ""

        sender_obj = item.get("sender")
        if isinstance(sender_obj, dict):
            sender = sender_obj.get("address", "")
            nonce = _safe_int(sender_obj.get("nonce"))
        else:
            sender = item.get("sender_address", "")
            nonce = _safe_int(item.get("nonce"))

        block_obj = item.get("block")
        if isinstance(block_obj, dict) and block_obj.get("height") is not None:
            block_height = _safe_int(block_obj.get("height"))
        else:
            bh = item.get("block_height")
            block_height = _safe_int(bh) if bh is not None else None

        fee_ustx = _safe_int(item.get("fee_rate"))

        # Inline STX balance_changes from v3 /principals/{principal}/transactions
        stx_delta = 0
        sbtc_delta = 0
        stbtc_delta = 0

        inline_bc = entry.get("balance_changes")
        if isinstance(inline_bc, dict) and isinstance(inline_bc.get("stx"), dict):
            stx_bc = inline_bc["stx"]
            if stx_bc.get("net") is not None:
                stx_delta = _safe_int(stx_bc.get("net"))
            else:
                stx_delta = _safe_int(stx_bc.get("received")) - _safe_int(stx_bc.get("sent"))
        else:
            if sender == address:
                stx_delta -= fee_ustx
            if tx_type == "token_transfer" and tx_status in ("success", "pending"):
                tt = item.get("token_transfer") or item.get("native_token_transfer") or {}
                amt_ustx = _safe_int(tt.get("amount"))
                recipient = tt.get("recipient") or tt.get("recipient_address") or ""
                if sender == address:
                    stx_delta -= amt_ustx
                if recipient == address:
                    stx_delta += amt_ustx

        # Per-tx FT balance changes from /extended/v3/principals/{principal}/balance-changes?tx_id=...
        if txid in ft_changes_map:
            bc_resp = ft_changes_map[txid] or {}
            for ch in bc_resp.get("results") or []:
                asset = ch.get("asset") or {}
                asset_type = (asset.get("type") or ch.get("asset_type") or "").lower()
                asset_id = asset.get("identifier") or ch.get("asset_identifier") or ""
                bc_val = ch.get("balance_change")
                if isinstance(bc_val, dict):
                    delta = (
                        _safe_int(bc_val.get("net"))
                        if bc_val.get("net") is not None
                        else _safe_int(bc_val.get("received")) - _safe_int(bc_val.get("sent"))
                    )
                else:
                    delta = _safe_int(bc_val)

                if asset_type == "ft" or asset_id:
                    if _matches_asset(asset_id, sbtc_asset_identifier):
                        sbtc_delta += delta
                    elif _matches_asset(asset_id, stbtc_asset_identifier):
                        stbtc_delta += delta

        normalized.append({
            "tx_id": txid,
            "tx_type": tx_type,
            "tx_status": tx_status,
            "sender_address": sender,
            "fee_rate_ustx": fee_ustx,
            "nonce": nonce,
            "block_height": block_height,
            "burn_block_time_iso": _extract_iso_time(item),
            "summary": _summarize_tx(item),
            "stx_delta_ustx": stx_delta,
            "sbtc_delta_sats": sbtc_delta,
            "stbtc_delta_sats": stbtc_delta,
            "amount_display": _format_signed_delta(stx_delta, sbtc_delta, stbtc_delta),
        })
    return normalized


def compute_running_balances(
    txs: List[Dict[str, Any]],
    current_stx_ustx: int,
    current_sbtc_sats: int,
    current_stbtc_sats: int = 0,
) -> List[Dict[str, Any]]:
    """
    Annotate reverse-chronological transactions (newest first) with running STX, sBTC,
    and stBTC balances after each confirmed transaction, matching Electrum's Bitcoin history tab.

    Adds `running_stx_ustx`, `running_sbtc_sats`, and `running_stbtc_sats` (None for pending txs).
    """
    running_stx = int(current_stx_ustx)
    running_sbtc = int(current_sbtc_sats)
    running_stbtc = int(current_stbtc_sats)
    annotated: List[Dict[str, Any]] = []

    for tx in txs:
        row = dict(tx)
        is_confirmed = row.get("block_height") is not None and row.get("tx_status") != "pending"
        if is_confirmed:
            row["running_stx_ustx"] = running_stx
            row["running_sbtc_sats"] = running_sbtc
            row["running_stbtc_sats"] = running_stbtc
            running_stx -= int(row.get("stx_delta_ustx", 0) or 0)
            running_sbtc -= int(row.get("sbtc_delta_sats", 0) or 0)
            running_stbtc -= int(row.get("stbtc_delta_sats", 0) or 0)
        else:
            row["running_stx_ustx"] = None
            row["running_sbtc_sats"] = None
            row["running_stbtc_sats"] = None
        annotated.append(row)

    return annotated


def merge_multi_address_transactions(
    per_address_txs: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """
    Merge transactions across multiple wallet addresses into a single reverse-chronological list.
    If the same tx_id appears in multiple wallet addresses (e.g. an internal transfer between two
    wallet addresses), their STX/sBTC/stBTC deltas are summed so the combined wallet running balance
    remains exact.
    """
    by_txid: Dict[str, Dict[str, Any]] = {}
    order_fallback = 0

    for _addr, txs in per_address_txs.items():
        for tx in txs:
            txid = tx.get("tx_id") or f"_unknown_{order_fallback}"
            order_fallback += 1
            if txid not in by_txid:
                by_txid[txid] = dict(tx)
            else:
                existing = by_txid[txid]
                existing["stx_delta_ustx"] = int(existing.get("stx_delta_ustx", 0) or 0) + int(tx.get("stx_delta_ustx", 0) or 0)
                existing["sbtc_delta_sats"] = int(existing.get("sbtc_delta_sats", 0) or 0) + int(tx.get("sbtc_delta_sats", 0) or 0)
                existing["stbtc_delta_sats"] = int(existing.get("stbtc_delta_sats", 0) or 0) + int(tx.get("stbtc_delta_sats", 0) or 0)
                existing["amount_display"] = _format_signed_delta(
                    existing["stx_delta_ustx"],
                    existing["sbtc_delta_sats"],
                    existing["stbtc_delta_sats"],
                )

    merged = list(by_txid.values())

    def _sort_key(row: Dict[str, Any]):
        bh = row.get("block_height")
        is_pending = bh is None or row.get("tx_status") == "pending"
        # Pending transactions first (1), then highest block height, latest timestamp, highest nonce
        return (
            1 if is_pending else 0,
            int(bh) if bh is not None else -1,
            row.get("burn_block_time_iso") or "",
            int(row.get("nonce", 0) or 0),
        )

    merged.sort(key=_sort_key, reverse=True)
    return merged


class StacksAPIClient:
    """Async client for Stacks Blockchain API using Electrum's proxy-aware aiohttp session."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    def _get_proxy(self):
        network = Network.get_instance()
        return network.proxy if network else None

    async def _get_json(self, path: str) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        async with make_aiohttp_session(self._get_proxy()) as session:
            async with session.get(url, headers={"Accept": "application/json"}) as resp:
                text = await resp.text()
                if resp.status >= 400:
                    raise StacksAPIError(f"GET {path} failed ({resp.status}): {text}")
                try:
                    return await resp.json(content_type=None)
                except Exception as e:
                    raise StacksAPIError(f"Invalid JSON from {path}: {text[:200]}") from e

    async def get_balances(
        self,
        address: str,
        sbtc_asset_identifier: str,
        stbtc_asset_identifier: str = "",
    ) -> StacksBalances:
        """Fetch STX and FT balances via Stacks Blockchain API v3."""
        stx_coro = self._get_json(f"/extended/v3/principals/{address}/balances/stx")
        ft_coro = self._get_json(f"/extended/v3/principals/{address}/balances/ft?limit=100")
        stx_data, ft_res = await asyncio.gather(stx_coro, ft_coro, return_exceptions=True)
        if isinstance(stx_data, Exception):
            raise stx_data
        ft_data = {} if isinstance(ft_res, Exception) else ft_res
        return parse_v3_balances_response(
            address,
            stx_data,
            ft_data,
            sbtc_asset_identifier,
            stbtc_asset_identifier,
        )

    async def get_account_info(self, address: str) -> StacksAccountInfo:
        data = await self._get_json(f"/v2/accounts/{address}?proof=0")
        balance_hex = data.get("balance", "0x0")
        locked_hex = data.get("locked", "0x0")
        balance = int(balance_hex, 16) if isinstance(balance_hex, str) and balance_hex.startswith("0x") else int(balance_hex)
        locked = int(locked_hex, 16) if isinstance(locked_hex, str) and locked_hex.startswith("0x") else int(locked_hex)
        nonce = int(data.get("nonce", 0))
        return StacksAccountInfo(
            address=address,
            balance_ustx=balance,
            locked_ustx=locked,
            nonce=nonce,
        )

    async def get_transactions(
        self,
        address: str,
        limit: int = 25,
        offset: int = 0,
        sbtc_asset_identifier: str = "",
        stbtc_asset_identifier: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Fetch principal transactions via Stacks Blockchain API v3.
        STX balance changes are returned inline; for transactions where `affected_balances.ft`
        is true, fetches per-tx FT balance changes via `/extended/v3/principals/{principal}/balance-changes?tx_id=...`.
        """
        tx_path = f"/extended/v3/principals/{address}/transactions?limit={int(limit)}"
        tx_data = await self._get_json(tx_path)

        ft_changes_by_tx: Dict[str, Dict[str, Any]] = {}
        if sbtc_asset_identifier or stbtc_asset_identifier:
            ft_txids: List[str] = []
            for entry in tx_data.get("results") or []:
                affected = entry.get("affected_balances") or {}
                if affected.get("ft"):
                    tx_obj = entry.get("transaction") or entry
                    tid = tx_obj.get("tx_id")
                    if tid:
                        ft_txids.append(tid)

            if ft_txids:
                sem = asyncio.Semaphore(5)

                async def _fetch_bc(tid: str):
                    async with sem:
                        try:
                            return tid, await self._get_json(
                                f"/extended/v3/principals/{address}/balance-changes?tx_id={tid}"
                            )
                        except Exception:
                            return tid, {}

                bc_results = await asyncio.gather(*(_fetch_bc(tid) for tid in ft_txids))
                ft_changes_by_tx = dict(bc_results)

        return parse_v3_transactions_response(
            address,
            tx_data,
            ft_balance_changes_by_tx=ft_changes_by_tx,
            sbtc_asset_identifier=sbtc_asset_identifier,
            stbtc_asset_identifier=stbtc_asset_identifier,
        )

    async def estimate_fee(
        self,
        payload_bytes: bytes,
        estimated_len: int,
        fallback_ustx: int = DEFAULT_STX_TRANSFER_FEE_USTX,
    ) -> int:
        """Estimate transaction fee in uSTX via `/v2/fees/transaction` with safe fallback."""
        url = f"{self.base_url}/v2/fees/transaction"
        body = {
            "transaction_payload": payload_bytes.hex(),
            "estimated_len": estimated_len,
        }
        try:
            async with make_aiohttp_session(self._get_proxy()) as session:
                async with session.post(url, json=body) as resp:
                    if resp.status >= 400:
                        return fallback_ustx
                    data = await resp.json(content_type=None)
                    estimations = data.get("estimations") or []
                    if estimations:
                        # Middle estimate (index 1 if 3 estimates, else 0)
                        mid = estimations[len(estimations) // 2]
                        fee = int(mid.get("fee", fallback_ustx))
                        return max(fee, 180)
        except Exception:
            pass
        return fallback_ustx

    async def broadcast_transaction(self, tx_bytes: bytes) -> str:
        """Broadcast a raw serialized Stacks transaction via `POST /v2/transactions`."""
        url = f"{self.base_url}/v2/transactions"
        headers = {"Content-Type": "application/octet-stream"}
        async with make_aiohttp_session(self._get_proxy()) as session:
            async with session.post(url, data=tx_bytes, headers=headers) as resp:
                text = (await resp.text()).strip()
                if resp.status >= 400:
                    raise StacksAPIError(f"Broadcast rejected ({resp.status}): {text}")
                # Stacks node returns the txid as a JSON-quoted string (e.g. "\"abcd...\"")
                return text.strip('"')

    async def get_live_prices(self, fallback_btc_usd: Optional[Decimal] = None) -> StacksPrices:
        """
        Fetch live USD spot prices for BTC and STX (with sBTC & stBTC pegged to BTC).
        Primary source: CoinGecko public simple/price API.
        Fallback source: Coinbase public spot price API.
        """
        btc_usd: Optional[Decimal] = fallback_btc_usd
        stx_usd: Optional[Decimal] = None

        def _to_dec(val: Any) -> Optional[Decimal]:
            if val is None:
                return None
            try:
                d = Decimal(str(val))
                return d if d > 0 else None
            except (InvalidOperation, ValueError):
                return None

        # 1. Try CoinGecko (single request for both bitcoin & blockstack/STX)
        try:
            url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,blockstack&vs_currencies=usd"
            async with make_aiohttp_session(self._get_proxy()) as session:
                async with session.get(url, headers={"Accept": "application/json"}) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        cg_btc = _to_dec((data.get("bitcoin") or {}).get("usd"))
                        cg_stx = _to_dec((data.get("blockstack") or {}).get("usd"))
                        if cg_btc is not None:
                            btc_usd = cg_btc
                        if cg_stx is not None:
                            stx_usd = cg_stx
        except Exception:
            pass

        # 2. Fallback to Coinbase public spot API for any missing quote
        if stx_usd is None or btc_usd is None:
            try:
                async with make_aiohttp_session(self._get_proxy()) as session:
                    if stx_usd is None:
                        async with session.get("https://api.coinbase.com/v2/prices/STX-USD/spot") as resp:
                            if resp.status == 200:
                                data = await resp.json(content_type=None)
                                stx_usd = _to_dec((data.get("data") or {}).get("amount"))
                    if btc_usd is None:
                        async with session.get("https://api.coinbase.com/v2/prices/BTC-USD/spot") as resp:
                            if resp.status == 200:
                                data = await resp.json(content_type=None)
                                btc_usd = _to_dec((data.get("data") or {}).get("amount"))
            except Exception:
                pass

        return StacksPrices(
            btc_usd=btc_usd,
            stx_usd=stx_usd,
            sbtc_usd=btc_usd,
            stbtc_usd=btc_usd,
        )
