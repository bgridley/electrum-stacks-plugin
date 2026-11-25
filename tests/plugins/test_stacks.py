import hashlib
import importlib.util
import json
import os
import py_compile
import struct
import sys
import unittest
from pathlib import Path

# Load pure-Python submodules directly so tests can run in both Electrum and standalone plugin repo
_REPO_ROOT = Path(__file__).resolve().parents[2]
_PLUGIN_DIR = (
    _REPO_ROOT / "electrum" / "plugins" / "stacks"
    if (_REPO_ROOT / "electrum" / "plugins" / "stacks").is_dir()
    else _REPO_ROOT / "stacks"
)


def _load_submodule(name: str):
    full_name = f"_stacks_test_pkg.{name}"
    if "_stacks_test_pkg" not in sys.modules:
        import types
        pkg = types.ModuleType("_stacks_test_pkg")
        pkg.__path__ = [str(_PLUGIN_DIR)]
        sys.modules["_stacks_test_pkg"] = pkg
    if full_name in sys.modules:
        return sys.modules[full_name]
    spec = importlib.util.spec_from_file_location(full_name, _PLUGIN_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = mod
    spec.loader.exec_module(mod)
    return mod


c32 = _load_submodule("c32")
clarity = _load_submodule("clarity")
tx = _load_submodule("tx")


class TestStacksC32(unittest.TestCase):

    def test_known_real_addresses(self):
        # Official mainnet sBTC contract address (SM = version 20)
        ver, h160 = c32.c32_address_decode("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4")
        self.assertEqual(ver, c32.ADDR_VERSION_MAINNET_MULTI_SIG)
        self.assertEqual(len(h160), 20)
        self.assertEqual(
            c32.c32_address(ver, h160),
            "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4",
        )

        # Official testnet sBTC contract address (SN = version 21)
        ver, h160 = c32.c32_address_decode("SN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1")
        self.assertEqual(ver, c32.ADDR_VERSION_TESTNET_MULTI_SIG)
        self.assertEqual(len(h160), 20)
        self.assertEqual(
            c32.c32_address(ver, h160),
            "SN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1",
        )

        # Stacks mainnet burn address (20 zero bytes)
        ver, h160 = c32.c32_address_decode("SP000000000000000000002Q6VF78")
        self.assertEqual(ver, c32.ADDR_VERSION_MAINNET_SINGLE_SIG)
        self.assertEqual(h160, b"\x00" * 20)
        self.assertEqual(c32.c32_address(ver, h160), "SP000000000000000000002Q6VF78")

        # Standard testnet address (Clarinet default deployer)
        ver, h160 = c32.c32_address_decode("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM")
        self.assertEqual(ver, c32.ADDR_VERSION_TESTNET_SINGLE_SIG)
        self.assertEqual(len(h160), 20)
        self.assertEqual(
            c32.c32_address(ver, h160),
            "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
        )

    def test_validation_and_network_filtering(self):
        self.assertTrue(c32.is_valid_stacks_address("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4", testnet=False))
        self.assertFalse(c32.is_valid_stacks_address("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4", testnet=True))
        self.assertTrue(c32.is_valid_stacks_address("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM", testnet=True))
        self.assertFalse(c32.is_valid_stacks_address("ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM", testnet=False))
        # Corrupted checksum
        self.assertFalse(c32.is_valid_stacks_address("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ5"))
        # Wrong prefix
        self.assertFalse(c32.is_valid_stacks_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))

    def test_leading_zero_hash160_roundtrip(self):
        h160 = b"\x00\x00\x01" + bytes(range(17))
        addr = c32.c32_address(c32.ADDR_VERSION_MAINNET_SINGLE_SIG, h160)
        self.assertTrue(addr.startswith("SP00"))
        ver, decoded = c32.c32_address_decode(addr)
        self.assertEqual(ver, c32.ADDR_VERSION_MAINNET_SINGLE_SIG)
        self.assertEqual(decoded, h160)

    def test_parse_principal(self):
        ver, h160, cname = c32.parse_principal("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token")
        self.assertEqual(ver, 20)
        self.assertEqual(len(h160), 20)
        self.assertEqual(cname, "sbtc-token")

        ver2, h160_2, cname2 = c32.parse_principal("SP000000000000000000002Q6VF78")
        self.assertEqual(ver2, 22)
        self.assertEqual(h160_2, b"\x00" * 20)
        self.assertIsNone(cname2)


class TestStacksClarity(unittest.TestCase):

    def test_clarity_primitives(self):
        self.assertEqual(clarity.serialize_uint(100), b"\x01" + (100).to_bytes(16, "big"))
        self.assertEqual(clarity.serialize_bool(True), b"\x03")
        self.assertEqual(clarity.serialize_bool(False), b"\x04")
        self.assertEqual(clarity.serialize_none(), b"\x09")
        self.assertEqual(
            clarity.serialize_optional_buff(b"hi"),
            b"\x0a\x02\x00\x00\x00\x02hi",
        )
        self.assertEqual(clarity.serialize_optional_buff(None), b"\x09")
        self.assertEqual(clarity.serialize_optional_buff(b""), b"\x09")

    def test_clarity_principals(self):
        sp = clarity.serialize_principal("SP000000000000000000002Q6VF78")
        self.assertEqual(sp, bytes([0x05, 22]) + b"\x00" * 20)

        cp = clarity.serialize_principal("SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token")
        self.assertEqual(cp[0], 0x06)
        self.assertEqual(cp[1], 20)
        self.assertEqual(cp[22], len("sbtc-token"))
        self.assertEqual(cp[23:], b"sbtc-token")

    def test_fungible_post_condition(self):
        pc = clarity.FungiblePostCondition(
            principal_address="SP000000000000000000002Q6VF78",
            contract_address=tx.SBTC_MAINNET_CONTRACT_ADDRESS,
            contract_name="sbtc-token",
            asset_name="sbtc-token",
            condition_code=clarity.FUNGIBLE_COND_EQ,
            amount=50_000,
        )
        raw = pc.serialize()
        self.assertEqual(raw[0], clarity.PC_TYPE_FUNGIBLE)
        self.assertEqual(raw[1], clarity.PC_PRINCIPAL_STANDARD)
        self.assertEqual(raw[2], 22)
        self.assertEqual(raw[3:23], b"\x00" * 20)
        self.assertEqual(struct.unpack(">Q", raw[-8:])[0], 50_000)


class TestStacksTransaction(unittest.TestCase):

    def setUp(self):
        # Deterministic 33-byte dummy compressed pubkey for serialization tests
        self.dummy_pubkey = bytes.fromhex(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )

    def test_stx_transfer_serialization_and_sighash(self):
        t1 = tx.build_stx_transfer_tx(
            sender_pubkey=self.dummy_pubkey,
            recipient="SP000000000000000000002Q6VF78",
            amount_ustx=1_500_000,
            nonce=5,
            fee_ustx=2000,
            memo="electrum-test",
            testnet=False,
        )
        t2 = tx.build_stx_transfer_tx(
            sender_pubkey=self.dummy_pubkey,
            recipient="SP000000000000000000002Q6VF78",
            amount_ustx=1_500_000,
            nonce=99,
            fee_ustx=9999,
            memo="electrum-test",
            testnet=False,
        )
        raw = t1.serialize()
        self.assertEqual(raw[0], tx.TX_VERSION_MAINNET)
        self.assertEqual(struct.unpack(">I", raw[1:5])[0], tx.CHAIN_ID_MAINNET)
        self.assertEqual(raw[5], tx.AUTH_TYPE_STANDARD)
        self.assertEqual(len(t1.txid()), 64)

        # Initial sighash MUST be independent of nonce & fee
        self.assertEqual(t1.sighash_initial(), t2.sighash_initial())
        # Presign sighash MUST depend on nonce & fee
        self.assertNotEqual(t1.presign_sighash(), t2.presign_sighash())

    def test_sbtc_transfer_serialization(self):
        t = tx.build_sbtc_transfer_tx(
            sender_pubkey=self.dummy_pubkey,
            recipient="ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM",
            amount_sats=100_000,
            nonce=0,
            fee_ustx=10_000,
            memo="sbtc",
            testnet=True,
        )
        raw = t.serialize()
        self.assertEqual(raw[0], tx.TX_VERSION_TESTNET)
        self.assertEqual(struct.unpack(">I", raw[1:5])[0], tx.CHAIN_ID_TESTNET)
        self.assertEqual(t.post_condition_mode, tx.POST_CONDITION_MODE_DENY)
        self.assertEqual(len(t.post_conditions), 1)
        self.assertEqual(t.payload.contract_name, "sbtc-token")
        self.assertEqual(t.payload.function_name, "transfer")
        self.assertEqual(len(t.payload.function_args), 4)
        self.assertEqual(len(t.txid()), 64)

    def test_stbtc_transfer_serialization(self):
        t = tx.build_stbtc_transfer_tx(
            sender_pubkey=self.dummy_pubkey,
            recipient="SP000000000000000000002Q6VF78",
            amount_sats=250_000,
            nonce=2,
            fee_ustx=10_000,
            memo="stbtc",
            testnet=False,
        )
        raw = t.serialize()
        self.assertEqual(raw[0], tx.TX_VERSION_MAINNET)
        self.assertEqual(struct.unpack(">I", raw[1:5])[0], tx.CHAIN_ID_MAINNET)
        self.assertEqual(t.post_condition_mode, tx.POST_CONDITION_MODE_DENY)
        self.assertEqual(len(t.post_conditions), 1)
        self.assertEqual(t.payload.contract_address, tx.STBTC_MAINNET_CONTRACT_ADDRESS)
        self.assertEqual(t.payload.contract_name, "stbtc-token")
        self.assertEqual(t.payload.function_name, "transfer")
        self.assertEqual(t.post_conditions[0].asset_name, "stbtc")
        self.assertEqual(len(t.txid()), 64)

    def test_signing_if_ecc_available(self):
        try:
            import electrum_ecc as ecc
        except ImportError:
            self.skipTest("electrum_ecc not installed in this Python environment")

        priv = (1).to_bytes(32, "big")
        pub = ecc.ECPrivkey(priv).get_public_key_bytes(compressed=True)
        t = tx.build_stx_transfer_tx(
            sender_pubkey=pub,
            recipient="SP000000000000000000002Q6VF78",
            amount_ustx=1_000_000,
            nonce=1,
            fee_ustx=1800,
            testnet=False,
        )
        vrs = t.sign(priv)
        self.assertEqual(len(vrs), 65)
        self.assertIn(vrs[0], (0, 1, 2, 3))
        # Verify signature recovers to the exact same public key
        btc_sig65 = bytes([27 + vrs[0]]) + vrs[1:]
        recovered_pub, _, _ = ecc.ECPubkey.from_ecdsa_sig65(btc_sig65, t.presign_sighash())
        self.assertEqual(recovered_pub.get_public_key_bytes(compressed=True), pub)


class TestStacksManifestAndSyntax(unittest.TestCase):

    def test_manifest_json(self):
        with open(_PLUGIN_DIR / "manifest.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["name"], "stacks")
        self.assertIn("qt", data["available_for"])
        self.assertIn("cmdline", data["available_for"])
        self.assertTrue(data["fullname"])
        self.assertTrue(data["version"])

    def test_all_plugin_files_compile(self):
        for py_file in sorted(_PLUGIN_DIR.glob("*.py")):
            py_compile.compile(str(py_file), doraise=True)

    def test_import_multiple_watch_addresses(self):
        try:
            from electrum.plugins.stacks.stacks import StacksPlugin
        except ImportError:
            self.skipTest("Electrum runtime dependencies not installed in this Python environment")

        class _FakeDB:
            def __init__(self):
                self._data = {}
            def get(self, k, default=None):
                return self._data.get(k, default)
            def put(self, k, v):
                self._data[k] = v

        class _FakeWallet:
            def __init__(self):
                self.db = _FakeDB()
                self.saved = 0
            def save_db(self):
                self.saved += 1

        plugin = object.__new__(StacksPlugin)
        plugin.is_testnet = lambda: False  # mainnet
        wallet = _FakeWallet()

        bulk_input = (
            "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4,\n"
            "SP000000000000000000002Q6VF78 "
            "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4; "
            "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM not-an-address"
        )
        res = plugin.import_watch_addresses(wallet, bulk_input)
        self.assertEqual(
            res["added"],
            [
                "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4",
                "SP000000000000000000002Q6VF78",
            ],
        )
        self.assertEqual(res["duplicates"], ["SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4"])
        self.assertEqual(
            res["invalid"],
            ["ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM", "not-an-address"],
        )
        self.assertEqual(len(plugin.get_watch_addresses(wallet)), 2)
        self.assertEqual(wallet.saved, 1)

    def test_no_v1_endpoints_in_plugin(self):
        for py_file in sorted(_PLUGIN_DIR.glob("*.py")):
            content = py_file.read_text(encoding="utf-8")
            self.assertNotIn("/extended/v1", content, f"Found v1 endpoint in {py_file.name}")

    def test_v3_balances_parsing(self):
        try:
            from electrum.plugins.stacks.api import parse_v3_balances_response
        except ImportError:
            self.skipTest("Electrum runtime dependencies not installed in this Python environment")

        addr = "SP000000000000000000002Q6VF78"
        sbtc_id = f"{tx.SBTC_MAINNET_CONTRACT_ADDRESS}.sbtc-token::sbtc-token"
        stbtc_id = f"{tx.STBTC_MAINNET_CONTRACT_ADDRESS}.stbtc-token::stbtc"
        stx_resp = {"balance": "5000000", "available": "4000000", "locked": {"amount": "1000000", "unlock_height": 900000}}
        ft_resp = {
            "results": [
                {"asset_identifier": sbtc_id, "balance": "75000"},
                {"asset_identifier": stbtc_id, "balance": "25000"},
            ]
        }
        bal = parse_v3_balances_response(addr, stx_resp, ft_resp, sbtc_id, stbtc_id)
        self.assertEqual(bal.stx_balance_ustx, 5_000_000)
        self.assertEqual(bal.stx_locked_ustx, 1_000_000)
        self.assertEqual(bal.stx_available_ustx, 4_000_000)
        self.assertEqual(bal.sbtc_balance_sats, 75_000)
        self.assertEqual(bal.stbtc_balance_sats, 25_000)

    def test_running_balances_stx_and_sbtc(self):
        try:
            from electrum.plugins.stacks.api import (
                parse_v3_transactions_response,
                compute_running_balances,
            )
        except ImportError:
            self.skipTest("Electrum runtime dependencies not installed in this Python environment")

        addr = "SP000000000000000000002Q6VF78"
        sbtc_id = f"{tx.SBTC_MAINNET_CONTRACT_ADDRESS}.sbtc-token::sbtc-token"
        stbtc_id = f"{tx.STBTC_MAINNET_CONTRACT_ADDRESS}.stbtc-token::stbtc"
        # Exact Hiro v3 /extended/v3/principals/{principal}/transactions schema (newest first)
        tx_payload = {
            "results": [
                {
                    "transaction": {
                        "tx_id": "0xpending",
                        "type": "token_transfer",
                        "status": "pending",
                        "sender": {"address": addr, "nonce": 3},
                        "fee_rate": "2000",
                        "block": None,
                        "token_transfer": {"recipient": "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4", "amount": "500000"},
                    },
                    "balance_changes": {"stx": {"sent": "502000", "received": "0", "net": "-502000"}},
                    "affected_balances": {"stx": True, "ft": False, "nft": False},
                },
                {
                    "transaction": {
                        "tx_id": "0xsend_sbtc",
                        "type": "contract_call",
                        "status": "success",
                        "sender": {"address": addr, "nonce": 2},
                        "fee_rate": "10000",
                        "block": {"height": 200, "time": 1735776000, "time_iso": "2025-01-02T00:00:00.000Z"},
                        "contract_call": {"contract_id": f"{tx.SBTC_MAINNET_CONTRACT_ADDRESS}.sbtc-token", "function_name": "transfer"},
                    },
                    "balance_changes": {"stx": {"sent": "10000", "received": "0", "net": "-10000"}},
                    "affected_balances": {"stx": True, "ft": True, "nft": False},
                },
                {
                    "transaction": {
                        "tx_id": "0xrecv_sbtc",
                        "type": "contract_call",
                        "status": "success",
                        "sender": {"address": "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4", "nonce": 1},
                        "fee_rate": "10000",
                        "block": {"height": 150, "time": 1735689600, "time_iso": "2025-01-01T00:00:00.000Z"},
                        "contract_call": {"contract_id": f"{tx.SBTC_MAINNET_CONTRACT_ADDRESS}.sbtc-token", "function_name": "transfer"},
                    },
                    "balance_changes": {"stx": {"sent": "0", "received": "0", "net": "0"}},
                    "affected_balances": {"stx": False, "ft": True, "nft": False},
                },
                {
                    "transaction": {
                        "tx_id": "0xrecv_stx",
                        "type": "token_transfer",
                        "status": "success",
                        "sender": {"address": "SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4", "nonce": 0},
                        "fee_rate": "2000",
                        "block": {"height": 100, "time": 1735603200, "time_iso": "2024-12-31T00:00:00.000Z"},
                        "token_transfer": {"recipient": addr, "amount": "11000000"},
                    },
                    "balance_changes": {"stx": {"sent": "0", "received": "11000000", "net": "11000000"}},
                    "affected_balances": {"stx": True, "ft": False, "nft": False},
                },
            ]
        }
        # Exact Hiro v3 /extended/v3/principals/{principal}/balance-changes?tx_id=...
        ft_bc_by_tx = {
            "0xsend_sbtc": {
                "results": [
                    {"tx_id": "0xsend_sbtc", "asset": {"type": "stx"}, "balance_change": {"sent": "10000", "received": "0", "net": "-10000"}},
                    {"tx_id": "0xsend_sbtc", "asset": {"type": "ft", "identifier": sbtc_id}, "balance_change": {"sent": "25000", "received": "0", "net": "-25000"}},
                    {"tx_id": "0xsend_sbtc", "asset": {"type": "ft", "identifier": stbtc_id}, "balance_change": {"sent": "0", "received": "25000", "net": "25000"}},
                ]
            },
            "0xrecv_sbtc": {
                "results": [
                    {"tx_id": "0xrecv_sbtc", "asset": {"type": "ft", "identifier": sbtc_id}, "balance_change": {"sent": "0", "received": "100000", "net": "100000"}},
                ]
            },
        }

        parsed = parse_v3_transactions_response(addr, tx_payload, ft_bc_by_tx, sbtc_id, stbtc_id)
        rows = compute_running_balances(
            parsed,
            current_stx_ustx=10_990_000,
            current_sbtc_sats=75_000,
            current_stbtc_sats=25_000,
        )

        # Row 0: pending
        self.assertIsNone(rows[0]["running_stx_ustx"])
        self.assertIsNone(rows[0]["running_sbtc_sats"])
        self.assertIsNone(rows[0]["running_stbtc_sats"])
        # Row 1: after sending 25k sats sBTC, receiving 25k sats stBTC & paying 10k uSTX fee
        self.assertEqual(rows[1]["running_stx_ustx"], 10_990_000)
        self.assertEqual(rows[1]["running_sbtc_sats"], 75_000)
        self.assertEqual(rows[1]["running_stbtc_sats"], 25_000)
        self.assertIn("-0.00025000 sBTC", rows[1]["amount_display"])
        self.assertIn("+0.00025000 stBTC", rows[1]["amount_display"])
        self.assertIn("-0.010000 STX", rows[1]["amount_display"])
        # Row 2: after receiving 100k sats sBTC
        self.assertEqual(rows[2]["running_stx_ustx"], 11_000_000)
        self.assertEqual(rows[2]["running_sbtc_sats"], 100_000)
        self.assertEqual(rows[2]["running_stbtc_sats"], 0)
        # Row 3: after receiving 11 STX
        self.assertEqual(rows[3]["running_stx_ustx"], 11_000_000)
        self.assertEqual(rows[3]["running_sbtc_sats"], 0)
        self.assertEqual(rows[3]["running_stbtc_sats"], 0)

    def test_merge_multi_address_transactions(self):
        try:
            from electrum.plugins.stacks.api import (
                merge_multi_address_transactions,
                compute_running_balances,
            )
        except ImportError:
            self.skipTest("Electrum runtime dependencies not installed in this Python environment")

        # Internal transfer of 5 STX (2,000 uSTX fee) from addr_a to addr_b at block 200,
        # after addr_a received 10 STX at block 100.
        # Combined wallet balance: 9,998,000 uSTX (only the 2,000 uSTX fee left the wallet).
        per_addr = {
            "SP_A": [
                {
                    "tx_id": "0xinternal",
                    "tx_status": "success",
                    "block_height": 200,
                    "burn_block_time_iso": "2026-01-02T00:00:00Z",
                    "nonce": 1,
                    "stx_delta_ustx": -5_002_000,
                    "sbtc_delta_sats": 0,
                    "stbtc_delta_sats": 0,
                },
                {
                    "tx_id": "0xdeposit",
                    "tx_status": "success",
                    "block_height": 100,
                    "burn_block_time_iso": "2026-01-01T00:00:00Z",
                    "nonce": 0,
                    "stx_delta_ustx": 10_000_000,
                    "sbtc_delta_sats": 0,
                    "stbtc_delta_sats": 0,
                },
            ],
            "SP_B": [
                {
                    "tx_id": "0xinternal",
                    "tx_status": "success",
                    "block_height": 200,
                    "burn_block_time_iso": "2026-01-02T00:00:00Z",
                    "nonce": 1,
                    "stx_delta_ustx": 5_000_000,
                    "sbtc_delta_sats": 0,
                    "stbtc_delta_sats": 0,
                },
            ],
        }

        merged = merge_multi_address_transactions(per_addr)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["tx_id"], "0xinternal")
        self.assertEqual(merged[0]["stx_delta_ustx"], -2_000)

        rows = compute_running_balances(merged, current_stx_ustx=9_998_000, current_sbtc_sats=0, current_stbtc_sats=0)
        self.assertEqual(rows[0]["running_stx_ustx"], 9_998_000)
        self.assertEqual(rows[1]["running_stx_ustx"], 10_000_000)

    def test_calculate_portfolio_usd(self):
        try:
            from decimal import Decimal
            from electrum.plugins.stacks.api import StacksPrices, calculate_portfolio_usd
        except ImportError:
            self.skipTest("Electrum runtime dependencies not installed in this Python environment")

        prices = StacksPrices(
            btc_usd=Decimal("60000"),
            stx_usd=Decimal("1.50"),
        )
        # 2 BTC ($120,000) + 1000 STX ($1,500) + 0.5 sBTC ($30,000) + 0.25 stBTC ($15,000) = $166,500
        res = calculate_portfolio_usd(
            btc_sats=200_000_000,
            stx_ustx=1_000_000_000,
            sbtc_sats=50_000_000,
            stbtc_sats=25_000_000,
            prices=prices,
        )
        self.assertEqual(res["btc_usd"], Decimal("120000"))
        self.assertEqual(res["stx_usd"], Decimal("1500"))
        self.assertEqual(res["sbtc_usd"], Decimal("30000"))
        self.assertEqual(res["stbtc_usd"], Decimal("15000"))
        self.assertEqual(res["stacks_total_usd"], Decimal("46500"))
        self.assertEqual(res["grand_total_usd"], Decimal("166500"))


if __name__ == "__main__":
    unittest.main()
