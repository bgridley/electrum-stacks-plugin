# Electrum Stacks Plugin (STX, sBTC & stBTC)

An external Electrum 4.6+ plugin that adds **Stacks (STX)**, **sBTC**, and **stBTC** (Stacking DAO) support to the Electrum desktop wallet and CLI—with zero modifications to core Electrum and zero extra Python dependencies.

## Features

* **BIP44 Stacks Key Derivation (`m/44'/5757'/0'/0/<index>`)** from Electrum BIP39 seeds, native Electrum seeds, or master `xprv` keys—plus bulk import of **watch-only** Stacks addresses (`SP...`/`SM...` mainnet, `ST...`/`SN...` testnet).
* **Main-Window Tabs**:
  * **STX Addresses** — Lists derived and imported watch-only addresses with live STX, sBTC, and stBTC balances, account switching, and bulk address import.
  * **STX History** — Displays per-address or combined **All Addresses** history with signed STX/sBTC/stBTC deltas and running token balances.
* **Bottom Portfolio Status Bar** — Shows aggregated STX, sBTC, and stBTC balances with live USD spot pricing and a combined **Total USD** portfolio value (BTC + STX + sBTC + stBTC).
* **Local SIP-005 Signing & Broadcasting**:
  * Native **STX** token transfers
  * **sBTC** (`SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token`) SIP-010 transfers with `FungiblePostCondition` (`SentEq`) + `PostConditionMode.Deny`
  * **stBTC** (`SP4SZE494VC2YC5JYG7AYFQ44F5Q4PYV7DVMDPBG.stbtc-token`) SIP-010 transfers with `FungiblePostCondition` (`SentEq`) + `PostConditionMode.Deny`
* **Stacks Blockchain API v3** — Uses Hiro's `/extended/v3/principals/...` endpoints exclusively (configurable custom API URL & token contracts in Settings).
* **CLI Support** — Adds `stacks_get_address`, `stacks_list_addresses`, `stacks_set_watch_address`, `stacks_import_watch_addresses`, `stacks_get_balance`, `stacks_get_history`, `stacks_send_stx`, `stacks_send_sbtc`, and `stacks_send_stbtc`.

## Installation (Stock Electrum 4.6+)

### Option 1: Install via Electrum UI (Recommended)
1. Download `electrum-stacks-plugin-0.1.0.zip` and `electrum-stacks-plugin-0.1.0.zip.sha256` from the [Releases](https://github.com/bgridley/electrum-stacks-plugin/releases) page.
2. Verify the SHA-256 checksum:
   ```bash
   shasum -a 256 -c electrum-stacks-plugin-0.1.0.zip.sha256
   ```
3. In Electrum, open **Tools → Plugins → Add Plugin**, select `electrum-stacks-plugin-0.1.0.zip`, and enable **Stacks (STX, sBTC & stBTC)**.

### Option 2: Manual Installation
Copy `electrum-stacks-plugin-0.1.0.zip` into your Electrum plugins directory:
* **macOS / Linux:** `~/.electrum/plugins/`
* **Windows:** `%APPDATA%\Electrum\plugins\`

Restart Electrum and enable **Stacks (STX, sBTC & stBTC)** under **Tools → Plugins**.

## Building the Plugin `.zip` from Source

```bash
zip -r electrum-stacks-plugin-0.1.0.zip stacks -x "stacks/__pycache__/*" "*.pyc"
shasum -a 256 electrum-stacks-plugin-0.1.0.zip > electrum-stacks-plugin-0.1.0.zip.sha256
```

## Running Tests

```bash
python3 tests/plugins/test_stacks.py -v
```

*(Run with an Electrum virtualenv Python to also execute the `electrum_ecc` signing/recovery and API parsing tests.)*

## License

MIT — see [LICENCE](LICENCE).
