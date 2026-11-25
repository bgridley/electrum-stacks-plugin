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

import asyncio
from decimal import Decimal
from functools import partial
from typing import Any, Callable, Coroutine, Dict, List, Optional, Tuple, TYPE_CHECKING

from PyQt6.QtCore import QObject, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QStatusBar,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from electrum.gui.qt.util import Buttons, CancelButton, CloseButton, OkButton, WindowModalDialog, read_QIcon
from electrum.i18n import _
from electrum.plugin import hook
from electrum.util import UserFacingException

from .api import (
    StacksBalances,
    StacksPrices,
    calculate_portfolio_usd,
    compute_running_balances,
    merge_multi_address_transactions,
)
from .c32 import is_valid_stacks_address
from .stacks import (
    StacksPlugin,
    format_sbtc,
    format_stbtc,
    format_stx,
    parse_sbtc_to_sats,
    parse_stbtc_to_sats,
    parse_stx_to_ustx,
)

if TYPE_CHECKING:
    from electrum.gui.qt.main_window import ElectrumWindow
    from electrum.wallet import Abstract_Wallet


class _AsyncResultSignal(QObject):
    finished = pyqtSignal(object)
    failed = pyqtSignal(str)


class _StacksQtMixin:
    """Shared async execution & password helpers for Stacks Qt tabs and dialogs."""

    window: "ElectrumWindow"
    wallet: "Abstract_Wallet"
    plugin: StacksPlugin
    _active_signals: List[_AsyncResultSignal]

    def _run_coro(
        self,
        coro: Coroutine[Any, Any, Any],
        on_success: Callable[[Any], None],
        on_error: Optional[Callable[[str], None]] = None,
    ) -> None:
        sig = _AsyncResultSignal(self)  # type: ignore[arg-type]
        self._active_signals.append(sig)

        def _cleanup():
            if sig in self._active_signals:
                self._active_signals.remove(sig)

        sig.finished.connect(lambda res: (_cleanup(), on_success(res)))
        sig.failed.connect(lambda err: (_cleanup(), (on_error or self._show_err)(err)))

        network = self.window.network
        if network is None or getattr(network, "asyncio_loop", None) is None:
            sig.failed.emit(_("Electrum is offline. Connect to the network to query Stacks."))
            return

        fut = asyncio.run_coroutine_threadsafe(coro, network.asyncio_loop)

        def _done_cb(f):
            try:
                res = f.result()
            except Exception as e:
                sig.failed.emit(str(e))
            else:
                sig.finished.emit(res)

        fut.add_done_callback(_done_cb)

    def _show_err(self, msg: str) -> None:
        self.window.show_error(msg, parent=self)  # type: ignore[arg-type]

    def _request_wallet_password(self, msg: str) -> Optional[str]:
        """Prompt for wallet password if the wallet is encrypted. Returns None on cancel (when encrypted)."""
        if not self.wallet.has_password():
            return None
        pw = self.wallet.get_unlocked_password()
        if pw is not None:
            return pw
        while True:
            pw = self.window.password_dialog(parent=self, msg=msg)  # type: ignore[arg-type]
            if pw is None:
                return None
            try:
                self.wallet.check_password(pw)
                return pw
            except Exception as e:
                self.window.show_error(str(e), parent=self)  # type: ignore[arg-type]


# ======================================================================
# Main Window Tab 1: STX History
# ======================================================================

class StacksHistoryTab(_StacksQtMixin, QWidget):
    """Main-window tab displaying Stacks (STX) & sBTC transaction history."""

    def __init__(self, plugin: "Plugin", window: "ElectrumWindow"):
        super().__init__(window)
        self.plugin = plugin
        self.window = window
        self.wallet = window.wallet
        self._active_signals = []

        layout = QVBoxLayout(self)

        # Top toolbar: address selector + balances + actions
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel(_("STX Address ({}):").format(self.plugin.get_network_name())))

        self.addr_combo = QComboBox()
        self.addr_combo.setMinimumWidth(320)
        self.addr_combo.currentIndexChanged.connect(self._on_address_selected)
        top_row.addWidget(self.addr_combo, stretch=1)

        self.refresh_btn = QPushButton(_("Refresh"))
        self.refresh_btn.clicked.connect(self.refresh_network_data)
        top_row.addWidget(self.refresh_btn)

        self.send_btn = QPushButton(_("Send STX / sBTC..."))
        self.send_btn.clicked.connect(lambda: self.plugin.open_stacks_dialog(self.window, initial_tab=1))
        top_row.addWidget(self.send_btn)

        layout.addLayout(top_row)

        # Balance summary bar
        bal_row = QHBoxLayout()
        self.stx_balance_label = QLabel(_("STX: —"))
        self.sbtc_balance_label = QLabel(_("sBTC: —"))
        self.stbtc_balance_label = QLabel(_("stBTC: —"))
        self.status_label = QLabel("")
        bal_row.addWidget(self.stx_balance_label)
        bal_row.addSpacing(16)
        bal_row.addWidget(self.sbtc_balance_label)
        bal_row.addSpacing(16)
        bal_row.addWidget(self.stbtc_balance_label)
        bal_row.addSpacing(16)
        bal_row.addWidget(self.status_label, stretch=1)
        layout.addLayout(bal_row)

        # Transaction history tree
        self.tx_tree = QTreeWidget()
        self.tx_tree.setHeaderLabels([
            _("Date"),
            _("Description"),
            _("Amount"),
            _("STX Balance"),
            _("sBTC Balance"),
            _("stBTC Balance"),
            _("Status"),
            _("Fee (uSTX)"),
            _("TxID"),
        ])
        self.tx_tree.setRootIsDecorated(False)
        self.tx_tree.setAlternatingRowColors(True)
        self.tx_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tx_tree.customContextMenuRequested.connect(self._on_context_menu)
        self.tx_tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.tx_tree, stretch=1)

        self.reload_addresses()

    ALL_ADDRESSES_KEY = "__ALL__"

    def reload_addresses(self) -> None:
        current = self.addr_combo.currentData()
        self.addr_combo.blockSignals(True)
        self.addr_combo.clear()

        entries = self.plugin.get_all_stacks_addresses(self.wallet)
        selected_idx = 0
        if entries:
            self.addr_combo.addItem(_("All Addresses ({})").format(len(entries)), self.ALL_ADDRESSES_KEY)
            if current == self.ALL_ADDRESSES_KEY:
                selected_idx = 0
            elif not current and len(entries) > 1:
                selected_idx = 0
            for i, entry in enumerate(entries, start=1):
                addr = entry["address"]
                label = f"{addr}  ({entry['path']})"
                if entry["is_active"]:
                    label += " ★"
                self.addr_combo.addItem(label, addr)
                if current and addr == current:
                    selected_idx = i
                elif not current and len(entries) == 1 and entry["is_active"]:
                    selected_idx = i

            self.addr_combo.setCurrentIndex(selected_idx)
            self.refresh_btn.setEnabled(True)
        else:
            self.addr_combo.addItem(_("No STX address — open STX Addresses tab to derive or add watch-only"), "")
            self.refresh_btn.setEnabled(False)
            self.tx_tree.clear()
            self.stx_balance_label.setText(_("STX: —"))
            self.sbtc_balance_label.setText(_("sBTC: —"))
            self.stbtc_balance_label.setText(_("stBTC: —"))

        self.addr_combo.blockSignals(False)

    def _selected_address(self) -> str:
        return self.addr_combo.currentData() or ""

    def _on_address_selected(self) -> None:
        if self._selected_address():
            self.refresh_network_data()

    def refresh_network_data(self) -> None:
        selection = self._selected_address()
        if not selection:
            return
        self.refresh_btn.setEnabled(False)

        if selection == self.ALL_ADDRESSES_KEY:
            entries = self.plugin.get_all_stacks_addresses(self.wallet)
            addresses = [e["address"] for e in entries]
            if not addresses:
                self.refresh_btn.setEnabled(False)
                return
            self.status_label.setText(_("Loading STX / sBTC / stBTC history for {} address(es)...").format(len(addresses)))

            async def _fetch():
                total_stx = 0
                total_locked = 0
                total_sbtc = 0
                total_stbtc = 0
                per_addr_txs: Dict[str, List[dict]] = {}
                for addr in addresses:
                    b = await self.plugin.fetch_balances(addr)
                    total_stx += b.stx_balance_ustx
                    total_locked += b.stx_locked_ustx
                    total_sbtc += b.sbtc_balance_sats
                    total_stbtc += b.stbtc_balance_sats
                    per_addr_txs[addr] = await self.plugin.fetch_transactions(addr, limit=50)
                combined_bal = StacksBalances(
                    address="all",
                    stx_balance_ustx=total_stx,
                    stx_locked_ustx=total_locked,
                    sbtc_balance_sats=total_sbtc,
                    sbtc_contract_id=self.plugin.get_sbtc_asset_identifier(),
                    stbtc_balance_sats=total_stbtc,
                    stbtc_contract_id=self.plugin.get_stbtc_asset_identifier(),
                )
                merged_txs = merge_multi_address_transactions(per_addr_txs)
                return combined_bal, merged_txs
        else:
            addr = selection
            self.status_label.setText(_("Loading STX / sBTC / stBTC history..."))

            async def _fetch():
                bal = await self.plugin.fetch_balances(addr)
                txs = await self.plugin.fetch_transactions(addr, limit=50)
                return bal, txs

        def _on_done(res):
            bal, txs = res
            self.refresh_btn.setEnabled(True)
            stx_text = _("STX: {}").format(format_stx(bal.stx_balance_ustx))
            if bal.stx_locked_ustx > 0:
                stx_text += _(" (locked: {})").format(format_stx(bal.stx_locked_ustx))
            self.stx_balance_label.setText(stx_text)
            self.sbtc_balance_label.setText(
                _("sBTC: {} ({:,} sats)").format(format_sbtc(bal.sbtc_balance_sats), bal.sbtc_balance_sats)
            )
            self.stbtc_balance_label.setText(
                _("stBTC: {} ({:,} sats)").format(format_stbtc(bal.stbtc_balance_sats), bal.stbtc_balance_sats)
            )
            txs_with_running = compute_running_balances(
                txs,
                current_stx_ustx=bal.stx_balance_ustx,
                current_sbtc_sats=bal.sbtc_balance_sats,
                current_stbtc_sats=bal.stbtc_balance_sats,
            )
            self._populate_tree(txs_with_running)
            self.status_label.setText(_("{} transactions").format(len(txs_with_running)))

        def _on_err(err_msg: str):
            self.refresh_btn.setEnabled(True)
            self.status_label.setText(_("Error: {}").format(err_msg))

        self._run_coro(_fetch(), _on_done, _on_err)

    def _populate_tree(self, txs: List[dict]) -> None:
        self.tx_tree.clear()
        for tx in txs:
            iso_time = (tx.get("burn_block_time_iso") or "")[:19].replace("T", " ")
            run_stx = tx.get("running_stx_ustx")
            run_sbtc = tx.get("running_sbtc_sats")
            run_stbtc = tx.get("running_stbtc_sats")
            stx_bal_str = format_stx(run_stx) if run_stx is not None else _("Pending")
            sbtc_bal_str = format_sbtc(run_sbtc) if run_sbtc is not None else _("Pending")
            stbtc_bal_str = format_stbtc(run_stbtc) if run_stbtc is not None else _("Pending")
            item = QTreeWidgetItem([
                iso_time or _("Pending"),
                tx.get("summary", ""),
                tx.get("amount_display", ""),
                stx_bal_str,
                sbtc_bal_str,
                stbtc_bal_str,
                tx.get("tx_status", ""),
                str(tx.get("fee_rate_ustx", "")),
                tx.get("tx_id", ""),
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, tx)
            self.tx_tree.addTopLevelItem(item)
        for col in range(8):
            self.tx_tree.resizeColumnToContents(col)

    def _on_item_double_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        txid = item.text(8)
        if txid:
            QApplication.clipboard().setText(txid)
            self.status_label.setText(_("Copied TxID: {}...").format(txid[:18]))

    def _on_context_menu(self, pos) -> None:
        item = self.tx_tree.itemAt(pos)
        if not item:
            return
        tx = item.data(0, Qt.ItemDataRole.UserRole) or {}
        txid = tx.get("tx_id", "")
        sender = tx.get("sender_address", "")

        menu = QMenu(self)
        if txid:
            menu.addAction(_("Copy TxID"), lambda: QApplication.clipboard().setText(txid))
            chain = "testnet" if self.plugin.is_testnet() else "mainnet"
            explorer_url = f"https://explorer.hiro.so/txid/{txid}?chain={chain}"
            menu.addAction(
                _("View in Hiro Explorer"),
                lambda: QDesktopServices.openUrl(QUrl(explorer_url)),
            )
        if sender:
            menu.addAction(_("Copy Sender Address"), lambda: QApplication.clipboard().setText(sender))
        menu.exec(self.tx_tree.viewport().mapToGlobal(pos))


# ======================================================================
# Main Window Tab 2: STX Addresses
# ======================================================================

class StacksAddressesTab(_StacksQtMixin, QWidget):
    """Main-window tab listing derived & watch-only Stacks (STX / sBTC) addresses."""

    def __init__(self, plugin: "Plugin", window: "ElectrumWindow"):
        super().__init__(window)
        self.plugin = plugin
        self.window = window
        self.wallet = window.wallet
        self._active_signals = []
        self._balances_cache: Dict[str, StacksBalances] = {}

        layout = QVBoxLayout(self)

        # Toolbar
        top_row = QHBoxLayout()
        top_row.addWidget(QLabel(_("Stacks Network: {}").format(self.plugin.get_network_name())))

        self.derive_btn = QPushButton(_("Derive Next Address"))
        self.derive_btn.setEnabled(self.plugin.can_derive_signing_key(self.wallet))
        self.derive_btn.clicked.connect(self._on_derive_next)
        top_row.addWidget(self.derive_btn)

        self.watch_btn = QPushButton(_("Import Addresses..."))
        self.watch_btn.clicked.connect(self._on_add_watch_only)
        top_row.addWidget(self.watch_btn)

        self.refresh_btn = QPushButton(_("Refresh Balances"))
        self.refresh_btn.clicked.connect(self.refresh_balances)
        top_row.addWidget(self.refresh_btn)

        self.send_btn = QPushButton(_("Send STX / sBTC..."))
        self.send_btn.clicked.connect(lambda: self.plugin.open_stacks_dialog(self.window, initial_tab=1))
        top_row.addWidget(self.send_btn)

        top_row.addStretch(1)
        layout.addLayout(top_row)

        self.status_label = QLabel("")
        layout.addWidget(self.status_label)

        # Addresses tree
        self.addr_tree = QTreeWidget()
        self.addr_tree.setHeaderLabels([
            _("Derivation / Type"),
            _("STX Address"),
            _("STX Balance"),
            _("sBTC Balance"),
            _("stBTC Balance"),
            _("Status"),
        ])
        self.addr_tree.setRootIsDecorated(False)
        self.addr_tree.setAlternatingRowColors(True)
        self.addr_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.addr_tree.customContextMenuRequested.connect(self._on_context_menu)
        self.addr_tree.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.addr_tree, stretch=1)

        self.reload_addresses()

    def reload_addresses(self) -> None:
        self.addr_tree.clear()
        entries = self.plugin.get_all_stacks_addresses(self.wallet)
        for entry in entries:
            addr = entry["address"]
            bal = self._balances_cache.get(addr)
            stx_str = format_stx(bal.stx_balance_ustx) if bal else "—"
            sbtc_str = format_sbtc(bal.sbtc_balance_sats) if bal else "—"
            stbtc_str = format_stbtc(bal.stbtc_balance_sats) if bal else "—"
            status_str = _("★ Active") if entry["is_active"] else ""
            item = QTreeWidgetItem([
                entry["path"],
                addr,
                stx_str,
                sbtc_str,
                stbtc_str,
                status_str,
            ])
            item.setData(0, Qt.ItemDataRole.UserRole, entry)
            self.addr_tree.addTopLevelItem(item)

        for col in range(5):
            self.addr_tree.resizeColumnToContents(col)

        if not entries:
            if self.plugin.can_derive_signing_key(self.wallet):
                self.status_label.setText(
                    _("Click 'Derive Next Address' to unlock and derive your first Stacks address (m/44'/5757'/0'/0/0).")
                )
            else:
                self.status_label.setText(
                    _("Watch-only wallet: click 'Add Watch-Only...' to monitor a Stacks address.")
                )
        else:
            self.status_label.setText(_("{} address(es)").format(len(entries)))

    def refresh_balances(self) -> None:
        entries = self.plugin.get_all_stacks_addresses(self.wallet)
        if not entries:
            return
        self.refresh_btn.setEnabled(False)
        self.status_label.setText(_("Refreshing STX & sBTC balances..."))

        addresses = [e["address"] for e in entries]

        async def _fetch_all():
            results: Dict[str, StacksBalances] = {}
            for addr in addresses:
                results[addr] = await self.plugin.fetch_balances(addr)
            return results

        def _on_done(results: Dict[str, StacksBalances]):
            self.refresh_btn.setEnabled(True)
            self._balances_cache.update(results)
            self.reload_addresses()
            self.status_label.setText(_("Balances updated for {} address(es).").format(len(results)))

        def _on_err(err_msg: str):
            self.refresh_btn.setEnabled(True)
            self.status_label.setText(_("Error: {}").format(err_msg))

        self._run_coro(_fetch_all(), _on_done, _on_err)

    def _on_derive_next(self) -> None:
        pw = self._request_wallet_password(_("Enter your wallet password to derive a Stacks address:"))
        if self.wallet.has_password() and pw is None:
            return
        try:
            idx, addr = self.plugin.derive_next_stacks_address(self.wallet, pw)
        except Exception as e:
            self._show_err(str(e))
            return
        self.plugin.notify_tabs_changed(self.window)
        self.status_label.setText(_("Derived m/44'/5757'/0'/0/{}: {}").format(idx, addr))
        self.refresh_balances()

    def _on_add_watch_only(self) -> None:
        prefix = "ST.../SN..." if self.plugin.is_testnet() else "SP.../SM..."
        dialog = WindowModalDialog(self, _("Import Watch-Only Stacks Addresses"))
        dialog.setMinimumWidth(520)
        dialog.setMinimumHeight(280)
        vbox = QVBoxLayout(dialog)
        vbox.addWidget(QLabel(
            _("Paste one or more Stacks addresses ({}) to monitor — one per line, or separated by commas/spaces:")
            .format(prefix)
        ))
        text_edit = QPlainTextEdit()
        text_edit.setPlaceholderText(
            "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM\nSN3VMHXEN64ZZF71JQ5VESXDWTR301XTTXGF4J8F1"
            if self.plugin.is_testnet()
            else "SP...\nSM..."
        )
        vbox.addWidget(text_edit, stretch=1)
        vbox.addLayout(Buttons(CancelButton(dialog), OkButton(dialog, _("Import"))))

        if not dialog.exec():
            return

        raw_text = text_edit.toPlainText().strip()
        if not raw_text:
            return

        result = self.plugin.import_watch_addresses(self.wallet, raw_text)
        added = result["added"]
        duplicates = result["duplicates"]
        invalid = result["invalid"]

        if added:
            self.plugin.notify_tabs_changed(self.window)
            self.refresh_balances()

        parts = []
        if added:
            parts.append(_("Imported {} address(es).").format(len(added)))
        if duplicates:
            parts.append(_("Skipped {} duplicate(s).").format(len(duplicates)))
        if invalid:
            parts.append(
                _("Ignored {} invalid address(es) for {}: {}").format(
                    len(invalid),
                    self.plugin.get_network_name(),
                    ", ".join(invalid[:5]) + ("..." if len(invalid) > 5 else ""),
                )
            )
        summary = " ".join(parts) or _("No addresses imported.")
        self.status_label.setText(summary)
        if invalid and not added:
            self._show_err(summary)

    def _on_item_double_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        addr = item.text(1)
        if addr:
            QApplication.clipboard().setText(addr)
            self.status_label.setText(_("Copied address: {}").format(addr))

    def _on_context_menu(self, pos) -> None:
        item = self.addr_tree.itemAt(pos)
        if not item:
            return
        entry = item.data(0, Qt.ItemDataRole.UserRole) or {}
        addr = entry.get("address", "")
        entry_type = entry.get("type")
        acct_idx = entry.get("account_index")

        menu = QMenu(self)
        menu.addAction(_("Copy Address"), lambda: QApplication.clipboard().setText(addr))

        if entry_type == "derived" and acct_idx is not None and not entry.get("is_active"):
            def _set_active():
                self.plugin.set_account_index(self.wallet, acct_idx)
                self.plugin.notify_tabs_changed(self.window)
            menu.addAction(_("Set as Active Sending Account"), _set_active)

        chain = "testnet" if self.plugin.is_testnet() else "mainnet"
        explorer_url = f"https://explorer.hiro.so/address/{addr}?chain={chain}"
        menu.addAction(
            _("View in Hiro Explorer"),
            lambda: QDesktopServices.openUrl(QUrl(explorer_url)),
        )

        if entry_type == "watch":
            def _remove_watch():
                self.plugin.remove_watch_address(self.wallet, addr)
                self._balances_cache.pop(addr, None)
                self.plugin.notify_tabs_changed(self.window)
            menu.addAction(_("Remove Watch-Only Address"), _remove_watch)

        menu.exec(self.addr_tree.viewport().mapToGlobal(pos))


# ======================================================================
# Modal Dialog (Send / Overview / Settings)
# ======================================================================

class StacksDialog(_StacksQtMixin, WindowModalDialog):
    """Dialog for Stacks (STX) and sBTC sending, overview, and settings in Electrum Qt."""

    def __init__(self, plugin: "Plugin", window: "ElectrumWindow", initial_tab: int = 0):
        super().__init__(window, _("Stacks (STX & sBTC) — {}").format(plugin.get_network_name()))
        self.plugin = plugin
        self.window = window
        self.wallet = window.wallet
        self._active_signals = []

        self.setMinimumWidth(680)
        self.setMinimumHeight(480)

        root_layout = QVBoxLayout(self)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_overview_tab(), _("Overview & History"))
        self.tabs.addTab(self._build_send_tab(), _("Send STX / sBTC"))
        self.tabs.addTab(self._build_settings_tab(), _("Settings"))
        if 0 <= initial_tab < self.tabs.count():
            self.tabs.setCurrentIndex(initial_tab)
        root_layout.addWidget(self.tabs)

        root_layout.addLayout(Buttons(CloseButton(self)))

        self._refresh_address_ui()
        if self.plugin.get_stacks_address(self.wallet):
            self._refresh_network_data()

    # ------------------------------------------------------------------
    # Tab 1: Overview & History
    # ------------------------------------------------------------------

    def _build_overview_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        info_box = QGroupBox(_("Stacks Account ({})").format(self.plugin.get_network_name()))
        form = QFormLayout(info_box)

        addr_row = QHBoxLayout()
        self.addr_edit = QLineEdit()
        self.addr_edit.setReadOnly(True)
        self.addr_edit.setPlaceholderText(_("Not initialized — unlock wallet or set watch-only address"))
        addr_row.addWidget(self.addr_edit, stretch=1)

        self.copy_addr_btn = QPushButton(_("Copy"))
        self.copy_addr_btn.clicked.connect(self._copy_address)
        addr_row.addWidget(self.copy_addr_btn)

        self.derive_btn = QPushButton(_("Derive / Unlock"))
        self.derive_btn.clicked.connect(self._on_derive_clicked)
        addr_row.addWidget(self.derive_btn)

        self.watch_btn = QPushButton(_("Watch-Only..."))
        self.watch_btn.clicked.connect(self._on_watch_address_clicked)
        addr_row.addWidget(self.watch_btn)

        form.addRow(_("STX Address:"), addr_row)

        self.stx_balance_label = QLabel("—")
        self.sbtc_balance_label = QLabel("—")
        self.stbtc_balance_label = QLabel("—")
        self.status_label = QLabel("")

        form.addRow(_("STX Balance:"), self.stx_balance_label)
        form.addRow(_("sBTC Balance:"), self.sbtc_balance_label)
        form.addRow(_("stBTC Balance:"), self.stbtc_balance_label)

        refresh_row = QHBoxLayout()
        self.refresh_btn = QPushButton(_("Refresh"))
        self.refresh_btn.clicked.connect(self._refresh_network_data)
        refresh_row.addWidget(self.refresh_btn)
        refresh_row.addWidget(self.status_label, stretch=1)
        form.addRow("", refresh_row)

        layout.addWidget(info_box)

        layout.addWidget(QLabel(_("Recent Stacks / sBTC Transactions:")))
        self.tx_tree = QTreeWidget()
        self.tx_tree.setHeaderLabels([_("Time"), _("Summary"), _("Amount"), _("Status"), _("Fee (uSTX)"), _("TxID")])
        self.tx_tree.setRootIsDecorated(False)
        self.tx_tree.setAlternatingRowColors(True)
        self.tx_tree.itemDoubleClicked.connect(self._on_tx_double_clicked)
        layout.addWidget(self.tx_tree, stretch=1)

        return w

    def _refresh_address_ui(self) -> None:
        addr = self.plugin.get_stacks_address(self.wallet)
        can_sign = self.plugin.can_derive_signing_key(self.wallet)
        if addr:
            self.addr_edit.setText(addr)
            self.copy_addr_btn.setEnabled(True)
            self.refresh_btn.setEnabled(True)
        else:
            self.addr_edit.clear()
            self.copy_addr_btn.setEnabled(False)
            self.refresh_btn.setEnabled(False)
        self.derive_btn.setVisible(can_sign and self.plugin.get_cached_pubkey(self.wallet) is None)
        if hasattr(self, "send_btn"):
            self.send_btn.setEnabled(can_sign)

    def _copy_address(self) -> None:
        addr = self.addr_edit.text().strip()
        if addr:
            QApplication.clipboard().setText(addr)
            self.status_label.setText(_("Address copied to clipboard."))

    def _on_derive_clicked(self) -> None:
        pw = self._request_wallet_password(_("Enter your wallet password to derive your Stacks address:"))
        if self.wallet.has_password() and pw is None:
            return
        try:
            self.plugin.derive_stacks_keypair(self.wallet, pw)
        except Exception as e:
            self._show_err(str(e))
            return
        self._refresh_address_ui()
        self.plugin.notify_tabs_changed(self.window)
        self._refresh_network_data()

    def _on_watch_address_clicked(self) -> None:
        current = self.plugin.get_watch_address(self.wallet) or ""
        text, ok = QInputDialog.getText(
            self,
            _("Watch-Only Stacks Address"),
            _("Enter a Stacks address ({}) to monitor:").format(
                "ST.../SN..." if self.plugin.is_testnet() else "SP.../SM..."
            ),
            text=current,
        )
        if not ok:
            return
        try:
            if text.strip():
                self.plugin.add_watch_address(self.wallet, text)
            else:
                self.plugin.set_watch_address(self.wallet, None)
        except Exception as e:
            self._show_err(str(e))
            return
        self._refresh_address_ui()
        self.plugin.notify_tabs_changed(self.window)
        if self.plugin.get_stacks_address(self.wallet):
            self._refresh_network_data()

    def _refresh_network_data(self) -> None:
        addr = self.plugin.get_stacks_address(self.wallet)
        if not addr:
            return
        self.refresh_btn.setEnabled(False)
        self.status_label.setText(_("Fetching Stacks & sBTC data..."))

        async def _fetch_all():
            bal = await self.plugin.fetch_balances(addr)
            txs = await self.plugin.fetch_transactions(addr, limit=25)
            return bal, txs

        def _on_done(res):
            bal, txs = res
            self.refresh_btn.setEnabled(True)
            self._update_balances_display(bal)
            self._update_tx_tree(txs)
            self.status_label.setText(_("Updated."))

        def _on_err(err_msg: str):
            self.refresh_btn.setEnabled(True)
            self.status_label.setText(_("Error: {}").format(err_msg))

        self._run_coro(_fetch_all(), _on_done, _on_err)

    def _update_balances_display(self, bal: StacksBalances) -> None:
        stx_str = format_stx(bal.stx_balance_ustx)
        if bal.stx_locked_ustx > 0:
            stx_str += _(" (available: {}, locked: {})").format(
                format_stx(bal.stx_available_ustx),
                format_stx(bal.stx_locked_ustx),
            )
        self.stx_balance_label.setText(stx_str)
        self.sbtc_balance_label.setText(
            f"{format_sbtc(bal.sbtc_balance_sats)} ({bal.sbtc_balance_sats:,} sats)"
        )
        self.stbtc_balance_label.setText(
            f"{format_stbtc(bal.stbtc_balance_sats)} ({bal.stbtc_balance_sats:,} sats)"
        )

    def _update_tx_tree(self, txs: List[dict]) -> None:
        self.tx_tree.clear()
        for tx in txs:
            iso_time = (tx.get("burn_block_time_iso") or "")[:19].replace("T", " ")
            item = QTreeWidgetItem([
                iso_time or _("Pending"),
                tx.get("summary", ""),
                tx.get("amount_display", ""),
                tx.get("tx_status", ""),
                str(tx.get("fee_rate_ustx", "")),
                tx.get("tx_id", ""),
            ])
            self.tx_tree.addTopLevelItem(item)
        for col in range(5):
            self.tx_tree.resizeColumnToContents(col)

    def _on_tx_double_clicked(self, item: QTreeWidgetItem, _col: int) -> None:
        txid = item.text(5)
        if txid:
            QApplication.clipboard().setText(txid)
            self.status_label.setText(_("Copied TxID: {}...").format(txid[:18]))

    # ------------------------------------------------------------------
    # Tab 2: Send STX / sBTC
    # ------------------------------------------------------------------

    def _build_send_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        form = QFormLayout()

        self.asset_combo = QComboBox()
        self.asset_combo.addItem("STX (Stacks Native)", "stx")
        self.asset_combo.addItem("sBTC (SIP-010)", "sbtc")
        self.asset_combo.addItem("stBTC (Stacking DAO SIP-010)", "stbtc")
        self.asset_combo.currentIndexChanged.connect(self._on_asset_changed)
        form.addRow(_("Asset:"), self.asset_combo)

        self.recipient_edit = QLineEdit()
        self.recipient_edit.setPlaceholderText(
            "ST..." if self.plugin.is_testnet() else "SP..."
        )
        form.addRow(_("Recipient Address:"), self.recipient_edit)

        self.amount_edit = QLineEdit()
        self.amount_edit.setPlaceholderText("0.000000")
        form.addRow(_("Amount:"), self.amount_edit)

        self.memo_edit = QLineEdit()
        self.memo_edit.setPlaceholderText(_("Optional (max 34 bytes)"))
        form.addRow(_("Memo:"), self.memo_edit)

        self.fee_edit = QLineEdit()
        self.fee_edit.setPlaceholderText(_("Auto-estimate (or enter uSTX, e.g. 2000)"))
        form.addRow(_("Fee (uSTX):"), self.fee_edit)

        layout.addLayout(form)

        self.send_status_label = QLabel("")
        self.send_status_label.setWordWrap(True)
        layout.addWidget(self.send_status_label)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.send_btn = QPushButton(_("Sign & Broadcast"))
        self.send_btn.setEnabled(self.plugin.can_derive_signing_key(self.wallet))
        self.send_btn.clicked.connect(self._on_send_clicked)
        btn_row.addWidget(self.send_btn)
        layout.addLayout(btn_row)

        if not self.plugin.can_derive_signing_key(self.wallet):
            layout.addWidget(QLabel(
                _("Note: This wallet is watch-only or does not expose a signing seed/xprv. Sending is disabled.")
            ))

        layout.addStretch(1)
        return w

    def _on_asset_changed(self) -> None:
        asset = self.asset_combo.currentData()
        self.amount_edit.setPlaceholderText("0.00000000" if asset in ("sbtc", "stbtc") else "0.000000")

    def _on_send_clicked(self) -> None:
        asset = self.asset_combo.currentData()
        recipient = self.recipient_edit.text().strip()
        amount_str = self.amount_edit.text().strip()
        memo = self.memo_edit.text()
        fee_str = self.fee_edit.text().strip()

        if not is_valid_stacks_address(recipient, testnet=self.plugin.is_testnet()):
            self._show_err(_("Invalid recipient Stacks address for {}.").format(self.plugin.get_network_name()))
            return

        try:
            if asset == "stx":
                parse_stx_to_ustx(amount_str)
            elif asset == "sbtc":
                parse_sbtc_to_sats(amount_str)
            else:
                parse_stbtc_to_sats(amount_str)
        except UserFacingException as e:
            self._show_err(str(e))
            return

        fee_ustx: Optional[int] = None
        if fee_str:
            try:
                fee_ustx = int(fee_str)
                if fee_ustx <= 0:
                    raise ValueError()
            except ValueError:
                self._show_err(_("Fee must be a positive integer in uSTX."))
                return

        if len(memo.encode("utf-8")) > 34:
            self._show_err(_("Memo exceeds 34 UTF-8 bytes."))
            return

        asset_label = {"stx": "STX", "sbtc": "sBTC", "stbtc": "stBTC"}[asset]
        confirm_msg = _(
            "Send {amount} {asset} to:\n{recipient}\n\nNetwork: {network}\nFee: {fee}\n\nProceed?"
        ).format(
            amount=amount_str,
            asset=asset_label,
            recipient=recipient,
            network=self.plugin.get_network_name(),
            fee=f"{fee_ustx} uSTX" if fee_ustx is not None else _("Auto-estimated"),
        )
        if not self.window.question(confirm_msg, parent=self):
            return

        pw = self._request_wallet_password(_("Enter your wallet password to sign this Stacks transaction:"))
        if self.wallet.has_password() and pw is None:
            return

        self.send_btn.setEnabled(False)
        self.send_status_label.setText(_("Signing and broadcasting transaction..."))

        if asset == "stx":
            coro = self.plugin.send_stx(
                wallet=self.wallet,
                recipient=recipient,
                amount_stx=amount_str,
                password=pw,
                memo=memo,
                fee_ustx=fee_ustx,
                broadcast=True,
            )
        elif asset == "sbtc":
            coro = self.plugin.send_sbtc(
                wallet=self.wallet,
                recipient=recipient,
                amount_sbtc=amount_str,
                password=pw,
                memo=memo,
                fee_ustx=fee_ustx,
                broadcast=True,
            )
        else:
            coro = self.plugin.send_stbtc(
                wallet=self.wallet,
                recipient=recipient,
                amount_stbtc=amount_str,
                password=pw,
                memo=memo,
                fee_ustx=fee_ustx,
                broadcast=True,
            )

        def _on_sent(result: dict):
            self.send_btn.setEnabled(True)
            txid = result.get("txid", "")
            self.send_status_label.setText(_("Broadcast succeeded! TxID: {}").format(txid))
            self.amount_edit.clear()
            self.memo_edit.clear()
            self._refresh_address_ui()
            self._refresh_network_data()
            self.plugin.notify_tabs_changed(self.window, refresh_network=True)

        def _on_fail(err_msg: str):
            self.send_btn.setEnabled(True)
            self.send_status_label.setText(_("Failed: {}").format(err_msg))
            self._show_err(err_msg)

        self._run_coro(coro, _on_sent, _on_fail)

    # ------------------------------------------------------------------
    # Tab 3: Settings
    # ------------------------------------------------------------------

    def _build_settings_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        form = QFormLayout()

        self.api_url_edit = QLineEdit()
        self.api_url_edit.setPlaceholderText(self.plugin.get_default_api_url())
        configured_api = self.plugin.config.get("plugins.stacks.api_url") or ""
        self.api_url_edit.setText(configured_api)
        form.addRow(_("Stacks API URL:"), self.api_url_edit)

        default_c_addr, default_c_name, default_a_name = self.plugin.get_default_sbtc_contract()
        self.sbtc_contract_edit = QLineEdit()
        self.sbtc_contract_edit.setPlaceholderText(f"{default_c_addr}.{default_c_name}::{default_a_name}")
        configured_sbtc = self.plugin.config.get("plugins.stacks.sbtc_contract") or ""
        self.sbtc_contract_edit.setText(configured_sbtc)
        form.addRow(_("sBTC Contract:"), self.sbtc_contract_edit)

        default_st_addr, default_st_name, default_st_asset = self.plugin.get_default_stbtc_contract()
        self.stbtc_contract_edit = QLineEdit()
        self.stbtc_contract_edit.setPlaceholderText(f"{default_st_addr}.{default_st_name}::{default_st_asset}")
        configured_stbtc = self.plugin.config.get("plugins.stacks.stbtc_contract") or ""
        self.stbtc_contract_edit.setText(configured_stbtc)
        form.addRow(_("stBTC Contract:"), self.stbtc_contract_edit)

        self.account_index_spin = QSpinBox()
        self.account_index_spin.setRange(0, 1000)
        self.account_index_spin.setValue(self.plugin.get_account_index(self.wallet))
        form.addRow(_("BIP44 Account Index (m/44'/5757'/0'/0/i):"), self.account_index_spin)

        layout.addLayout(form)

        save_row = QHBoxLayout()
        save_row.addStretch(1)
        save_btn = QPushButton(_("Save Settings"))
        save_btn.clicked.connect(self._on_save_settings)
        save_row.addWidget(save_btn)
        layout.addLayout(save_row)

        layout.addStretch(1)
        return w

    def _on_save_settings(self) -> None:
        try:
            self.plugin.set_api_url(self.api_url_edit.text())
            self.plugin.set_sbtc_contract(self.sbtc_contract_edit.text())
            self.plugin.set_stbtc_contract(self.stbtc_contract_edit.text())
            new_idx = self.account_index_spin.value()
            if new_idx != self.plugin.get_account_index(self.wallet):
                self.plugin.set_account_index(self.wallet, new_idx)
        except Exception as e:
            self._show_err(str(e))
            return
        self._refresh_address_ui()
        self.plugin.notify_tabs_changed(self.window)
        self.window.show_message(_("Stacks plugin settings saved."), parent=self)


# ======================================================================
# Bottom Portfolio Status Bar (STX / sBTC / stBTC + Combined Total USD)
# ======================================================================

def _fmt_usd(val: Optional[Decimal]) -> str:
    if val is None:
        return "—"
    return f"${val:,.2f}"


class StacksPortfolioBar(_StacksQtMixin, QStatusBar):
    """
    Bottom status bar displaying aggregated STX, sBTC, and stBTC balances with live USD
    pricing, plus a combined portfolio USD total (BTC + STX + sBTC + stBTC).
    """

    def __init__(self, plugin: "Plugin", window: "ElectrumWindow"):
        super().__init__(window)
        self.plugin = plugin
        self.window = window
        self.wallet = window.wallet
        self._active_signals = []
        self._last_balances: Optional[StacksBalances] = None
        self._last_prices: StacksPrices = StacksPrices()

        self.setSizeGripEnabled(False)
        self.setStyleSheet("QStatusBar::item { border: 0px; }")

        self.assets_label = QLabel(_("STX: —  |  sBTC: —  |  stBTC: —"))
        self.assets_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.addWidget(self.assets_label, 1)

        self.total_label = QLabel(_("Total: —"))
        self.total_label.setStyleSheet("font-weight: bold; padding-right: 6px;")
        self.total_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.addPermanentWidget(self.total_label)

        self.refresh_btn = QPushButton("↻")
        self.refresh_btn.setFlat(True)
        self.refresh_btn.setMaximumWidth(28)
        self.refresh_btn.setToolTip(_("Refresh STX / sBTC / stBTC balances & live USD prices"))
        self.refresh_btn.clicked.connect(self.refresh)
        self.addPermanentWidget(self.refresh_btn)

        # Auto-refresh live prices & balances every 60s
        self._timer = QTimer(self)
        self._timer.setInterval(60_000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def _get_btc_balance_sats(self) -> int:
        try:
            return int(self.wallet.get_balances_for_piechart().total())
        except Exception:
            return 0

    def _get_electrum_fx_btc_usd(self) -> Optional[Decimal]:
        try:
            fx = getattr(self.window, "fx", None)
            if fx and fx.is_enabled() and getattr(fx, "ccy", None) == "USD":
                rate = fx.exchange_rate()
                if rate and rate > 0:
                    return Decimal(str(rate))
        except Exception:
            pass
        return None

    def refresh(self) -> None:
        fallback_btc_usd = self._get_electrum_fx_btc_usd()

        async def _fetch():
            bal = await self.plugin.fetch_all_balances(self.wallet)
            prices = await self.plugin.fetch_live_prices(fallback_btc_usd=fallback_btc_usd)
            return bal, prices

        def _on_done(res):
            bal, prices = res
            self._last_balances = bal
            self._last_prices = prices
            self._render()

        def _on_err(_err_msg: str):
            # Keep previous values if network temporarily unavailable; still render BTC + cached prices
            self._render()

        self._run_coro(_fetch(), _on_done, _on_err)

    def _render(self) -> None:
        bal = self._last_balances or StacksBalances(
            address="all",
            stx_balance_ustx=0,
            stx_locked_ustx=0,
            sbtc_balance_sats=0,
            sbtc_contract_id=self.plugin.get_sbtc_asset_identifier(),
            stbtc_balance_sats=0,
            stbtc_contract_id=self.plugin.get_stbtc_asset_identifier(),
        )
        prices = self._last_prices
        if prices.btc_usd is None:
            fx_btc = self._get_electrum_fx_btc_usd()
            if fx_btc is not None:
                prices = StacksPrices(
                    btc_usd=fx_btc,
                    stx_usd=prices.stx_usd,
                    sbtc_usd=fx_btc,
                    stbtc_usd=fx_btc,
                )

        btc_sats = self._get_btc_balance_sats()
        usd = calculate_portfolio_usd(
            btc_sats=btc_sats,
            stx_ustx=bal.stx_balance_ustx,
            sbtc_sats=bal.sbtc_balance_sats,
            stbtc_sats=bal.stbtc_balance_sats,
            prices=prices,
        )

        stx_amt = Decimal(bal.stx_balance_ustx) / Decimal(1_000_000)
        sbtc_amt = Decimal(bal.sbtc_balance_sats) / Decimal(100_000_000)
        stbtc_amt = Decimal(bal.stbtc_balance_sats) / Decimal(100_000_000)
        btc_amt = Decimal(btc_sats) / Decimal(100_000_000)

        stx_part = f"STX: {stx_amt:,.2f}"
        if usd["stx_usd"] is not None:
            stx_part += f" ({_fmt_usd(usd['stx_usd'])})"
        if prices.stx_usd is not None:
            stx_part += f" 1 STX~${prices.stx_usd:,.2f}"

        sbtc_part = f"sBTC: {sbtc_amt:.8f}"
        if usd["sbtc_usd"] is not None:
            sbtc_part += f" ({_fmt_usd(usd['sbtc_usd'])})"

        stbtc_part = f"stBTC: {stbtc_amt:.8f}"
        if usd["stbtc_usd"] is not None:
            stbtc_part += f" ({_fmt_usd(usd['stbtc_usd'])})"

        self.assets_label.setText(f"  {stx_part}  |  {sbtc_part}  |  {stbtc_part}")

        grand = usd["grand_total_usd"]
        if grand is not None:
            self.total_label.setText(_("Total: {} USD").format(_fmt_usd(grand)))
        else:
            self.total_label.setText(_("Total: —"))

        tooltip_lines = [
            _("Combined Portfolio Breakdown (Live USD):"),
            f"  BTC:   {btc_amt:.8f} BTC  ({_fmt_usd(usd['btc_usd'])})",
            f"  STX:   {stx_amt:,.6f} STX  ({_fmt_usd(usd['stx_usd'])})",
            f"  sBTC:  {sbtc_amt:.8f} sBTC ({_fmt_usd(usd['sbtc_usd'])})",
            f"  stBTC: {stbtc_amt:.8f} stBTC ({_fmt_usd(usd['stbtc_usd'])})",
            f"  ─────────────────────────────",
            f"  Total: {_fmt_usd(grand)} USD",
        ]
        tooltip = "\n".join(tooltip_lines)
        self.assets_label.setToolTip(tooltip)
        self.total_label.setToolTip(tooltip)


# ======================================================================
# Qt Plugin Entry Point
# ======================================================================

class Plugin(StacksPlugin):

    def __init__(self, *args):
        StacksPlugin.__init__(self, *args)
        # window -> (history_tab, addresses_tab, portfolio_bar, menu_actions)
        self._window_tabs: Dict[
            "ElectrumWindow",
            Tuple[StacksHistoryTab, StacksAddressesTab, StacksPortfolioBar, List[Any]],
        ] = {}

    @hook
    def load_wallet(self, wallet: "Abstract_Wallet", window: "ElectrumWindow"):
        self.start_wallet(wallet)
        self._attach_tabs(window)

    @hook
    def on_close_window(self, window: "ElectrumWindow"):
        self._detach_tabs(window)
        self.stop_wallet(window.wallet)

    def on_close(self):
        for window in list(self._window_tabs.keys()):
            self._detach_tabs(window)
        super().on_close()

    @hook
    def init_menubar(self, window: "ElectrumWindow"):
        window.wallet_menu.addAction(
            _("Stacks (STX / sBTC / stBTC)..."),
            partial(self.open_stacks_dialog, window),
        )

    def _attach_tabs(self, window: "ElectrumWindow") -> None:
        if window in self._window_tabs:
            return

        history_tab = StacksHistoryTab(self, window)
        addresses_tab = StacksAddressesTab(self, window)
        portfolio_bar = StacksPortfolioBar(self, window)

        history_icon = read_QIcon("tab_history.png")
        addresses_icon = read_QIcon("tab_addresses.png")

        window.tabs.addTab(history_tab, history_icon, _("STX History"))
        window.tabs.addTab(addresses_tab, addresses_icon, _("STX Addresses"))

        # Place the Stacks portfolio & combined USD bar at the bottom right above Electrum's BTC status bar
        central = window.centralWidget()
        if central is not None and central.layout() is not None:
            central.layout().addWidget(portfolio_bar)

        menu_actions: List[Any] = []
        if hasattr(window, "view_menu") and window.view_menu is not None:
            sep = window.view_menu.addSeparator()
            menu_actions.append(sep)

            def _make_toggle(tab: QWidget, icon, title: str):
                act = window.view_menu.addAction(title)
                act.setCheckable(True)
                act.setChecked(True)

                def _on_toggled(checked: bool):
                    idx = window.tabs.indexOf(tab)
                    if checked and idx == -1:
                        window.tabs.addTab(tab, icon, title)
                    elif not checked and idx != -1:
                        window.tabs.removeTab(idx)

                act.toggled.connect(_on_toggled)
                menu_actions.append(act)

            _make_toggle(history_tab, history_icon, _("STX History"))
            _make_toggle(addresses_tab, addresses_icon, _("STX Addresses"))

            bar_act = window.view_menu.addAction(_("STX Portfolio Bar"))
            bar_act.setCheckable(True)
            bar_act.setChecked(True)
            bar_act.toggled.connect(portfolio_bar.setVisible)
            menu_actions.append(bar_act)

        self._window_tabs[window] = (history_tab, addresses_tab, portfolio_bar, menu_actions)

        # Auto-fetch initial data
        portfolio_bar.refresh()
        if self.get_stacks_address(window.wallet):
            history_tab.refresh_network_data()
            addresses_tab.refresh_balances()

    def _detach_tabs(self, window: "ElectrumWindow") -> None:
        entry = self._window_tabs.pop(window, None)
        if not entry:
            return
        history_tab, addresses_tab, portfolio_bar, menu_actions = entry
        portfolio_bar.stop()
        central = window.centralWidget()
        if central is not None and central.layout() is not None:
            central.layout().removeWidget(portfolio_bar)
        portfolio_bar.deleteLater()
        for tab in (history_tab, addresses_tab):
            idx = window.tabs.indexOf(tab)
            if idx != -1:
                window.tabs.removeTab(idx)
            tab.deleteLater()
        if hasattr(window, "view_menu") and window.view_menu is not None:
            for act in menu_actions:
                window.view_menu.removeAction(act)

    def notify_tabs_changed(self, window: "ElectrumWindow", *, refresh_network: bool = False) -> None:
        entry = self._window_tabs.get(window)
        if not entry:
            return
        history_tab, addresses_tab, portfolio_bar, _ = entry
        addresses_tab.reload_addresses()
        history_tab.reload_addresses()
        portfolio_bar.refresh()
        if refresh_network:
            addresses_tab.refresh_balances()
            history_tab.refresh_network_data()

    def open_stacks_dialog(self, window: "ElectrumWindow", initial_tab: int = 0):
        d = StacksDialog(self, window, initial_tab=initial_tab)
        d.exec()
