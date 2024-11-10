import time

from textual.app import App, ComposeResult
from textual.widgets import DataTable
from textual.widgets import RichLog
from textual.widgets import Label
from rich.text import Text
from textual import work
from textual.binding import Binding
from textual.containers import Horizontal
import logging
from queue import Empty
import threading
from textual.containers import Vertical


class TUIApp(App):
    BINDINGS = [
        Binding("ctrl+c", "request_quit", "Quit", show=False, priority=True),
    ]

    def __init__(self, ui_api):
        super().__init__()
        self.ui_api = ui_api
        self.is_run = True
        self.stopping = False
        self.table_col = ("Name", "Peer ID", "Local", "Endpoint", "Crypto", "Status", "Ping")
        self.log_reader_thread = threading.Thread(target=self.log_reader)
        self.table_updater_thread = threading.Thread(target=self.table_updater)

    def compose(self) -> ComposeResult:
        with Horizontal(id="peers"):
            yield DataTable(id="peer-table")
            with Vertical(id="info"):
                yield Label("Peer_id: ", id="peer_id")
                yield Label("bind address: ", id="local_addr")
                yield Label("Server status: ", id="server_status")
        yield RichLog(highlight=True, markup=True, id="main-log", wrap=True, max_lines=5000)

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.zebra_stripes = True

        for col in self.table_col:
            table.add_column(col, key=col)

        table.styles.border = ("ascii", "grey")
        table.show_cursor = False
        table.border_title = "Peers table"
        table.styles.width = "auto"
        table.styles.height = "auto"

        log = self.query_one(RichLog)
        log.styles.border = ("ascii", "grey")
        log.border_title = "Logs console"
        log.styles.min_height = 5
        log.styles.overflow_x = "hidden"
        log.styles.margin = (1, 0, 0, 0)

        hor = self.query_one(Horizontal)
        hor.styles.width = "auto"
        hor.styles.height = "auto"
        hor.styles.max_height = "70%"
        hor.styles.max_width = "100%"

        ver = self.query_one(Vertical)
        ver.styles.padding = 1
        ver.styles.margin = (0, 0, 0, 1)
        ver.styles.width = "auto"
        ver.styles.height = "auto"
        ver.styles.border = ("ascii", "grey")
        ver.border_title = "Info"

    def log_reader(self):
        while self.is_run:
            try:
                log = self.ui_api.log_queue.get(timeout=1)
            except Empty:
                continue
            self.call_from_thread(self.query_one(RichLog).write, Text.from_ansi(log.message))

    def table_updater(self):
        table = self.query_one(DataTable)
        peer_id_label = self.query_one("#peer_id")
        bind_addr_label = self.query_one("#local_addr")
        server_status_label = self.query_one("#server_status")
        while self.is_run:
            self.call_from_thread(peer_id_label.update, f"Peer_id: {self.ui_api.conf.PEER_ID}")
            peer_bind = self.ui_api.get_local_addr()
            self.call_from_thread(bind_addr_label.update,
                                  f"Bind address: {peer_bind[0]}:{peer_bind[1]}")

            server_status = self.ui_api.get_server_status()
            if server_status is None:
                server_status = "Connecting"
            elif server_status:
                server_status = "Online"
            else:
                server_status = "Offline"
            self.call_from_thread(server_status_label.update, f"Server status: {server_status}")

            rows = []
            for peer in self.ui_api.get_peers():
                peer_id = peer.get("id")
                endpoint = self.ui_api.get_endpoint(peer_id)
                if endpoint is not None:
                    endpoint = f"{endpoint[0]}:{endpoint[1]}"
                else:
                    endpoint = " "*21
                status = self.ui_api.get_peer_status(peer_id)
                ping = self.ui_api.get_peer_ping(peer_id)
                if peer_id == self.ui_api.conf.PEER_ID:
                    status = "Self"
                    ping = "~"
                elif status:
                    status = "Online"
                else:
                    status = "Offline"
                rows.append((peer.get("name"), peer_id, peer.get("addr"), endpoint,
                             self.ui_api.get_crypto_status(peer_id), status, ping,))
            self.call_from_thread(table.clear)
            self.call_from_thread(table.add_rows, rows)
            time.sleep(1)

    @work(exclusive=True, thread=True)
    def action_request_quit(self) -> None:
        """Action to display the quit dialog."""
        if self.stopping:
            logging.info("stopping.")
            return
        self.stopping = True
        self.ui_api.stop()
        self.call_from_thread(self.action_quit)
        self.is_run = False
        self.log_reader_thread.join()
        self.table_updater_thread.join()

    def on_ready(self) -> None:
        logging.info("TUI started")
        self.log_reader_thread.start()
        self.table_updater_thread.start()
