
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QPushButton,
    QMessageBox,
    QListWidget,
    QLineEdit,
    QLabel
)
from PySide6.QtCore import Qt, QThreadPool
from proxy import load_blocked, remove_blocked, save_blocked, add_to_blocked_hosts, get_blocked
from ui_.worker.worker import Worker
import logging
logger = logging.getLogger(__name__)

class BlcokHostsWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent) 
        self._parent = parent    
        main_layout = QVBoxLayout(self)
        self.setLayout(main_layout)
        main_layout.addWidget(QLabel("Block host:"))
        
        load_blocked()

        self.hosts_list = QListWidget()
        main_layout.addWidget(self.hosts_list)
        self.hosts_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hosts_list.customContextMenuRequested.connect(self.show_context_menu)

        self._update_hosts_list()
        
        self.inp_host = QLineEdit()
        self.inp_host.setPlaceholderText("Enter a host like 'example.com'")
        main_layout.addWidget(self.inp_host)

        self.btn_add = QPushButton("Add")
        main_layout.addWidget(self.btn_add)
        self.btn_add.clicked.connect(self.add_to_list)
        
        self.threadpool = QThreadPool()
        
    def show_context_menu(self, pos):
        item = self.hosts_list.itemAt(pos)
        if item:
            reply = QMessageBox.question(
                self,
                "Confirm Delete",
                f"Do you want to remove '{item.text()}'?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                remove_blocked(item.text())
                self.hosts_list.takeItem(self.hosts_list.row(item))
                worker = Worker(
                    save_blocked
                )
                self.threadpool.start(worker)
    
    def _update_hosts_list(self):
        self.hosts_list.clear()
        for host in get_blocked():
            self.hosts_list.addItem(host)
        
    def add_to_list(self):
        host = self.inp_host.text().strip()
        if not host:
            return
        try:
            added = add_to_blocked_hosts(host)
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, "Invalid host rule", str(exc))
            return
        if added:
            self.hosts_list.addItem(host)
            self.inp_host.clear()
            self.inp_host.setFocus()
            