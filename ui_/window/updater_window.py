
from PySide6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QPushButton, QMessageBox, QLabel, QHBoxLayout
from PySide6.QtCore import QThreadPool
from ui_.worker.worker import Worker
from updater import get_tor_versions, get_bundle_links, get_version_by_bundle, download_file, list_downloaded_bundles, delete_bundle
from updater import get_own_bundles, check_bundle_compatibility, delete_bundle
from config import CONFIG
from config import BUNDLE_DIR
from utils import extract_tar_gz_file, resource_path
import ast
import json
import os
import logging

logger = logging.getLogger()

class UpdaterWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_ = parent
        
        main_layout = QHBoxLayout()
        self.setLayout(main_layout)
        
        left_layout = QVBoxLayout()
        main_layout.addLayout(left_layout)
        
        
        self.btn_get_versions = QPushButton("get versions")
        self.btn_get_versions.clicked.connect(self.get_available_versions)
        left_layout.addWidget(self.btn_get_versions)
        
        self.updates_list = QListWidget()
        self.updates_list.itemClicked.connect(self.selected_version)
        left_layout.addWidget(self.updates_list)
        
        self.lbl_status = QLabel()
        left_layout.addWidget(self.lbl_status)
       
        self.thread_pool = QThreadPool()
        
    
        right_layout = QVBoxLayout()
        main_layout.addLayout(right_layout)
        
        self.btn_refresh_version = QPushButton("refresh")
        self.btn_refresh_version.clicked.connect(self.refresh_version)
        right_layout.addWidget(self.btn_refresh_version)

        self.list_tor_versions = QListWidget()
        right_layout.addWidget(self.list_tor_versions)
        
        self.btn_set_default_version = QPushButton("set default version")
        self.btn_set_default_version.clicked.connect(self.set_default_version)
        right_layout.addWidget(self.btn_set_default_version)
        
        self.btn_delete_version = QPushButton("delete version")
        self.btn_delete_version.clicked.connect(self.delete_version)
        right_layout.addWidget(self.btn_delete_version)
    
    def refresh_version(self):
        self.list_tor_versions.clear()
        logger.info("Verified local Tor bundles: %s", get_own_bundles())
        for i in get_own_bundles():
            if check_bundle_compatibility(i):
                self.list_tor_versions.addItem(i)
                
    def set_default_version(self):
        if items:=self.list_tor_versions.selectedItems():
            item = items[0]
            reply = QMessageBox.question(self, 
                                        "Download", 
                                        f"Do you want set default tor?\n{item.text()}",
                                        QMessageBox.Yes| QMessageBox.No, 
                                        QMessageBox.No)
            if reply == QMessageBox.No:
                return
            
            CONFIG["tor_path"] = item.text()
            self.refresh_version()            
            

            
    def delete_version(self):
        items = self.list_tor_versions.selectedItems()
        if not items:
            return
        item = items[0]
        reply = QMessageBox.question(self,
                                     "Delete Tor bundle",
                                     f"Delete this verified local bundle?\n{item.text()}",
                                     QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        if os.path.normcase(str(CONFIG["tor_path"] or "")) == os.path.normcase(item.text()):
            CONFIG["tor_path"] = None
        delete_bundle(item.text())
        self.refresh_version()            
        
    def get_available_versions(self):
        self.btn_get_versions.setDisabled(True)
        self.worker = Worker(get_tor_versions)
        self.worker.signals.finished.connect(self.set_tor_versions)
        self.thread_pool.start(self.worker)
        
    def set_tor_versions(self, data):
        
        try:
            data = ast.literal_eval(data)
            if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
                data = []
        except (ValueError, SyntaxError):
            data = []
        
        
        self.worker = Worker(self.get_download_links, data)
        self.worker.signals.finished.connect(self.set_download_links)
        self.thread_pool.start(self.worker)
        
        
    
    def get_download_links(self, data):        
        lst = []
        
        for i in data:
            lst.extend(get_bundle_links(i))
        return lst
    
    def set_download_links(self, data):
        
        try:
            data = ast.literal_eval(data)
            if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
                data = []
        except (ValueError, SyntaxError):
            data = [] 
        
        self.updates_list.clear()
        
        downloaded_bundles = list_downloaded_bundles()
        downloaded_bundles = list(map(lambda x: os.path.basename(x), downloaded_bundles))
        logger.debug("Downloaded archive names: %s", downloaded_bundles)
        for i in data:
            if i not in downloaded_bundles:
                self.updates_list.addItem(i)
        
        self.btn_get_versions.setDisabled(False)
        

    
    def selected_version(self, item):
        reply = QMessageBox.question(self,
                                     "Verify and install Tor bundle",
                                     f"Download and verify the official Tor signature for?\n{item.text()}",
                                     QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        self.updates_list.setEnabled(False)
        self.btn_get_versions.setEnabled(False)
        bundle = item.text()
        version = get_version_by_bundle(bundle)
        self.lbl_status.setText(f"Downloading and verifying {bundle}…")
        self.worker = Worker(self.download_bundle, bundle, version)
        self.worker.signals.finished.connect(self._on_download_finished)
        self.worker.signals.error.connect(self._on_download_error)
        self.thread_pool.start(self.worker)

    def download_bundle(self, bundle, version):
        logger.info("Downloading and verifying %s", bundle)
        archive = download_file(bundle, version)
        base_path = os.path.join(BUNDLE_DIR, os.path.basename(bundle).replace(".tar.gz", ""))
        extract_tar_gz_file(archive, base_path)
        return f"Installed verified Tor Expert Bundle {bundle}"

    def _on_download_finished(self, message):
        self.lbl_status.setText(message)
        self.updates_list.setEnabled(True)
        self.btn_get_versions.setEnabled(True)
        self.refresh_version()
        self.get_available_versions()

    def _on_download_error(self, error):
        logger.error("Tor bundle download/verification failed: %s", error)
        self.lbl_status.setText("Download or signature verification failed; the bundle was not installed.")
        QMessageBox.warning(self, "Tor bundle verification failed", str(error))
        self.updates_list.setEnabled(True)
        self.btn_get_versions.setEnabled(True)
        

