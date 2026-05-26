from PySide6.QtCore import Qt, QObject, Signal, QThread
from PySide6.QtWidgets import (QWidget, QLabel, QVBoxLayout, QButtonGroup,
    QRadioButton, QLineEdit, QPushButton, QProgressBar)
from encryption import encrypt, decrypt


class Worker(QObject):
    progress = Signal(int)
    finished = Signal()

    def __init__(self, file, password, mode=None):
        super().__init__()
        self.file = file
        self.password = password
        self.mode = mode

    def run(self):
        if self.mode is not None:
            encrypt(self.file, self.password, self.mode, progress_signal=self.progress.emit)
        else:
            decrypt(self.file, self.password, progress_signal=self.progress.emit)
        self.finished.emit()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.resize(400, 400)

        self.label = QLabel("Drop a file here")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout = QVBoxLayout()
        layout.addWidget(self.label)

        self.setLayout(layout)

        self.setAcceptDrops(True)

        self.enc_window = None

    def dragEnterEvent(self, event, /):
        if event.mimeData().hasUrls():
            event.accept()

    def dropEvent(self, event, /):
        paths = event.mimeData().urls()

        if not paths: return

        path = paths[0].toLocalFile()
        print(path)

        self.enc_window = EncWindow(path)
        self.enc_window.show()


class EncWindow(QWidget):
    def __init__(self, dropped_file_path):
        super().__init__()
        self.file = dropped_file_path

        self.resize(400, 200)

        self.label = QLabel("Encrypt or decrypt a file")
        self.label.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.work_mode_rg = QButtonGroup()
        self.encrypt_button = QRadioButton("Encrypt")
        self.decrypt_button = QRadioButton("decrypt")
        self.work_mode_rg.addButton(self.encrypt_button)
        self.work_mode_rg.addButton(self.decrypt_button)

        self.password_input = QLineEdit("Password")

        self.encryption_mode_rg = QButtonGroup()
        self.ecb_button = QRadioButton("ECB")
        self.cbc_button = QRadioButton("CBC")
        self.ctr_button = QRadioButton("CTR")
        self.encryption_mode_rg.addButton(self.ecb_button)
        self.encryption_mode_rg.addButton(self.cbc_button)
        self.encryption_mode_rg.addButton(self.ctr_button)

        self.continue_button = QPushButton("Continue")
        self.continue_button.clicked.connect(self.click)

        widgets = [self.label,
                   self.encrypt_button, self.decrypt_button,
                   self.password_input,
                   self.ecb_button, self.cbc_button, self.ctr_button,
                   self.continue_button]

        layout = QVBoxLayout()

        for widget in widgets:
            layout.addWidget(widget)

        self.setLayout(layout)

    def click(self):
        if self.encrypt_button.isChecked():
            self._encrypt()
        elif self.decrypt_button.isChecked():
            self._decrypt()

    def _encrypt(self):
        if self.ecb_button.isChecked(): mode = "ecb"
        elif self.cbc_button.isChecked(): mode = "cbc"
        elif self.ctr_button.isChecked(): mode = "ctr"
        else: return

        password = self.password_input.text()

        self._add_progress_bar()

        self._create_worker_thread(Worker(self.file, password, mode))

        self.thread.start()

    def _decrypt(self):
        password = self.password_input.text()

        self._add_progress_bar()
        self._create_worker_thread(Worker(self.file, password))

        self.thread.start()

    def _add_progress_bar(self):
        self.progress_bar = QProgressBar()
        self.layout().addWidget(self.progress_bar)
        self.layout().update()

    def _create_worker_thread(self, worker: Worker):
        self.thread = QThread()
        self.worker = worker
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.progress_bar.setValue)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.close)



