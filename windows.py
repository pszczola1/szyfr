from PySide6.QtCore import Qt, QObject, Signal, QThread
from PySide6.QtWidgets import (QWidget, QLabel, QVBoxLayout, QButtonGroup,
    QRadioButton, QLineEdit, QPushButton, QProgressBar, QMessageBox, QFileDialog)
from encryption import encrypt, decrypt

class Worker(QObject):
    progress = Signal(int)
    finished = Signal()
    error = Signal(str)

    def __init__(self, file, output_path, password, mode=None):
        super().__init__()
        self.file = file
        self.output_path = output_path
        self.password = password
        self.mode = mode

    def run(self):
        if self.mode is not None:
            encrypt(self.file, self.output_path, self.password, self.mode, progress_signal=self.progress.emit)
        else:
            try:
                decrypt(self.file, self.output_path, self.password, progress_signal=self.progress.emit)
            except ValueError as e:
                self.error.emit(str(e))
        self.finished.emit()

class MainWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.resize(400, 400)
        self.setWindowTitle("File encryptor")

        self.label = QLabel("Drop a file here")
        self.label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.file_dialog_button = QPushButton("Browse")
        self.file_dialog_button.clicked.connect(self._show_file_dialog)

        layout = QVBoxLayout()
        layout.addWidget(self.label)
        layout.addWidget(self.file_dialog_button)

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

        self._create_enc_window(path)

    def _show_file_dialog(self):
        path, _ = QFileDialog.getOpenFileUrl(self, "Select file", "", "")
        if path.isEmpty(): return
        print(path.path()[1:])
        self._create_enc_window(path.path()[1:])

    def _create_enc_window(self, path):
        self.enc_window = EncWindow(path)
        self.enc_window.show()


class EncWindow(QWidget):
    def __init__(self, dropped_file_path):
        super().__init__()
        self.output_path = None
        self.file = dropped_file_path

        self.resize(400, 200)
        self.setWindowTitle(" ")

        self.label = QLabel("Encrypt or decrypt a file")
        self.label.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.work_mode_rg = QButtonGroup()
        self.encrypt_button = QRadioButton("Encrypt")
        self.decrypt_button = QRadioButton("Decrypt")
        self.encrypt_button.clicked.connect(self._enable_mode_buttons)
        self.decrypt_button.clicked.connect(self._disable_mode_buttons)
        self.work_mode_rg.addButton(self.encrypt_button)
        self.work_mode_rg.addButton(self.decrypt_button)

        self.password_label = QLabel("Password:")
        self.password_input = QLineEdit("")

        self.mode_label = QLabel("Mode:")
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
                   self.password_label, self.password_input,
                   self.mode_label, self.ecb_button, self.cbc_button, self.ctr_button,
                   self.continue_button]

        layout = QVBoxLayout()

        for widget in widgets:
            layout.addWidget(widget)

        self.setLayout(layout)

    def click(self):
        if self.encrypt_button.isChecked():
            password = self.password_input.text()
            if len(password) < 8:
                QMessageBox.critical(self, "Incorrect password", "Password has to be at least 8 characters long")
                return

            if self.ecb_button.isChecked():
                mode = "ecb"
            elif self.cbc_button.isChecked():
                mode = "cbc"
            elif self.ctr_button.isChecked():
                mode = "ctr"
            else:
                QMessageBox.information(self, "Choose encryption mode", "For encryption you have to choose one of the available encryption modes")
                return
            
            output_path, _ = QFileDialog.getSaveFileName(self, "Save a file", "", "*.bin;;*")
            output_path = output_path.strip()

            if output_path == "": return
            self.output_path = output_path
            self._encrypt(mode)

        elif self.decrypt_button.isChecked():
            output_path, _ = QFileDialog.getSaveFileName(self, "Save a file", "", "")
            output_path = output_path.strip()

            if output_path == "": return
            self.output_path = output_path
            self._decrypt()

        else:
            QMessageBox.information(self, "Encryption or decryption", "You have to choose encryption or decryption")

    def _encrypt(self, mode):
        password = self.password_input.text()
        self._add_progress_bar()
        self._create_worker_thread(Worker(self.file, self.output_path, password, mode))
        self.thread.start()

    def _decrypt(self):
        password = self.password_input.text()

        self._add_progress_bar()
        self._create_worker_thread(Worker(self.file, self.output_path, password))
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
        self.worker.error.connect(self.show_error)

        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self.close)

    def _enable_mode_buttons(self):
        self.ecb_button.setDisabled(False)
        self.cbc_button.setDisabled(False)
        self.ctr_button.setDisabled(False)

    def _disable_mode_buttons(self):
        self.ecb_button.setDisabled(True)
        self.cbc_button.setDisabled(True)
        self.ctr_button.setDisabled(True)

    def show_error(self, error_message):
        QMessageBox.critical(self, "Error", error_message)



