from PySide6.QtCore import Signal, QObject


class Data(QObject):
    valueChanged = Signal(str)

    def __init__(self):
        super().__init__()
        self._value = ""

    def get_value(self):
        return self._value

    def set_value(self, val):
        if self._value != val:
            self._value = val
            self.valueChanged.emit(self._value)

    value = property(get_value, set_value)
    

class QRWorkerSignals(QObject):
    started = Signal()
    finished = Signal(str)
    cancelled = Signal(str)
    error = Signal(str)
