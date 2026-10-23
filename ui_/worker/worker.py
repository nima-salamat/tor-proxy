import logging

from PySide6.QtCore import Signal, QObject, QRunnable, Slot
from .utils import QRWorkerSignals

logger = logging.getLogger(__name__)


class Worker(QRunnable):
    """Run a blocking task off the GUI thread and report failures with tracebacks."""

    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
        self.signals = QRWorkerSignals()

    @Slot()
    def run(self):
        try:
            self.signals.started.emit()
            result = self.fn(*self.args, **self.kwargs)
            result = "" if result is None else result
            self.signals.finished.emit(str(result))
        except Exception as exc:
            task_name = getattr(self.fn, "__qualname__", type(self.fn).__name__)
            logger.exception("Background task failed (%s).", task_name)
            try:
                self.signals.error.emit(f"{type(exc).__name__}: {exc}")
            except RuntimeError:
                logger.exception("Could not notify the GUI about a background task failure.")
