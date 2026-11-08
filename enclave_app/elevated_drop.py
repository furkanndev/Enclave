"""Enclave - Yönetici modunda Dosya Gezgini'nden sürükle-bırak.

Windows, normal yetkili Gezgin'den yönetici penceresine OLE sürüklemesini engeller. Bu yüzden yalnızca yönetici modunda
pencerenin OLE hedefi kaldırılır ve klasik WM_DROPFILES iletisi dinlenir; normal modda hiçbir şey değişmez.
"""

import sys
from typing import Callable, List, Optional

from PyQt6.QtCore import QAbstractNativeEventFilter, QTimer
from PyQt6.QtWidgets import QApplication, QWidget

WM_DROPFILES = 0x0233
MESSAGES = (WM_DROPFILES, 0x0049, 0x004A)

class _DropFilter(QAbstractNativeEventFilter):
    def __init__(self) -> None:
        super().__init__()
        self.hwnd = 0
        self.on_drop: Optional[Callable[[List[str]], None]] = None

    def nativeEventFilter(self, event_type, message):
        if bytes(event_type) != b"windows_generic_MSG":
            return False, 0
        import ctypes
        from ctypes import wintypes
        msg = wintypes.MSG.from_address(int(message))
        if msg.message != WM_DROPFILES or msg.hWnd != self.hwnd:
            return False, 0
        shell32 = ctypes.windll.shell32
        shell32.DragQueryFileW.argtypes = [wintypes.WPARAM, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
        shell32.DragFinish.argtypes = [wintypes.WPARAM]
        paths = []
        for index in range(shell32.DragQueryFileW(msg.wParam, 0xFFFFFFFF, None, 0)):
            buffer = ctypes.create_unicode_buffer(32768)
            shell32.DragQueryFileW(msg.wParam, index, buffer, 32768)
            paths.append(buffer.value)
        shell32.DragFinish(msg.wParam)
        if paths and self.on_drop:
            callback = self.on_drop
            QTimer.singleShot(0, lambda: callback(paths))
        return True, 0

_filter: Optional[_DropFilter] = None

def enable_elevated_drop(window: QWidget, on_drop: Callable[[List[str]], None]) -> None:
    """Pencere yönetici modundaysa Gezgin'den bırakılan dosyaları on_drop işlevine iletir."""
    global _filter
    if sys.platform != "win32":
        return
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return
    if _filter is None:
        _filter = _DropFilter()
        QApplication.instance().installNativeEventFilter(_filter)
    hwnd = int(window.winId())
    _filter.hwnd, _filter.on_drop = hwnd, on_drop
    user32 = ctypes.windll.user32
    for message in MESSAGES:
        user32.ChangeWindowMessageFilterEx(ctypes.c_void_p(hwnd), message, 1, None)
    ctypes.windll.ole32.RevokeDragDrop(ctypes.c_void_p(hwnd))
    ctypes.windll.shell32.DragAcceptFiles(ctypes.c_void_p(hwnd), True)
