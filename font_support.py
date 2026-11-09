"""Portable private fonts for WinPE. No system-wide installation."""
import ctypes
import os
import sys
from pathlib import Path

FONT_FAMILY = 'Noto Sans CJK TC'
_status = '尚未載入'


def _resource_root():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))


def load_private_fonts():
    global _status
    if os.name != 'nt':
        _status = '非 Windows 環境'
        return False
    try:
        gdi32 = ctypes.WinDLL('gdi32', use_last_error=True)
        add = gdi32.AddFontResourceExW
        add.argtypes = [ctypes.c_wchar_p, ctypes.c_uint, ctypes.c_void_p]
        add.restype = ctypes.c_int
        loaded = []
        for filename in ('NotoSansCJK-Regular.ttc', 'NotoSansCJK-Bold.ttc'):
            path = _resource_root() / 'fonts' / filename
            if not path.is_file():
                _status = '缺少字型檔：' + filename
                return False
            count = add(str(path), 0x10, None)  # FR_PRIVATE: only this process
            if count <= 0:
                _status = '載入失敗：' + filename + ' (Win32=' + str(ctypes.get_last_error()) + ')'
                return False
            loaded.append(filename)
        _status = 'Windows 已載入私人字型：' + ', '.join(loaded)
        return True
    except Exception as exc:
        _status = '字型載入例外：' + repr(exc)
        return False


def font_status():
    return _status


def resolve_tk_family(root):
    """Check Tk's font enumeration; do not falsely claim it can render Chinese."""
    try:
        import tkinter.font as tkfont
        families = set(tkfont.families(root))
        if FONT_FAMILY in families:
            return FONT_FAMILY, 'Tk 已辨識 ' + FONT_FAMILY
        return 'Microsoft JhengHei UI', 'Tk 未列出 Noto Sans CJK TC，使用原有字型設定；可能仍缺字'
    except Exception as exc:
        return 'Microsoft JhengHei UI', 'Tk 字型檢查失敗：' + repr(exc)
