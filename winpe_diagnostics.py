"""Read-only deployment checks. Standard library only; no PowerShell dependency."""
import ctypes
import os
import platform
import shutil
import sys
from datetime import datetime


def collect_report():
    lines = ['Backup and Restore Tool - Environment Report',
             'Time: ' + datetime.now().isoformat(timespec='seconds'),
             'OS: ' + platform.platform(),
             'Architecture: ' + platform.machine(),
             'Python: ' + sys.version.splitlines()[0],
             'Frozen executable: ' + str(bool(getattr(sys, 'frozen', False))),
             'Executable: ' + sys.executable,
             'SystemRoot: ' + os.environ.get('SystemRoot', '(missing)'),
             'WinPE MiniNT registry: unknown']
    if os.name == 'nt':
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\MiniNT')
            winreg.CloseKey(key)
            lines[-1] = 'WinPE MiniNT registry: PRESENT'
        except FileNotFoundError:
            lines[-1] = 'WinPE MiniNT registry: absent'
        except OSError as exc:
            lines[-1] = 'WinPE MiniNT registry: ERROR ' + str(exc)
    for exe in ('dism.exe', 'diskpart.exe', 'bcdboot.exe', 'pnputil.exe', 'powershell.exe'):
        lines.append(exe + ': ' + (shutil.which(exe) or 'NOT FOUND'))
    try:
        import tkinter
        lines.append('Tkinter import: OK (Tk ' + str(tkinter.TkVersion) + ')')
    except Exception as exc:
        lines.append('Tkinter import: FAILED ' + repr(exc))
    lines.append('Disk operations: NOT EXECUTED (read-only report)')
    lines.append('Note: command presence does not establish functional WinPE compatibility.')
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    print(collect_report())
