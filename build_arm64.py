"""Package v0.24.3 on native Windows ARM64. Does not launch the application."""

import hashlib
import os
import platform
import struct
import subprocess
import sys
import sysconfig
from pathlib import Path


SOURCE = "Backup_and_Restore_Tool_v0.24.3.py"
OUTPUT = "Backup_and_Restore_Tool_v0.24.3_ARM64"
PYINSTALLER = "6.22.3"
ARM64 = 0xAA64
FONT_FILES = (
    "NotoSansCJK-Regular.ttc",
    "NotoSansCJK-Bold.ttc",
    "OFL.txt",
    "NOTICE.txt",
)


def pe_machine(path):
    with path.open("rb") as binary:
        if binary.read(2) != b"MZ":
            raise ValueError(f"{path}: DOS signature missing")
        binary.seek(0x3C)
        pe_offset = int.from_bytes(binary.read(4), "little")
        binary.seek(pe_offset)
        if binary.read(4) != b"PE\0\0":
            raise ValueError(f"{path}: PE signature missing")
        return struct.unpack("<H", binary.read(2))[0]


def run_python(*args):
    command = [sys.executable, *args]
    print(subprocess.list2cmdline(command), flush=True)
    subprocess.run(command, check=True)


def main():
    os.chdir(Path(__file__).resolve().parents[1])
    print(f"Python: {sys.version}\nExecutable: {sys.executable}")
    print(f"OS: {platform.system()} / {platform.machine()}; ABI: {sysconfig.get_platform()}")
    if sys.platform != "win32" or sysconfig.get_platform() != "win-arm64":
        raise RuntimeError("A native Windows ARM64 Python is required.")
    if pe_machine(Path(sys.executable)) != ARM64:
        raise RuntimeError("Python executable does not have an ARM64 PE header.")

    # Detect missing Tcl/Tk before packaging, without opening a window.
    run_python(
        "-c",
        "import tkinter as tk; print('Tk:', tk.TkVersion, 'Tcl:', tk.Tcl().eval('info patchlevel'))",
    )
    if not Path(SOURCE).is_file():
        raise FileNotFoundError(SOURCE)
    for name in FONT_FILES:
        path = Path("fonts") / name
        if not path.is_file() or path.stat().st_size == 0:
            raise FileNotFoundError(f"Missing or empty font resource: {path}")

    run_python("-m", "pip", "install", "--only-binary=:all:", f"PyInstaller=={PYINSTALLER}")
    run_python("-m", "pip", "freeze")
    run_python(
        "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
        "--noupx", "--name", OUTPUT,
        "--hidden-import", "winpe_diagnostics",
        "--hidden-import", "font_support",
        "--hidden-import", "restore_engine_v021",
        "--hidden-import", "restore_safety",
        "--hidden-import", "shrink_layout_v023",
        "--hidden-import", "driver_manager",
        "--add-data", "fonts:fonts",
        SOURCE,
    )

    exe = Path("dist") / f"{OUTPUT}.exe"
    machine = pe_machine(exe)
    print(f"EXE PE Machine: 0x{machine:04X}")
    if machine != ARM64:
        raise RuntimeError(f"{exe} is not an ARM64 executable.")

    from PyInstaller.archive.readers import CArchiveReader

    entries = {name.replace("\\", "/") for name in CArchiveReader(str(exe)).toc}
    required = {
        "_tkinter.pyd", "_tcl_data/init.tcl", "_tk_data/tk.tcl",
        *(f"fonts/{name}" for name in FONT_FILES),
    }
    missing = required - entries
    if missing:
        raise RuntimeError(f"Missing packaged files: {', '.join(sorted(missing))}")

    with exe.open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    exe.with_suffix(".exe.sha256").write_text(f"{digest}  {exe.name}\n", encoding="ascii")
    print(f"Verified: {exe}\nSHA-256: {digest}")


if __name__ == "__main__":
    main()
