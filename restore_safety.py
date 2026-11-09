"""Fail-closed physical-disk protection for WinPE restore (v0.21.2).

Do not infer a physical boot device from X:, which is typically a RAM disk.
Unresolved boot media or path mapping means destructive restore is disabled.
"""
import os
import sys
import ctypes

class SafetyError(RuntimeError):
    pass


def _drive(path):
    return os.path.splitdrive(os.path.abspath(path))[0].upper()


def _boot_markers(root):
    return any(os.path.isfile(os.path.join(root, rel)) for rel in (
        'sources\\boot.wim', 'Sources\\boot.wim', 'bootmgr',
        'EFI\\Boot\\bootx64.efi', 'EFI\\Boot\\bootaa64.efi',
        'EFI\\Microsoft\\Boot\\bootmgfw.efi'))


def protected_disks(disks, backup_folder, disk_for_path, winpe):
    """Return (protected disk number -> reasons, errors).

    Conservative boot-media detection: any physical removable drive, or any
    partition containing recognizable Windows boot-media files is protected.
    If a WinPE boot source cannot be positively identified, block all restores.
    This deliberately does not support PXE boot in this version.
    """
    protected = {}
    errors = []
    boot_found = False

    def add(number, reason):
        protected.setdefault(int(number), []).append(reason)

    paths = [('備份來源', backup_folder),
             ('Tool', sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(sys.argv[0]))]
    for label, path in paths:
        try:
            drive = _drive(path)
            if drive == 'X:':
                # X: is RAM; tool running from RAM does not identify boot media.
                continue
            if path.startswith('\\\\') or not drive:
                raise SafetyError('不支援或無法辨識的路徑')
            add(disk_for_path(path), label)
        except Exception as exc:
            errors.append('%s磁碟辨識失敗：%s' % (label, exc))

    if not winpe:
        errors.append('不是 WinPE，禁止 Full Disk Restore')
    for disk in disks:
        number = int(disk['Number'])
        for part in disk.get('Partitions', []):
            letter = str(part.get('DriveLetter') or '').strip().rstrip(':').upper()
            if len(letter) != 1 or not letter.isalpha() or letter == 'X':
                continue
            root = letter + ':\\'
            try:
                kind = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root)) if os.name == 'nt' else 0
                if kind == 2:  # DRIVE_REMOVABLE: all removable physical disks protected
                    add(number, '可移除式媒體（可能為 WinPE 開機媒體）')
                    boot_found = True
                if _boot_markers(root):
                    add(number, '偵測到 Windows / WinPE 開機媒體檔案')
                    boot_found = True
            except (OSError, ValueError) as exc:
                errors.append('無法檢查 Disk %d 的 %s：%s' % (number, root, exc))
    if winpe and not boot_found:
        errors.append('無法可靠定位 WinPE 實體開機媒體；為避免誤清磁碟，已禁止還原。PXE 暫不支援。')
    return protected, errors


def assert_restore_safe(disks, target, backup_folder, disk_for_path, winpe):
    protected, errors = protected_disks(disks, backup_folder, disk_for_path, winpe)
    number = int(target['Number'])
    if number in protected:
        errors.insert(0, '目標 Disk %d 受保護：%s' % (number, '、'.join(protected[number])))
    if errors:
        raise SafetyError('；'.join(errors))
    return protected
