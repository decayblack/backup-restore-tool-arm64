import traceback
import json
import hashlib
import subprocess
import threading
import os
import base64
import re
import shutil
import tempfile
import sys
import time
import ctypes
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from winpe_diagnostics import collect_report
from restore_safety import protected_disks, assert_restore_safe
from restore_engine_v021 import restore as execute_full_restore, plan as full_restore_plan
from shrink_layout_v023 import calculate as calculate_shrink_layout, LayoutError
from font_support import load_private_fonts, resolve_tk_family, font_status
from driver_manager import exe_directory, find_infs, load_drivers

APP_VERSION = '0.24.3 Driver Management + Restore Diagnostics' 
APP_NAME = 'Backup and Restore Tool'
BG = '#132D49'
PANEL = '#1D4165'
CARD = '#28567E'
TEXT = '#eef5fc'
MUTED = '#C1D8EB'
ACCENT = '#80C5FF'

FOLDER_ICON_PNG = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAb0lEQVR4nGNgGHGAEZnz83rdf1wK2TWbGHHJIQMmYgwjRh4GWIhRBAPXZhngNVQr7QIjCzEKYUBGU5uAhQz/4S68e3gTMWYSBHAD5XTw204MeHTlKiJSqAVGDRw1kAwAL0GIzX74gFbaBaJKpIEFAFLNHY8fbS75AAAAAElFTkSuQmCC'
DRIVE_ICON_PNG = 'iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAAfklEQVR4nGNgGHGAEV3g2vNP/0k1REuSD24OC7ph5y/dINlV155/+g8zlIlSwxgYGBjOX7oB9xkLuuTGI5dINtDfRg/OZsKjjiwwaiDlACOWkWOMHECRC0/LXqOegTDD0A2FG6glycdoqKdBtIGmj7XgtKGeBjw/U71wGIEAAFOMK7+ytTDEAAAAAElFTkSuQmCC'

# Windows native storage inventory; no PowerShell dependency.
# Read-only DeviceIoControl queries; no disk layout changes.
import struct
import uuid
from ctypes import wintypes

KERNEL32 = ctypes.WinDLL('kernel32', use_last_error=True) if os.name == 'nt' else None
INVALID_HANDLE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
OPEN_EXISTING = 3
IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x00070050
IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400

if KERNEL32:
    KERNEL32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
    KERNEL32.CreateFileW.restype = wintypes.HANDLE
    KERNEL32.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    KERNEL32.DeviceIoControl.restype = wintypes.BOOL
    KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
    KERNEL32.CloseHandle.restype = wintypes.BOOL


def _open_device(path):
    handle = KERNEL32.CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   None, OPEN_EXISTING, 0, None)
    if handle == INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def _ioctl(handle, code, size=65536, in_data=None):
    output = ctypes.create_string_buffer(size)
    received = wintypes.DWORD()
    inp = ctypes.create_string_buffer(in_data) if in_data is not None else None
    ok = KERNEL32.DeviceIoControl(handle, code, inp, len(in_data) if in_data else 0,
                                   output, size, ctypes.byref(received), None)
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return output.raw[:received.value]


def _volume_extents(letter):
    handle = _open_device('\\\\.\\' + letter + ':')
    try:
        raw = _ioctl(handle, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 4096)
        count = struct.unpack_from('<I', raw, 0)[0]
        if count < 1 or count > 64 or len(raw) < 8 + 24 * count:
            raise RuntimeError('磁碟區 Extents 資料不完整，無法安全辨識實體磁碟。')
        return [(struct.unpack_from('<I', raw, 8 + i * 24)[0],
                 struct.unpack_from('<q', raw, 16 + i * 24)[0]) for i in range(count)]
    finally:
        KERNEL32.CloseHandle(handle)


def _volume_guid_volumes():
    """Enumerate mounted volume GUID paths without changing drive letters or disk layout."""
    found = {}
    first = KERNEL32.FindFirstVolumeW
    first.argtypes = [wintypes.LPWSTR, wintypes.DWORD]
    first.restype = wintypes.HANDLE
    next_volume = KERNEL32.FindNextVolumeW
    next_volume.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
    next_volume.restype = wintypes.BOOL
    close = KERNEL32.FindVolumeClose
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    buf = ctypes.create_unicode_buffer(1024)
    handle = first(buf, len(buf))
    if handle == INVALID_HANDLE:
        return found
    try:
        while True:
            guid_path = buf.value
            try:
                # DeviceIoControl accepts the volume GUID path without trailing slash.
                volume = _open_device(guid_path.rstrip('\\'))
                try:
                    raw = _ioctl(volume, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 4096)
                    count = struct.unpack_from('<I', raw, 0)[0]
                    if count == 1 and len(raw) >= 32:
                        disk_no = struct.unpack_from('<I', raw, 8)[0]
                        offset = struct.unpack_from('<q', raw, 16)[0]
                        fs = ctypes.create_unicode_buffer(64)
                        ok = KERNEL32.GetVolumeInformationW(guid_path, None, 0, None, None, None, fs, len(fs))
                        if ok and fs.value.upper() in ('NTFS', 'FAT32'):
                            found.setdefault((disk_no, offset), (guid_path, fs.value))
                finally:
                    KERNEL32.CloseHandle(volume)
            except OSError:
                pass
            if not next_volume(handle, buf, len(buf)):
                break
    finally:
        close(handle)
    return found


def _drive_volumes():
    result = {}
    mask = KERNEL32.GetLogicalDrives()
    for index in range(26):
        if not (mask & (1 << index)):
            continue
        letter = chr(65 + index)
        try:
            extents = _volume_extents(letter)
            fs = ctypes.create_unicode_buffer(64)
            label = ctypes.create_unicode_buffer(256)
            ok = KERNEL32.GetVolumeInformationW(letter + ':\\', label, len(label),
                                                  None, None, None, fs, len(fs))
            for disk_number, offset in extents:
                result.setdefault((disk_number, offset), []).append(
                    (letter, fs.value if ok else '', label.value if ok else ''))
        except OSError:
            continue  # Unmounted, inaccessible or virtual volumes have no drive-letter mapping.
    return result


def _disk_model(handle):
    try:
        raw = _ioctl(handle, IOCTL_STORAGE_QUERY_PROPERTY, 4096, struct.pack('<II', 0, 0) + b'\0')
        if len(raw) >= 36:
            offset = struct.unpack_from('<I', raw, 16)[0]  # ProductIdOffset
            if 0 < offset < len(raw):
                return raw[offset:].split(b'\0', 1)[0].decode('ascii', 'replace').strip()
    except OSError:
        pass
    return ''


def _disk_identity(layout, style):
    """Read disk-level identity from DRIVE_LAYOUT_INFORMATION_EX union."""
    if style == 1 and len(layout) >= 48:
        return {'gpt_disk_guid': str(uuid.UUID(bytes_le=layout[8:24])),
                'gpt_usable_start': struct.unpack_from('<q', layout, 24)[0],
                'gpt_usable_length': struct.unpack_from('<q', layout, 32)[0],
                'gpt_max_partition_count': struct.unpack_from('<I', layout, 40)[0]}
    if style == 0 and len(layout) >= 16:
        return {'mbr_signature': '%08X' % struct.unpack_from('<I', layout, 8)[0],
                'mbr_checksum': struct.unpack_from('<I', layout, 12)[0]}
    return {}


def _layout_snapshot(disk):
    """Canonical source disk layout for future restore planning; no disk writes."""
    partitions = []
    for p in sorted(disk.get('Partitions', []), key=lambda x: (int(x.get('Offset', 0)), int(x['Number']))):
        partitions.append({
            'number': int(p['Number']), 'offset_bytes': int(p.get('Offset', 0)),
            'size_bytes': int(p['Size']), 'type': p.get('Type', ''),
            'partition_guid': p.get('PartitionId', ''),
            'partition_type_guid': p.get('PartitionTypeGuid', ''),
            'filesystem': p.get('FileSystem', ''),
            'volume_guid_path_at_capture': p.get('VolumeGuidPath', ''),
            'drive_letter_at_capture': p.get('DriveLetter', '')})
    return {'disk_size_bytes': int(disk['Size']),
            'partition_style': disk.get('PartitionStyle', ''),
            'disk_identity': disk.get('DiskIdentity', {}),
            'partitions': partitions}


def _layout_hash(snapshot):
    # Exclude ephemeral mount paths and drive letters from the identity hash.
    stable = {'disk_size_bytes': snapshot['disk_size_bytes'],
              'partition_style': snapshot['partition_style'],
              'disk_identity': snapshot['disk_identity'],
              'partitions': [{k: v for k, v in p.items()
                              if k not in ('volume_guid_path_at_capture', 'drive_letter_at_capture', 'filesystem')}
                             for p in snapshot['partitions']]}
    return hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=False,
                                     separators=(',', ':')).encode('utf-8')).hexdigest()


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path, data):
    temp = path + '.tmp'
    with open(temp, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def _scan_native():
    volumes = _drive_volumes()
    guid_volumes = _volume_guid_volumes()
    disks = []
    for number in range(64):
        try:
            handle = _open_device(r'\\.\PhysicalDrive' + str(number))
        except OSError:
            continue
        try:
            size_raw = _ioctl(handle, IOCTL_DISK_GET_LENGTH_INFO, 8)
            size = struct.unpack_from('<q', size_raw)[0]
            layout = _ioctl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, 65536)
            if len(layout) < 48:
                raise RuntimeError('磁碟配置資訊長度不足。')
            style, count = struct.unpack_from('<II', layout, 0)
            if count > 128 or len(layout) < 48 + 144 * count:
                raise RuntimeError('Partition 配置資訊不完整。')
            parts = []
            for i in range(count):
                off = 48 + i * 144
                pstyle = struct.unpack_from('<I', layout, off)[0]
                start, length, part_num = struct.unpack_from('<qqI', layout, off + 8)
                if part_num == 0 or length <= 0:
                    continue
                partition_id = ''
                partition_type_guid = ''
                if pstyle == 1:
                    guid = uuid.UUID(bytes_le=layout[off + 32:off + 48])
                    partition_type_guid = str(guid)
                    partition_id = str(uuid.UUID(bytes_le=layout[off + 48:off + 64]))
                    typ = { 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b': 'System',
                            'e3c9e316-0b5c-4db8-817d-f92df00215ae': 'Reserved',
                            'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7': 'Basic',
                            'de94bba4-06d1-4d40-a16a-bfd50179d6ac': 'Recovery' }.get(str(guid), str(guid))
                elif pstyle == 0:
                    typ = 'MBR 0x%02X' % layout[off + 32]
                else:
                    typ = 'Unknown'
                mapped = volumes.get((number, start), [])
                letter, fs, label = mapped[0] if mapped else ('', '', '')
                volume_guid, guid_fs = guid_volumes.get((number, start), ('', ''))
                if not fs:
                    fs = guid_fs
                parts.append({'Number': part_num, 'Size': length, 'Offset': start,
                              'PartitionId': partition_id, 'PartitionTypeGuid': partition_type_guid,
                              'Type': typ,
                              'DriveLetter': letter, 'VolumeGuidPath': volume_guid, 'FileSystem': fs, 'Label': label})
            disks.append({'Number': number, 'Model': _disk_model(handle) or 'Physical Disk ' + str(number),
                          'Size': size, 'BusType': 'Unknown',
                          'PartitionStyle': {0:'MBR', 1:'GPT', 2:'RAW'}.get(style, 'Unknown'),
                          'IsBoot': False, 'IsSystem': False, 'DiskIdentity': _disk_identity(layout, style), 'Partitions': parts})
        finally:
            KERNEL32.CloseHandle(handle)
    return disks


def scan_disks():
    if os.name != 'nt':
        raise RuntimeError('磁碟掃描僅支援 Windows / WinPE。')
    return _scan_native()


def is_winpe():
    if os.name != 'nt':
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SYSTEM\CurrentControlSet\Control\MiniNT'):
            return True
    except OSError:
        return False


def disk_for_path(path):
    """Resolve a drive letter to one physical disk, refusing spanning volumes."""
    if os.name != 'nt' or path.startswith('\\\\'):
        raise RuntimeError('不支援網路路徑或非 Windows 路徑。')
    drive = os.path.splitdrive(os.path.abspath(path))[0].rstrip(':')
    if len(drive) != 1 or not drive.isalpha():
        raise RuntimeError('路徑必須位於有磁碟代號的本機磁碟。')
    extents = _volume_extents(drive.upper())
    disks = {number for number, _ in extents}
    if len(disks) != 1:
        raise RuntimeError('此磁碟區跨越多顆實體磁碟，無法安全辨識。')
    return disks.pop()


def volume_filesystem(path):
    """Read volume filesystem using Win32; works without PowerShell."""
    if os.name != 'nt':
        raise RuntimeError('磁碟檔案系統檢查僅支援 Windows。')
    root = os.path.splitdrive(os.path.abspath(path))[0] + '\\'
    if len(root) != 3 or root[1:] != ':\\':
        raise RuntimeError('目的地必須是有磁碟代號的本機磁碟。')
    fs = ctypes.create_unicode_buffer(64)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        ctypes.c_wchar_p(root), None, 0, None, None, None, fs, len(fs))
    if not ok:
        raise ctypes.WinError()
    return fs.value.upper()


def safe_backup_name(name):
    name = name.strip()
    if not name or name in ('.', '..') or name.endswith(('.', ' ')) or len(name) > 100:
        raise ValueError('備份名稱不可空白、以點或空格結尾，且不可超過 100 字元。')
    if any(ch in name for ch in '<>:"/\\|?*') or any(ord(ch) < 32 for ch in name):
        raise ValueError('備份名稱含有不允許的字元。')
    return name


def backup_plan(disk, mode, part_number):
    parts = disk.get('Partitions', [])
    if not parts:
        raise RuntimeError('來源磁碟沒有可辨識的 Partition。')
    if mode == 'Single Partition Backup':
        parts = [p for p in parts if int(p['Number']) == int(part_number)]
        if not parts:
            raise RuntimeError('所選 Partition 已不存在。')
    captures, skipped = [], []
    for p in parts:
        fs = str(p.get('FileSystem') or '').upper()
        letter = str(p.get('DriveLetter') or '').strip().rstrip(':')
        info = {'number': int(p['Number']), 'size': int(p['Size']),
                'offset': int(p.get('Offset', 0)),
                'partition_id': p.get('PartitionId', ''),
                'partition_type_guid': p.get('PartitionTypeGuid', ''),
                'type': p.get('Type', ''), 'filesystem': fs, 'drive_letter': letter,
                'volume_guid_path': p.get('VolumeGuidPath', '')}
        if fs in ('NTFS', 'FAT32') and (len(letter) == 1 and letter.isalpha() or info['volume_guid_path']):
            info['capture_root'] = letter + ':\\' if letter else info['volume_guid_path']
            captures.append(info)
        else:
            info['reason'] = '無支援的檔案系統或找不到可存取的磁碟代號 / Volume GUID 路徑'
            skipped.append(info)
    if mode == 'Single Partition Backup' and skipped:
        raise RuntimeError('此 Partition 無法以 DISM Capture-Image 備份：' + skipped[0]['reason'])
    if not captures:
        raise RuntimeError('找不到可備份的 NTFS / FAT32 磁區。')
    return captures, skipped


def run_backup(disk, mode, part_number, destination, name, progress, cancel_event=None, runtime=None):
    """WinPE only. Captures file-based images, never promises sector-complete backup."""
    if not is_winpe():
        raise RuntimeError('安全限制：真正的備份只能在 WinPE 執行。')
    if not shutil.which('dism.exe'):
        raise RuntimeError('找不到 dism.exe。')
    source_number = int(disk['Number'])
    captures, skipped = backup_plan(disk, mode, part_number)
    # GPT MSR is a structural reservation, not a filesystem image.
    # All other uncapturable partitions remain hard blockers for Full Disk Backup.
    structural = [p for p in skipped if p.get('type') == 'Reserved'
                  and str(disk.get('PartitionStyle', '')).upper() == 'GPT'
                  and str(p.get('partition_type_guid', '')).lower() == 'e3c9e316-0b5c-4db8-817d-f92df00215ae']
    unsupported = [p for p in skipped if p not in structural]
    if mode == 'Full Disk Backup' and unsupported:
        reasons = '; '.join('Partition %s: %s' % (x['number'], x['reason']) for x in unsupported)
        raise RuntimeError('Full Disk Backup 存在無法擷取的磁區，已停止：' + reasons)
    if not os.path.isdir(destination):
        raise RuntimeError('備份目的地不存在。')
    if volume_filesystem(destination) == 'FAT32':
        raise RuntimeError('目的地為 FAT32，單一 WIM 可能超過 4GB；本版尚未支援 SWM 分割，請選擇 NTFS 目的地。')
    if disk_for_path(destination) == source_number:
        raise RuntimeError('備份目的地不能位於來源實體磁碟。')
    # X: is WinPE's RAM disk and is not a physical source disk.
    tool_path = os.path.abspath(__file__)
    if os.path.splitdrive(tool_path)[0].upper() != 'X:':
        if disk_for_path(tool_path) == source_number:
            raise RuntimeError('禁止備份程式所在實體磁碟，請改用另一顆磁碟。')
    system_drive = os.environ.get('SystemDrive', 'X:').upper()
    if system_drive != 'X:':
        if disk_for_path(system_drive + '\\') == source_number:
            raise RuntimeError('禁止備份 WinPE 系統所在磁碟。')
    name = safe_backup_name(name)
    folder = os.path.join(destination, name)
    if os.path.lexists(folder):
        raise RuntimeError('同名備份資料夾已存在，請使用其他名稱。')
    # WIM captures used files rather than the full partition capacity.
    # Do not reject a destination solely because its free space is less than
    # the sum of the source partition sizes. Compression ratio is unknown.
    usage = shutil.disk_usage(destination)
    if usage.free < 512 * 1024 * 1024:
        raise RuntimeError('目的地剩餘空間不足 512 MB，無法安全開始備份。')
    used_estimates = []
    for part in captures:
        try:
            # GetDiskFreeSpaceExW works for both drive letters and volume GUID roots.
            # shutil.disk_usage uses this Windows API internally.
            source_usage = shutil.disk_usage(part['capture_root'])
            used_estimates.append(max(0, source_usage.total - source_usage.free))
        except (OSError, ValueError):
            used_estimates = []
            break
    estimated_used = sum(used_estimates) if len(used_estimates) == len(captures) else None
    free_gb = usage.free / (1024 ** 3)
    if estimated_used is None:
        progress('目的地可用空間 %.1f GiB；來源使用量無法讀取，備份容量無法預估。' % free_gb)
    else:
        used_gb = estimated_used / (1024 ** 3)
        progress('來源磁區已使用約 %.1f GiB；目的地可用 %.1f GiB（WIM 實際大小取決於壓縮率）。' % (used_gb, free_gb))
        if usage.free < estimated_used:
            progress('注意：目的地可用空間低於來源已使用量，可能因壓縮而足夠，也可能在備份途中耗盡。')
    # Re-read inventory immediately before work. Refuse if identity/partition layout changed.
    fresh = next((d for d in scan_disks() if int(d['Number']) == source_number), None)
    if not fresh or fresh.get('Model') != disk.get('Model') or int(fresh['Size']) != int(disk['Size']) or _layout_hash(_layout_snapshot(fresh)) != _layout_hash(_layout_snapshot(disk)):
        raise RuntimeError('來源磁碟資訊已改變，請重新掃描。')
    fresh_parts = {int(p['Number']): p for p in fresh.get('Partitions', [])}
    for p in captures:
        q = fresh_parts.get(p['number'])
        if (not q or int(q['Size']) != p['size']
                or int(q.get('Offset', -1)) != p['offset']
                or q.get('PartitionId', '') != p['partition_id']
                or q.get('PartitionTypeGuid', '') != p['partition_type_guid']
                or str(q.get('DriveLetter') or '').strip().rstrip(':').upper() != p['drive_letter'].upper()
                or q.get('VolumeGuidPath', '') != p['volume_guid_path']):
            raise RuntimeError('Partition 配置已改變，請重新掃描。')
    for p in captures:
        if not os.path.isdir(p['capture_root']):
            raise RuntimeError('Partition %d 的來源路徑無法存取：%s' % (p['number'], p['capture_root']))
    if cancel_event is not None and cancel_event.is_set():
        raise RuntimeError('使用者已取消備份（尚未開始擷取）。')
    os.mkdir(folder)
    if runtime is not None:
        runtime['folder'] = folder
    log_path = os.path.join(folder, 'Backup.log')
    metadata_path = os.path.join(folder, 'BackupInfo.json')
    layout_snapshot = _layout_snapshot(fresh)
    metadata = {'schema_version': 3, 'tool_version': APP_VERSION, 'status': 'in_progress',
                'mode': mode, 'created_at': datetime.now().astimezone().isoformat(),
                'disk': {'number': source_number, 'model': disk['Model'], 'size': int(disk['Size']),
                         'partition_style': disk.get('PartitionStyle'), 'bus_type': disk.get('BusType'),
                         'disk_identity': disk.get('DiskIdentity', {})},
                'partition_layout': disk.get('Partitions', []),
                'restore_layout': layout_snapshot, 'restore_layout_sha256': _layout_hash(layout_snapshot),
                'restore_engine_implemented': False,
                'capacity_precheck': {'destination_free_bytes': usage.free,
                                      'source_used_estimate_bytes': estimated_used,
                                      'estimate_is_not_wim_size': True},
                'captures': [], 'skipped_partitions': unsupported,
                'structural_partitions': [{**p, 'handling': 'layout_only_msr_no_wim'} for p in structural],
                'partition_layout_contains_offsets_and_gpt_ids': True,
                'required_boot_partitions_not_yet_captured': [
                    {'number': p['Number'], 'type': p['Type']}
                    for p in disk.get('Partitions', [])
                    if p.get('Type') in ('System', 'Recovery')
                    and int(p['Number']) not in {c['number'] for c in captures}],
                'is_complete_disk_image': False,
                'note': 'DISM 為檔案層級 WIM；未包含 MBR/GPT 原始磁區、未配置空間或跳過的 Partition。'}
    def save_metadata():
        _atomic_json(metadata_path, metadata)
    save_metadata()
    try:
        with open(log_path, 'w', encoding='utf-8') as log:
            for idx, p in enumerate(captures, 1):
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError('使用者已取消備份。')
                if runtime is not None:
                    runtime.update({'partition': p['number'], 'index': idx, 'total': len(captures), 'stage': '擷取中', 'image': 'Partition_%d.wim' % p['number'], 'partition_started': time.monotonic()})
                image = 'Partition_%d.wim' % p['number']
                path = os.path.join(folder, image)
                command = ['dism.exe', '/Capture-Image', '/ImageFile:' + path,
                           '/CaptureDir:' + p['capture_root'],
                           '/Name:Partition_%d' % p['number'], '/Compress:fast', '/CheckIntegrity']
                progress('正在備份 Partition %d（%d/%d）' % (p['number'], idx, len(captures)))
                log.write('COMMAND: ' + subprocess.list2cmdline(command) + '\n')
                log.flush()
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError('使用者已取消備份。')
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                           creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                if runtime is not None:
                    runtime['process'] = process
                try:
                    # stdout may not emit a newline for each DISM percentage update.
                    # A separate GUI timer monitors WIM bytes; this loop preserves logs.
                    for line in iter(process.stdout.readline, b''):
                        log.write(line.decode('utf-8', 'replace'))
                        log.flush()
                    code = process.wait()
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait()
                    if runtime is not None:
                        runtime['process'] = None
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError('使用者已取消備份；未完成的 WIM 不可用於還原。')
                log.write('EXIT CODE: %d\n' % code)
                log.flush()
                if code != 0:
                    raise RuntimeError('Partition %d DISM 備份失敗，Exit Code %d，詳見 Backup.log。' % (p['number'], code))
                # Validate that DISM can open the newly created WIM image.
                verify = ['dism.exe', '/Get-WimInfo', '/WimFile:' + path]
                if runtime is not None:
                    runtime['stage'] = '檢查映像'
                progress('正在檢查 Partition %d 的 WIM 映像…' % p['number'])
                log.write('VERIFY COMMAND: ' + subprocess.list2cmdline(verify) + '\n')
                log.flush()
                with subprocess.Popen(verify, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as check:
                    for line in iter(check.stdout.readline, b''):
                        log.write(line.decode('utf-8', 'replace'))
                    verify_code = check.wait()
                log.write('VERIFY EXIT CODE: %d\n' % verify_code)
                log.flush()
                if verify_code != 0 or not os.path.isfile(path) or os.path.getsize(path) == 0:
                    raise RuntimeError('Partition %d WIM 映像檢查失敗，詳見 Backup.log。' % p['number'])
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError('使用者已取消備份。')
                if runtime is not None:
                    runtime['stage'] = '計算 SHA-256'
                progress('正在計算 Partition %d 映像 SHA-256…' % p['number'])
                image_sha256 = _sha256_file(path)
                metadata['captures'].append({**p, 'image_file': image, 'image_sha256': image_sha256,
                                             'dism_exit_code': code,
                                             'wim_info_exit_code': verify_code,
                                             'image_size_bytes': os.path.getsize(path)})
                save_metadata()
                if runtime is not None:
                    runtime['completed'] = idx
        metadata['status'] = 'completed_partial' if unsupported else 'completed_file_level'
        metadata['bootable_restore_verified'] = False
        save_metadata()
        return folder, len(captures), len(unsupported)
    except Exception as exc:
        metadata['status'] = 'cancelled' if cancel_event is not None and cancel_event.is_set() else 'failed'
        metadata['error'] = str(exc)
        save_metadata()
        raise RuntimeError(str(exc) + '\n未完成的檔案保留在：' + folder) from exc



def restore_preflight(backup_folder, target_disk, progress):
    """Read-only validation. No disk writes, no DISM Apply, no DiskPart."""
    if not os.path.isdir(backup_folder):
        raise RuntimeError('請選擇有效的備份資料夾。')
    metadata_file = os.path.join(backup_folder, 'BackupInfo.json')
    with open(metadata_file, 'r', encoding='utf-8') as f:
        info = json.load(f)
    if not isinstance(info, dict) or info.get('schema_version') != 3:
        raise RuntimeError('BackupInfo.json 格式不支援（需要 schema_version 3）。')
    if info.get('status') not in ('completed_file_level', 'completed_partial'):
        raise RuntimeError('備份狀態不是已完成，拒絕進行還原準備。')
    layout = info.get('restore_layout')
    if not isinstance(layout, dict) or not isinstance(layout.get('partitions'), list):
        raise RuntimeError('備份缺少有效的 Partition Layout。')
    if info.get('restore_layout_sha256') != _layout_hash(layout):
        raise RuntimeError('Partition Layout SHA-256 不符，Metadata 可能遭到修改。')
    captures = info.get('captures')
    if not isinstance(captures, list) or not captures:
        raise RuntimeError('沒有可供還原的 WIM 映像。')
    partition_numbers = {int(x['number']) for x in layout['partitions']}
    seen = set()
    for idx, capture in enumerate(captures, 1):
        number = int(capture['number'])
        if number in seen or number not in partition_numbers:
            raise RuntimeError('WIM Partition Number 重複或不在備份配置內。')
        seen.add(number)
        filename = capture.get('image_file', '')
        if (not isinstance(filename, str) or not filename or
                filename != os.path.basename(filename) or
                filename in ('.', '..') or '/' in filename or '\\' in filename):
            raise RuntimeError('備份映像檔名不安全。')
        image_path = os.path.join(backup_folder, filename)
        if os.path.islink(image_path) or not os.path.isfile(image_path):
            raise RuntimeError('找不到映像檔：' + filename)
        expected_size = capture.get('image_size_bytes')
        if type(expected_size) is not int or os.path.getsize(image_path) != expected_size:
            raise RuntimeError('映像檔大小不符：' + filename)
        expected_hash = capture.get('image_sha256', '')
        if not isinstance(expected_hash, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', expected_hash):
            raise RuntimeError('映像檔缺少有效 SHA-256：' + filename)
        progress('正在檢查 WIM SHA-256（%d/%d）：%s' % (idx, len(captures), filename))
        if _sha256_file(image_path).lower() != expected_hash.lower():
            raise RuntimeError('映像檔 SHA-256 不符：' + filename)
    progress('正在重新確認目標磁碟…')
    number = int(target_disk['Number'])
    fresh = next((d for d in scan_disks() if int(d['Number']) == number), None)
    if not fresh or _layout_hash(_layout_snapshot(fresh)) != _layout_hash(_layout_snapshot(target_disk)):
        raise RuntimeError('目標磁碟資訊已變更，請重新掃描。')
    source_size = int(layout['disk_size_bytes'])
    target_size = int(fresh['Size'])
    source_style = layout.get('partition_style', '')
    target_style = fresh.get('PartitionStyle', '')
    skipped = info.get('skipped_partitions', [])
    structural = info.get('structural_partitions', [])
    boot_missing = info.get('required_boot_partitions_not_yet_captured', [])
    warnings = []
    if target_size < source_size:
        try:
            planned, _ = calculate_shrink_layout(layout['partitions'], source_size, target_size)
            win = planned[2]['size_bytes'] // (1024**3)
            warnings.append('縮容實驗模式：Windows 目標磁區約 %d GiB。注意：尚無可靠的 WIM 解壓後容量驗證，資料超出容量會使 DISM 失敗。' % win)
        except LayoutError as exc:
            warnings.append('縮容配置不可用：' + str(exc))
    if target_style != source_style:
        warnings.append('目標磁碟目前為 %s；Full Disk Restore 將在確認後清除並重建成 %s。' % (target_style, source_style))
    if skipped:
        warnings.append('部分磁區未備份：%d 個。' % len(skipped))
    if structural:
        warnings.append('MSR 等結構性磁區僅記錄分割配置，未產生 WIM：%d 個。' % len(structural))
    if boot_missing:
        warnings.append('必要開機/Recovery 磁區可能缺失：%d 個。' % len(boot_missing))
    # Read-only safety gate: a failed/ambiguous path resolution is BLOCKED,
    # never interpreted as permission to overwrite a disk.
    blockers = []
    protected = {}
    locations = {
        '備份映像所在磁碟': backup_folder,
        'Tool 所在磁碟': os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__),
        'WinPE/Windows 系統所在磁碟': os.environ.get('SystemRoot', r'C:\\Windows'),
    }
    for label, path in locations.items():
        if os.path.splitdrive(os.path.abspath(path))[0].upper() == 'X:':
            protected[label] = 'X: (WinPE RAM Disk)'
            continue
        try:
            disk_no = disk_for_path(path)
            protected[label] = disk_no
            if disk_no == number:
                blockers.append('目標 Disk %s 與%s相同，禁止破壞性還原。' % (number, label))
        except Exception as error:
            protected[label] = '無法判定'
            blockers.append('%s無法可靠辨識：%s' % (label, error))
    if target_size < source_size:
        try:
            calculate_shrink_layout(layout['partitions'], source_size, target_size)
        except LayoutError as exc:
            blockers.append('縮容配置不可用：' + str(exc))
    if source_style != 'GPT' or target_style not in ('GPT', 'RAW', 'MBR'):
        blockers.append('目前僅支援 GPT 備份還原至 GPT/RAW/MBR 目標磁碟。')
    if skipped or boot_missing:
        blockers.append('備份缺少部分磁區或必要開機磁區，不能宣稱完整還原。')
    if structural:
        warnings.append('Restore 時需重建 MSR；MSR 沒有 WIM 屬於正常情況。')
    # v0.21.2: include boot-media protection in the read-only preflight.
    boot_protected, safety_errors = protected_disks(scan_disks(), backup_folder, disk_for_path, is_winpe())
    for disk_no, reasons in boot_protected.items():
        protected['Disk %s' % disk_no] = '、'.join(reasons)
        if disk_no == number:
            blockers.append('目標磁碟受保護：' + '、'.join(reasons))
    blockers.extend(safety_errors)
    # Preview mapping only. This never assigns a write destination.
    source_partitions = sorted(layout['partitions'], key=lambda p: (int(p['offset_bytes']), int(p['number'])))
    target_partitions = sorted(fresh.get('Partitions', []), key=lambda p: (int(p.get('Offset', 0)), int(p['Number'])))
    mappings = []
    for part in source_partitions:
        matches = [q for q in target_partitions
                   if int(q.get('Offset', -1)) == int(part['offset_bytes'])
                   and int(q.get('Size', -1)) == int(part['size_bytes'])
                   and str(q.get('PartitionTypeGuid', '')).lower() == str(part.get('partition_type_guid', '')).lower()]
        mappings.append({'source_partition': int(part['number']),
                         'image_available': int(part['number']) in seen,
                         'target_partition': int(matches[0]['Number']) if len(matches) == 1 else None,
                         'match_status': 'exact-layout' if len(matches) == 1 else 'unmatched-or-ambiguous'})
    if any(m['match_status'] != 'exact-layout' for m in mappings):
        warnings.append('目標磁區與備份配置不同；Full Disk Restore 必須先安全重建分割配置。')
    # Full restore is guarded separately and requires explicit confirmation.
    warnings.append('此備份為檔案層級 WIM，並非逐扇區完整磁碟映像。')
    warnings.append('本版僅檢查還原準備狀態，開機可還原性尚未驗證。')
    return {'source': info.get('disk', {}), 'source_size': source_size,
            'source_style': source_style, 'target': fresh, 'captures': captures,
            'skipped': skipped, 'structural': structural, 'warnings': warnings, 'status': info['status'],
            'protected_disks': protected, 'blockers': blockers, 'partition_mapping': mappings}


def capacity(value):
    return f'{float(value) / 1e9:,.1f} GB'



def validate_partition_restore(folder, capture, disk, partition):
    """Fail closed. Restore only to an existing, empty, local NTFS data partition."""
    if not is_winpe():
        raise RuntimeError('只允許在 WinPE 還原。')
    if not shutil.which('dism.exe'):
        raise RuntimeError('找不到 DISM。')
    if not os.path.isdir(folder):
        raise RuntimeError('備份資料夾不存在。')
    with open(os.path.join(folder, 'BackupInfo.json'), encoding='utf-8') as stream:
        info = json.load(stream)
    if info.get('schema_version') != 3 or info.get('status') not in ('completed_file_level', 'completed_partial'):
        raise RuntimeError('BackupInfo.json 格式或備份狀態不符合。')
    layout = info.get('restore_layout')
    if not isinstance(layout, dict) or info.get('restore_layout_sha256') != _layout_hash(layout):
        raise RuntimeError('備份磁碟配置雜湊驗證失敗。')
    found = [x for x in info.get('captures', []) if int(x['number']) == int(capture['number'])]
    if len(found) != 1 or found[0] != capture:
        raise RuntimeError('來源磁區與 BackupInfo.json 不一致。')
    if capture.get('filesystem', '').upper() != 'NTFS':
        raise RuntimeError('初版僅支援 NTFS WIM 還原。')
    filename = capture.get('image_file')
    if not isinstance(filename, str) or not filename.lower().endswith('.wim') or filename != os.path.basename(filename):
        raise RuntimeError('WIM 檔名無效。')
    image_path = os.path.join(folder, filename)
    if os.path.islink(image_path) or not os.path.isfile(image_path):
        raise RuntimeError('WIM 不存在或為連結。')
    if os.path.getsize(image_path) != capture.get('image_size_bytes'):
        raise RuntimeError('WIM 大小驗證失敗。')
    if _sha256_file(image_path).lower() != str(capture.get('image_sha256', '')).lower():
        raise RuntimeError('WIM SHA-256 驗證失敗。')
    fresh = next((d for d in scan_disks() if int(d['Number']) == int(disk['Number'])), None)
    if not fresh or _layout_hash(_layout_snapshot(fresh)) != _layout_hash(_layout_snapshot(disk)):
        raise RuntimeError('目標磁碟配置已變動，請重新掃描。')
    matches = [x for x in fresh.get('Partitions', []) if int(x['Number']) == int(partition['Number'])]
    if len(matches) != 1 or matches[0] != partition:
        raise RuntimeError('目標 Partition 已變更。')
    target = matches[0]
    if target.get('Type') not in ('Basic', 'MBR 0x07'):
        raise RuntimeError('禁止寫入 EFI、Recovery、MSR 或未知類型磁區。')
    if str(target.get('FileSystem') or '').upper() != 'NTFS':
        raise RuntimeError('目標 Partition 必須是 NTFS。')
    letter = str(target.get('DriveLetter') or '').rstrip(':').upper()
    if len(letter) != 1 or not letter.isalpha() or letter == 'X':
        raise RuntimeError('目標 Partition 必須有非 X: 的磁碟代號。')
    root = letter + ':\\'
    if disk_for_path(root) != int(fresh['Number']):
        raise RuntimeError('目標磁區磁碟代號無法正確對應。')
    if int(target['Size']) < int(capture['size']):
        raise RuntimeError('目標磁區小於來源磁區；目前不支援縮容還原。')
    # Prevent accidental writes to the tool, image, and OS physical disks.
    protected_paths = [('備份資料夾', folder),
                       ('程式執行位置', os.path.abspath(sys.executable if getattr(sys, 'frozen', False) else __file__)),
                       ('WinPE 系統', os.environ.get('SystemRoot', r'X:\Windows'))]
    for label, path in protected_paths:
        drive = os.path.splitdrive(os.path.abspath(path))[0].upper()
        if drive == 'X:' and label in ('WinPE 系統', '程式執行位置') and is_winpe():
            continue  # WinPE X: RAM disk, not a physical SSD.
        if disk_for_path(path) == int(fresh['Number']):
            raise RuntimeError('目標與%s位於同一實體磁碟，禁止還原。' % label)
    if os.path.islink(root):
        raise RuntimeError('目標磁區路徑不可為連結。')
    # Do not overlay a populated partition; never format or delete here.
    with os.scandir(root) as entries:
        if next(entries, None) is not None:
            raise RuntimeError('目標磁區不是空白的。為避免覆蓋資料，拒絕還原。')
    return capture, fresh, target, root


def apply_single_partition(folder, capture, disk, partition, progress):
    # Revalidate after confirmation, immediately before DISM.
    source, fresh, target, root = validate_partition_restore(folder, capture, disk, partition)
    image_path = os.path.join(folder, source['image_file'])
    log_path = os.path.join(folder, 'Restore_%s.log' % datetime.now().strftime('%Y%m%d_%H%M%S'))
    command = ['dism.exe', '/Apply-Image', '/ImageFile:' + image_path,
               '/Index:1', '/ApplyDir:' + root, '/CheckIntegrity']
    progress('正在套用 WIM 至 Disk %s / Partition %s' % (fresh['Number'], target['Number']))
    with open(log_path, 'w', encoding='utf-8') as log:
        log.write('TARGET DISK: %s\nTARGET PARTITION: %s\nTARGET ROOT: %s\n' %
                  (fresh['Number'], target['Number'], root))
        log.write('COMMAND: ' + subprocess.list2cmdline(command) + '\n')
        log.flush()
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)) as proc:
            for raw in iter(proc.stdout.readline, b''):
                log.write(raw.decode('utf-8', 'replace'))
                log.flush()
            code = proc.wait()
        log.write('\nEXIT CODE: %s\n' % code)
    if code != 0:
        raise RuntimeError('DISM 還原失敗，Exit Code: %s。目標磁區可能已部分寫入；Log：%s' % (code, log_path))
    return log_path


class DiskTool(tk.Tk):
    def __init__(self):
        load_private_fonts()
        super().__init__()
        self.chinese_font, self.tk_font_status = resolve_tk_family(self)
        self.title(APP_NAME + ' - WinPE')
        self._fit_window(1180, 780, min_width=720, min_height=500)
        self._last_layout_mode = None
        self._base_font_specs = {}
        self._resize_pending = None
        self.bind('<Configure>', self._responsive_layout, add='+')
        self.configure(bg=BG)
        self.active = 'Backup'
        self.nav_buttons = {}
        self.disks = []
        self.scanning = False
        self.scan_progress = None
        self.scan_status = None
        self.scan_button = None
        self.restore_check_running = False
        self.restore_folder = ''
        self.restore_status = None
        self.restore_result = None
        self.restore_detail_frame = None
        self.restore_detail_button = None
        self.restore_progress_bar = None
        self.restore_summary = None
        self.backup_detail_frame = None
        self.backup_detail_button = None
        self.backup_detail_text = None
        self.restore_check_button = None
        self.restore_apply_button = None
        self.restore_running = False
        self.restore_started_at = None
        self.restore_source_combo = None
        self.restore_target_combo = None
        self.restore_candidates = []
        self.restore_target_parts = []
        self.backup_running = False
        self.backup_cancel_event = threading.Event()
        self.backup_runtime = {}
        self.backup_started_at = None
        self.backup_last_bytes = 0
        self.backup_last_tick = None
        self.backup_status = None
        self.backup_button = None
        self.backup_progress = None
        self.backup_mode = 'Full Disk Backup'
        self.backup_disk_number = None
        self.backup_partition_number = None
        self.backup_destination = ''
        self.backup_name = 'Backup_' + datetime.now().strftime('%Y%m%d_%H%M%S')
        self.backup_partition_combo = None
        self.backup_mode_combo = None
        self.backup_name_var = None
        self.backup_dest_var = None
        self.driver_loading = False
        self.driver_source = tk.StringVar(value=str(exe_directory() / 'Drivers'))
        self.driver_mode = tk.StringVar(value='folder')
        self.driver_status_var = tk.StringVar(value='尚未載入 Driver')
        self.driver_log_text = None
        self.driver_load_button = None
        self._layout()
        self.protocol('WM_DELETE_WINDOW', self._on_app_close)
        self.show_page('Backup')
        self.after(100, self._responsive_layout)
        self.after(200, self._auto_load_drivers)
        self.after(900, self._initial_disk_scan)

    def _fit_window(self, preferred_width, preferred_height, min_width=640, min_height=460):
        """Fit inside the actual desktop work area, including low-resolution WinPE."""
        self.update_idletasks()
        screen_w = max(1, self.winfo_screenwidth())
        screen_h = max(1, self.winfo_screenheight())
        width = min(max(preferred_width, round(screen_w * 0.85)), max(400, screen_w - 36))
        height = min(max(preferred_height, round(screen_h * 0.85)), max(320, screen_h - 72))
        self.geometry('%dx%d+%d+%d' % (width, height,
            max(0, (screen_w - width)//2), max(0, (screen_h - height)//2)))
        self.minsize(min(min_width, width), min(min_height, height))

    def _responsive_layout(self, event=None):
        if event is not None and event.widget is not self:
            return
        if not hasattr(self, 'sidebar'):
            return
        # Reflow on every resize, but debounce to avoid repeated expensive font work.
        if self._resize_pending is not None:
            self.after_cancel(self._resize_pending)
        self._resize_pending = self.after(65, self._apply_responsive_layout)

    def _apply_responsive_layout(self):
        from tkinter import font as tkfont
        self._resize_pending = None
        w, h = self.winfo_width(), self.winfo_height()
        if w < 2 or h < 2:
            return
        # Window width drives font size, height drives vertical spacing.
        factor = 0.80 * min(1.0, max(0.65, w / 1120.0))
        if h < 650:
            factor = min(factor, 0.80 * max(0.65, h / 800.0))
        tight = h < 680 or w < 950
        # Scale from the ORIGINAL font spec; never repeatedly scale a scaled font.
        self._scale_widget_fonts(self, factor)
        self._scale_ttk_fonts(factor)
        # Sidebar is measured against its actual text, not an arbitrary width.
        widest = 0
        for key, btn in self.nav_buttons.items():
            btn.configure(text=key, padx=7 if tight else 12,
                          pady=4 if tight else 10)
            btn.pack_configure(padx=4 if tight else 8, pady=1 if tight else 3)
            try:
                f = tkfont.Font(root=self, font=btn.cget('font'))
                widest = max(widest, f.measure(key))
            except tk.TclError:
                widest = max(widest, 130)
        sidebar_width = max(155, widest + (38 if tight else 60))
        self.sidebar.configure(width=sidebar_width)
        self.sidebar_title.configure(padx=7 if tight else 12,
                                     pady=6 if tight else 14)
        self.header.configure(padx=8 if tight else 20, pady=5 if tight else 15)
        self.body.pack_configure(padx=5 if tight else 16,
                                 pady=(0, 3 if tight else 10))
        self.sidebar.pack_configure(padx=(0, 5 if tight else 12))
        self.footer.configure(padx=8 if tight else 20, pady=2 if tight else 7)
        self.header_subtitle.pack_forget()
        if w >= 1350:
            self.header_subtitle.pack(side='right')
        self._adapt_page_spacing(tight)
        self.page_canvas.configure(scrollregion=self.page_canvas.bbox('all'))

    def _scale_widget_fonts(self, root, factor):
        from tkinter import font as tkfont
        stack = [root]
        while stack:
            widget = stack.pop()
            try:
                stack.extend(widget.winfo_children())
                spec = widget.cget('font')
            except (tk.TclError, AttributeError):
                continue
            if not spec:
                continue
            try:
                if widget not in self._base_font_specs:
                    f = tkfont.Font(root=self, font=spec)
                    self._base_font_specs[widget] = (f.actual('family'),
                        abs(int(f.actual('size'))), f.actual('weight'))
                family, original, weight = self._base_font_specs[widget]
                size = max(8, round(original * factor))
                widget.configure(font=(family, size, weight))
            except (tk.TclError, TypeError, ValueError):
                continue
        # Forget destroyed widgets, so repeated page switching does not leak refs.
        self._base_font_specs = {widget: val for widget, val in self._base_font_specs.items()
                                 if widget.winfo_exists()}

    def _scale_ttk_fonts(self, factor):
        from tkinter import font as tkfont
        if not hasattr(self, '_ttk_font_original'):
            self._ttk_font_original = (self.chinese_font, 12)
        style = ttk.Style(self)
        style.configure('Responsive.TCombobox',
            font=(self._ttk_font_original[0], max(8, round(self._ttk_font_original[1] * factor))))
        for widget in self._walk_widgets(self):
            if isinstance(widget, ttk.Combobox):
                try:
                    widget.configure(style='Responsive.TCombobox',
                                     font=(self.chinese_font, max(8, round(12 * factor))))
                except tk.TclError:
                    pass

    def _walk_widgets(self, root):
        stack = [root]
        while stack:
            widget = stack.pop()
            yield widget
            try:
                stack.extend(widget.winfo_children())
            except tk.TclError:
                pass

    def _adapt_page_spacing(self, tight):
        if not hasattr(self, 'content'):
            return
        try:
            for child in self.content.winfo_children():
                if child.winfo_manager() != 'pack':
                    continue
                if isinstance(child, tk.Label):
                    child.pack_configure(padx=8 if tight else 22,
                                         pady=(5, 2) if tight else (16, 6))
                elif isinstance(child, tk.Frame):
                    child.pack_configure(padx=7 if tight else 20)
                    for row in child.winfo_children():
                        if isinstance(row, tk.Frame) and row.winfo_manager() == 'pack':
                            row.pack_configure(pady=2 if tight else 6)
                            for control in row.winfo_children():
                                if isinstance(control, ttk.Combobox):
                                    control.configure(width=16 if tight else 36)
        except tk.TclError:
            pass

    def _layout(self):
        header = tk.Frame(self, bg=BG, padx=24, pady=18)
        self.header = header
        header.pack(fill='x')
        tk.Label(header, text=APP_NAME, font=(self.chinese_font, 25, 'bold'), bg=BG, fg=TEXT).pack(side='left')
        self.header_subtitle = tk.Label(header, text='Portable Backup & Restore  |  WinPE Backup', font=(self.chinese_font, 12), bg=BG, fg=MUTED)
        if self.winfo_screenwidth() >= 1250:
            self.header_subtitle.pack(side='right')
        body = tk.Frame(self, bg=BG)
        self.body = body
        body.pack(fill='both', expand=True, padx=20, pady=(0, 12))
        sidebar = tk.Frame(body, bg=PANEL, width=245)
        self.sidebar = sidebar
        sidebar.pack(side='left', fill='y', padx=(0, 12))
        sidebar.pack_propagate(False)
        self.sidebar_title = tk.Label(sidebar, text='功能選單', font=(self.chinese_font, 13, 'bold'), bg=PANEL, fg=MUTED, anchor='w', padx=16, pady=18)
        self.sidebar_title.pack(fill='x')
        for name in ('Backup', 'Restore', 'Driver Manager', 'System / Logs'):
            btn = tk.Button(sidebar, text=name, anchor='w', padx=16, pady=13, relief='flat', bd=0,
                            font=(self.chinese_font, 13), bg=PANEL, fg=TEXT, activebackground=CARD,
                            activeforeground=TEXT, cursor='hand2', command=lambda n=name: self.show_page(n))
            btn.pack(fill='x', padx=8, pady=3)
            self.nav_buttons[name] = btn
        # Scrollable right-side page; sidebar/header/footer stay fixed.
        content_host = tk.Frame(body, bg=PANEL)
        content_host.pack(side='left', fill='both', expand=True)
        self.page_canvas = tk.Canvas(content_host, bg=PANEL, highlightthickness=0, bd=0)
        self.page_scrollbar = tk.Scrollbar(content_host, orient='vertical',
                                            command=self.page_canvas.yview)
        self.page_canvas.configure(yscrollcommand=self.page_scrollbar.set)
        self.page_scrollbar.pack(side='right', fill='y')
        self.page_canvas.pack(side='left', fill='both', expand=True)
        self.content = tk.Frame(self.page_canvas, bg=PANEL)
        self.page_window = self.page_canvas.create_window((0, 0), window=self.content,
                                                          anchor='nw')
        self.content.bind('<Configure>', self._update_page_scrollregion)
        self.page_canvas.bind('<Configure>', self._resize_page_width)
        self.bind_all('<MouseWheel>', self._page_mousewheel, add='+')
        self.bind_all('<Button-4>', self._page_mousewheel, add='+')
        self.bind_all('<Button-5>', self._page_mousewheel, add='+')
        footer = tk.Frame(self, bg=BG, padx=24, pady=10)
        self.footer = footer
        footer.pack(fill='x')
        tk.Label(footer, text=f'Version {APP_VERSION}', bg=BG, fg=MUTED).pack(side='left')
        if self.winfo_screenwidth() >= 1250:
            tk.Label(footer, text='WinPE Backup  |  Full Disk Restore: in development', bg=BG, fg=MUTED).pack(side='right')

    def _update_page_scrollregion(self, event=None):
        self.page_canvas.configure(scrollregion=self.page_canvas.bbox('all'))

    def _resize_page_width(self, event):
        self.page_canvas.itemconfigure(self.page_window, width=event.width)

    def _page_mousewheel(self, event):
        # Only scroll when the pointer is over the right-hand page.
        widget = self.winfo_containing(event.x_root, event.y_root)
        current = widget
        inside = False
        while current is not None:
            if current is self.page_canvas or current is self.content:
                inside = True
                break
            current = getattr(current, 'master', None)
        if not inside:
            return
        # Preserve native scrolling inside text boxes and dropdowns.
        if isinstance(widget, (tk.Text, tk.Listbox, tk.Spinbox, ttk.Combobox)):
            return
        if self.page_canvas.bbox('all') is None:
            return
        if event.num == 4:
            steps = -3
        elif event.num == 5:
            steps = 3
        else:
            steps = -int(event.delta / 120) if event.delta else 0
            if steps == 0 and event.delta:
                steps = -1 if event.delta > 0 else 1
        if steps:
            self.page_canvas.yview_scroll(steps, 'units')
            return 'break'

    def show_page(self, name):
        if self.driver_loading or (self.backup_running and name != 'Backup') or (self.restore_check_running and name != 'Restore') or (self.restore_running and name != 'Restore'):
            return
        self.page_canvas.yview_moveto(0)
        self.active = name
        for page, button in self.nav_buttons.items():
            button.configure(bg=CARD if page == name else PANEL)
        for child in self.content.winfo_children():
            child.destroy()
        tk.Label(self.content, text=name, font=(self.chinese_font, 23, 'bold'), bg=PANEL, fg=TEXT,
                 anchor='w').pack(fill='x', padx=28, pady=(28, 7))
        subtitles = {
            'Backup': '建立完整磁碟或單一磁區備份',
            'Restore': '從備份映像還原磁碟或磁區',
            'Driver Manager': '管理 WinPE 儲存裝置驅動程式',
            'System / Logs': '檢視環境資訊與操作紀錄'
        }
        tk.Label(self.content, text=subtitles[name], font=(self.chinese_font, 13),
                 bg=PANEL, fg=MUTED, anchor='w').pack(fill='x', padx=28, pady=(0, 25))
        panel = tk.Frame(self.content, bg=CARD, padx=22, pady=22)
        panel.pack(fill='x', padx=28)
        self.disk_selector = None
        self.backup_partition_combo = None
        self.disk_details = None
        self.restore_apply_button = None
        self.restore_source_combo = None
        self.restore_target_combo = None
        self.scan_progress = None
        self.scan_status = None
        self.scan_button = None
        if name == 'Backup':
            self._build_backup(panel)
        elif name == 'Restore':
            self._build_restore(panel)
        elif name == 'Driver Manager':
            self._build_driver_manager(panel)
        else:
            self._row(panel, '執行環境', ['Windows 11 開發模式（示意）'])
            self._disk_row(panel, '實體磁碟')
            tk.Button(panel, text='檢查 WinPE / 執行環境', command=self._show_environment_report,
                      font=(self.chinese_font, 13), padx=16, pady=9).pack(anchor='w', pady=(12, 4))
        if name == 'System / Logs':
            self._build_scan_controls(panel)
        if name in ('Backup', 'System / Logs'):
            tk.Label(panel, text='Backup 僅在 WinPE 執行。', bg=CARD, fg=MUTED, font=(self.chinese_font, 12), anchor='w').pack(fill='x', pady=(16, 8))
        self.bind('<F5>', lambda event: None if (self.backup_running or self.restore_running or self.restore_check_running) else self.refresh_disks())

        self._last_layout_mode = None
        self.after_idle(self._responsive_layout)

    def _build_driver_manager(self, panel):
        tk.Label(panel, text='啟動時自動掃描 EXE 同層 Drivers；也可手動指定資料夾或 INF。',
                 bg=CARD, fg=TEXT, font=(self.chinese_font, 12), wraplength=700,
                 justify='left').pack(anchor='w', pady=(0, 12))
        for value, label in [('folder', '選擇資料夾（包含所有子資料夾的 INF）'),
                             ('inf', '選擇單一 INF 檔案')]:
            tk.Radiobutton(panel, text=label, variable=self.driver_mode, value=value,
                           bg=CARD, fg=TEXT, selectcolor=PANEL, activebackground=CARD,
                           activeforeground=TEXT, font=(self.chinese_font, 12)).pack(anchor='w')
        path_row = tk.Frame(panel, bg=CARD)
        path_row.pack(fill='x', pady=(12, 8))
        tk.Entry(path_row, textvariable=self.driver_source, font=(self.chinese_font, 11)).pack(
            side='left', fill='x', expand=True, padx=(0, 8))
        tk.Button(path_row, text='瀏覽...', command=self._browse_driver_source,
                  font=(self.chinese_font, 11)).pack(side='left')
        self.driver_load_button = tk.Button(panel, text='載入 Driver', command=self._manual_load_drivers,
                                           font=(self.chinese_font, 12), padx=15, pady=8)
        self.driver_load_button.pack(anchor='w', pady=8)
        tk.Label(panel, textvariable=self.driver_status_var, bg=CARD, fg=TEXT,
                 font=(self.chinese_font, 11), wraplength=720, justify='left').pack(anchor='w', pady=8)
        self.driver_log_text = tk.Text(panel, height=12, bg=PANEL, fg=TEXT, wrap='word',
                                       font=(self.chinese_font, 10))
        self.driver_log_text.pack(fill='x', pady=8)

    def _browse_driver_source(self):
        if self.driver_loading or self.backup_running or self.restore_running or self.restore_check_running:
            return
        if self.driver_mode.get() == 'folder':
            folder = self._choose_folder('選擇 Driver 資料夾', self.driver_source.get())
            if folder:
                self.driver_source.set(folder)
        else:
            inf = self._choose_inf_file()
            if inf:
                self.driver_source.set(inf)

    def _choose_inf_file(self):
        """Use the same Explorer-style picker as Backup/Restore, showing INF files."""
        return self._choose_folder('選擇 Driver INF 檔案', self.driver_source.get(), selection_mode='inf')

    def _initial_disk_scan(self):
        if self.driver_loading:
            self.after(400, self._initial_disk_scan)
        elif not self.scanning:
            self.refresh_disks()

    def _auto_load_drivers(self):
        folder = exe_directory() / 'Drivers'
        if not folder.is_dir():
            self.driver_status_var.set('Drivers 資料夾不存在，自動略過。')
            return
        try:
            if not find_infs(folder):
                self.driver_status_var.set('Drivers 資料夾沒有 INF，自動略過。')
                return
        except OSError as exc:
            self.driver_status_var.set('Driver 掃描失敗：' + str(exc))
            return
        self._begin_driver_load(str(folder), single=False, automatic=True)

    def _manual_load_drivers(self):
        self._begin_driver_load(self.driver_source.get().strip(),
                                single=self.driver_mode.get() == 'inf', automatic=False)

    def _begin_driver_load(self, source, single=False, automatic=False):
        if self.driver_loading or self.backup_running or self.restore_running or self.restore_check_running or self.scanning:
            if not automatic:
                messagebox.showwarning('無法載入', '其他作業執行中，請完成後再載入 Driver。', parent=self)
            return
        try:
            infs = find_infs(source, single)
        except (OSError, ValueError) as exc:
            if not automatic:
                messagebox.showerror('Driver 路徑錯誤', str(exc), parent=self)
            self.driver_status_var.set(str(exc))
            return
        if not infs:
            self.driver_status_var.set('找不到 INF，未執行載入。')
            return
        if not is_winpe():
            self.driver_status_var.set('目前不是 WinPE；不會實際載入 Driver。')
            return
        self.driver_loading = True
        self.driver_status_var.set('正在載入 %d 個 INF…' % len(infs))
        for button in self.nav_buttons.values():
            button.configure(state='disabled')
        if self.driver_load_button:
            self.driver_load_button.configure(state='disabled')
        def notify(message):
            self.after(0, lambda msg=message: self._driver_log_line(msg))
        def worker():
            try:
                result = load_drivers(source, single=single, notify=notify)
                self.after(0, lambda r=result: self._driver_load_finished(r, None))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._driver_load_finished(None, e))
        threading.Thread(target=worker, daemon=True).start()

    def _driver_log_line(self, message):
        if self.driver_log_text is not None and self.driver_log_text.winfo_exists():
            self.driver_log_text.insert('end', message + '\n')
            self.driver_log_text.see('end')

    def _driver_load_finished(self, result, error):
        self.driver_loading = False
        for button in self.nav_buttons.values():
            button.configure(state='normal')
        if self.driver_load_button and self.driver_load_button.winfo_exists():
            self.driver_load_button.configure(state='normal')
        if error:
            self.driver_status_var.set('Driver 載入失敗：' + error)
            return
        self.driver_status_var.set('找到 {found} / 載入指令成功 {loaded} / 失敗 {failed} / 略過 {skipped}。Log：{log}。正在重新掃描磁碟…'.format(**result))
        self.refresh_disks()

    def _show_environment_report(self):
        try:
            report = collect_report() + '\nPortable font: ' + font_status() + '\nTk font: ' + self.tk_font_status + '\n'
            window = tk.Toplevel(self)
            window.title('WinPE / 執行環境檢查')
            window.geometry('820x480')
            window.configure(bg=BG)
            view = tk.Text(window, wrap='word', bg=PANEL, fg=TEXT,
                           font=(self.chinese_font, 11), padx=12, pady=12)
            view.pack(fill='both', expand=True, padx=12, pady=12)
            view.insert('1.0', report)
            view.configure(state='disabled')
        except Exception as exc:
            messagebox.showerror('環境檢查失敗', str(exc), parent=self)

    def _build_restore(self, panel):
        self.restore_mode_combo = self._row(panel, '還原模式',
            ['Full Disk Restore', 'Single Partition Restore'])
        self.restore_mode_combo.current(0)
        self.restore_mode_combo.bind('<<ComboboxSelected>>', self._on_restore_mode)
        frame = tk.Frame(panel, bg=CARD)
        frame.pack(fill='x', pady=8)
        tk.Label(frame, text='備份來源', width=12, anchor='w', bg=CARD, fg=TEXT,
                 font=(self.chinese_font, 13)).pack(side='left')
        self.restore_folder_var = tk.StringVar(value=self.restore_folder or '尚未選擇備份資料夾')
        tk.Entry(frame, textvariable=self.restore_folder_var, state='readonly',
                 font=(self.chinese_font, 12), readonlybackground=PANEL, fg=TEXT).pack(
                 side='left', fill='x', expand=True, padx=(12, 8))
        tk.Button(frame, text='瀏覽', command=self._browse_restore_folder,
                  font=(self.chinese_font, 11)).pack(side='left', padx=(0, 5))
        self._disk_row(panel, '目標磁碟')
        self._build_scan_controls(panel, include_details=False)
        self.restore_source_combo = self._row(panel, '來源 Partition', ['請先選擇備份資料夾'])
        self.restore_target_combo = self._row(panel, '目標 Partition', ['請先選擇目標磁碟'])
        self.restore_source_combo.bind('<<ComboboxSelected>>', lambda e: self._invalidate_restore_ready())
        self.restore_target_combo.bind('<<ComboboxSelected>>', lambda e: self._invalidate_restore_ready())
        self._populate_restore_choices()
        self.restore_check_button = None  # Internal validation only; no separate check UI.
        self.restore_apply_button = tk.Button(panel, text='開始 Full Disk Restore',
            command=self._start_restore_action, font=(self.chinese_font, 12),
            width=30, padx=12, pady=6, state='normal')
        self.restore_apply_button.pack(anchor='w', pady=(10, 7))
        self.restore_status = tk.Label(panel, text='實驗版：Full Disk Restore 將清除目標 SSD；請使用可清除的測試磁碟。',
                                       bg=CARD, fg=MUTED, font=(self.chinese_font, 11))
        self.restore_status.pack(anchor='w', pady=(2, 7))
        self.restore_progress_bar = ttk.Progressbar(panel, mode='determinate', maximum=100)
        self.restore_progress_bar.pack(fill='x', pady=(3, 6))
        self.restore_summary = tk.Label(panel, text='整體進度：尚未開始 | 已花時間：— | ETA：—',
                                        bg=CARD, fg=TEXT, font=(self.chinese_font, 11), anchor='w')
        self.restore_summary.pack(fill='x', pady=(0, 5))
        self.restore_detail_button = tk.Button(panel, text='顯示細節',
            command=lambda: self._toggle_details('restore'), font=(self.chinese_font, 11))
        self.restore_detail_button.pack(anchor='w', pady=(2, 4))
        self.restore_detail_frame = tk.Frame(panel, bg=CARD)
        self.restore_result = tk.Text(self.restore_detail_frame, height=13, bg=PANEL, fg=TEXT,
                                      font=(self.chinese_font, 11), wrap='word', relief='flat')
        self.restore_result.pack(fill='both', expand=True)
        self.restore_result.insert('1.0', '請選擇備份來源及可清除的目標 SSD。開始後會先驗證 SHA-256，通過並再次確認後才會清除磁碟。')
        self.restore_result.configure(state='disabled')
        self._on_restore_mode()

    def _on_restore_mode(self, event=None):
        single = self.restore_mode_combo.current() == 1
        for widget in (self.restore_source_combo, self.restore_target_combo):
            if widget is not None:
                widget.configure(state='readonly' if single else 'disabled')
        self._invalidate_restore_ready()
        if self.restore_status is not None:
            self.restore_status.configure(text=(
                'Full Disk Restore 實驗版：會清除整顆目標 SSD，請勿選擇存放備份的磁碟。'
                if not single else 'Single Partition Restore：請確認目標為空白 NTFS 測試磁區。'))
        self.restore_apply_button.configure(state='normal')

    def _start_restore_action(self):
        if self.restore_mode_combo.current() == 0:
            self._start_full_restore()
            return
        self._start_partition_restore()

    def _start_full_restore(self):
        if self.restore_running or self.restore_check_running or self.backup_running:
            return
        if not self.restore_folder or not self.disks:
            self._backup_dialog('Restore', '請先選擇備份資料夾及目標 SSD。')
            return
        folder = self.restore_folder
        try:
            target = dict(self.disks[self._selected_disk_index()])
        except (RuntimeError, IndexError) as exc:
            self._backup_dialog('Restore 安全限制', str(exc))
            return
        try:
            with open(os.path.join(folder, 'BackupInfo.json'), encoding='utf-8') as f:
                info = json.load(f)
            full_restore_plan(info, target)
            assert_restore_safe(scan_disks(), target, folder, disk_for_path, is_winpe())
            if not is_winpe():
                raise RuntimeError('Full Disk Restore 僅允許在 WinPE 執行。')
            # A fast first gate; full SHA-256 and fresh disk scan happen in worker.
            for label, path in [('備份資料夾', folder),
                                ('Tool', sys.executable if getattr(sys, 'frozen', False) else __file__)]:
                drive = os.path.splitdrive(os.path.abspath(path))[0].upper()
                if drive == 'X:':
                    continue
                if disk_for_path(path) == int(target['Number']):
                    raise RuntimeError(label + '位於目標 SSD，禁止清除。')
        except Exception as exc:
            self._backup_dialog('Restore 條件不符', str(exc))
            return
        disk_text = 'Disk %s\n%s\n%s / %s' % (target['Number'], target['Model'],
            capacity(target['Size']), target['PartitionStyle'])
        if not self._backup_dialog('最後確認：Full Disk Restore',
            '即將永久清除以下目標 SSD 的全部 Partition 與資料：\n\n' + disk_text +
            '\n\n備份來源：' + folder +
            '\n\n程式會驗證 SHA-256，並在 DiskPart clean 前重新確認磁碟身分與安全隔離。'
            '\n清除後無法復原，且中途取消不能保證磁碟可開機。\n\n確認開始還原？', confirm=True):
            return
        self.restore_running = True
        self.restore_started_at = time.monotonic()
        self._set_restore_controls_locked(True)
        self.restore_status.configure(text='開始 SHA-256 驗證；請勿關閉程式')
        self.restore_progress_bar.configure(value=0)
        self.restore_summary.configure(text='整體進度：0% | 已花時間：00:00:00 | ETA：估算中')
        self.restore_result.configure(state='normal')
        self.restore_result.delete('1.0', 'end')
        self.restore_result.insert('end', '開始 Restore；磁碟寫入前會再次檢查。\n')
        self.restore_result.configure(state='disabled')
        def worker():
            try:
                log = execute_full_restore(folder, target, restore_preflight,
                    scan_disks, disk_for_path,
                    lambda stage, pct, elapsed, msg, logfile:
                        self.after(0, lambda a=stage,b=pct,c=elapsed,d=msg,e=logfile:
                            self._full_restore_progress(a,b,c,d,e)))
                self.after(0, lambda: self._full_restore_done(None, log))
            except Exception as exc:
                # Capture failures even when the restore engine has not opened its log yet.
                # Never let a logging failure mask the original restore exception.
                details = traceback.format_exc()
                log_file = None
                for log_dir in (folder, os.path.join(tempfile.gettempdir(), 'Backup_and_Restore_Tool')):
                    try:
                        os.makedirs(log_dir, exist_ok=True)
                        candidate = os.path.join(log_dir, 'Restore_ERROR_%s.log' % time.strftime('%Y%m%d_%H%M%S'))
                        with open(candidate, 'w', encoding='utf-8') as out:
                            out.write('Backup and Restore Tool v0.24.3\n')
                            out.write('Target disk: %s\n' % target.get('Number'))
                            out.write('Target style: %s\n' % target.get('PartitionStyle'))
                            out.write('Backup folder: %s\n\n' % folder)
                            out.write(details)
                        log_file = candidate
                        break
                    except Exception:
                        continue
                error = '%s: %s' % (type(exc).__name__, exc)
                if log_file:
                    error += '\n\n錯誤追蹤 Log：' + log_file
                else:
                    error += '\n\n無法寫入錯誤 Log。\n' + details[-1400:]
                self.after(0, lambda e=error: self._full_restore_done(e, None))
        threading.Thread(target=worker, daemon=True).start()

    def _toggle_details(self, which):
        if which == 'restore':
            frame, button = self.restore_detail_frame, self.restore_detail_button
        else:
            frame, button = self.backup_detail_frame, self.backup_detail_button
        if frame is None or button is None or not frame.winfo_exists():
            return
        if frame.winfo_manager():
            frame.pack_forget()
            button.configure(text='顯示細節')
        else:
            frame.pack(fill='both', expand=True, pady=(4, 8))
            button.configure(text='隱藏細節')

    def _full_restore_progress(self, stage, pct, elapsed, msg, logfile):
        if not self.restore_running:
            return
        eta = '估算中'
        if stage == '套用 WIM' and 3 < pct < 95:
            remaining = elapsed * (100.0 - pct) / pct
            eta = '約 %d 分鐘（粗估）' % max(1, round(remaining/60))
        self.restore_status.configure(text='目前作業：' + stage + ' | ' + msg[:100])
        self.restore_progress_bar.configure(value=max(0, min(100, pct)))
        self.restore_summary.configure(text='整體進度：約 %.1f%% | 已花時間：%s | ETA：%s' % (
            pct, self._format_elapsed(elapsed), eta))
        self.restore_result.configure(state='normal')
        self.restore_result.insert('end', msg + '\n')
        self.restore_result.see('end')
        self.restore_result.configure(state='disabled')

    def _full_restore_done(self, error, log):
        self.restore_running = False
        self._set_restore_controls_locked(False)
        self._invalidate_restore_ready()
        if error:
            self.restore_status.configure(text='Restore 失敗：請勿直接嘗試開機')
            self._backup_dialog('Restore 失敗', error)
        else:
            self.restore_status.configure(text='WIM + BCDBoot 已完成；尚未驗證開機')
            self.restore_progress_bar.configure(value=100)
            self._completion_dialog('Restore', 'WIM 與 BCDBoot 指令已完成；Windows 實際開機仍需驗證。\nLog：' + str(log) + '\n重新開機前請移除 WinPE 開機媒體。', elapsed=time.monotonic() - self.restore_started_at)

    def _browse_restore_folder(self):
        path = self._choose_folder('選擇備份來源資料夾', self.restore_folder)
        if path:
            self.restore_folder = path
            self.restore_folder_var.set(path)
            if self.disk_selector:
                options = self._disk_options()
                self.disk_selector.configure(values=options,
                    state='readonly' if self._restore_disk_indices else 'disabled')
                self.disk_selector.current(0)
            self._populate_restore_choices()
            self._invalidate_restore_ready()

    def _start_restore_check(self):
        if self.restore_check_running:
            return
        if not self.disks:
            messagebox.showwarning('Restore', '請先掃描並選擇目標磁碟。')
            return
        if not self.restore_folder:
            messagebox.showwarning('Restore', '請先選擇備份資料夾。')
            return
        target = dict(self.disks[self._selected_disk_index()])
        folder = self.restore_folder
        self._invalidate_restore_ready()
        self.restore_check_running = True
        self.restore_apply_button.configure(state='disabled')
        self.restore_check_button.configure(state='disabled') if self.restore_check_button else None
        self.restore_status.configure(text='正在檢查映像與磁碟…')
        def worker():
            try:
                result = restore_preflight(folder, target,
                    lambda msg: self.after(0, lambda m=msg: self._restore_status_update(m)))
                self.after(0, lambda: self._restore_check_finished(result, None))
            except Exception as error:
                msg = str(error)
                self.after(0, lambda: self._restore_check_finished(None, msg))
        threading.Thread(target=worker, daemon=True).start()

    def _restore_status_update(self, message):
        if self.active == 'Restore' and self.restore_status is not None:
            self.restore_status.configure(text=message)

    def _restore_check_finished(self, result, error):
        self.restore_check_running = False
        if self.restore_apply_button is not None:
            self.restore_apply_button.configure(state='normal')
        if self.active != 'Restore':
            return
        self.restore_check_button.configure(state='normal') if self.restore_check_button else None
        self.restore_status.configure(text='檢查失敗' if error else '檢查完成')
        if error:
            report = '檢查失敗：\n' + error
        else:
            source = result['source']
            target = result['target']
            report = ('備份狀態：%s\n來源：%s | %s | %s\n'
                      '目標：Disk %s | %s | %s | %s\n\n'
                      '映像檔 SHA-256 驗證通過：%d 個\n') % (
                          result['status'], source.get('model', '?'),
                          capacity(result['source_size']), result['source_style'],
                          target['Number'], target['Model'], capacity(target['Size']),
                          target['PartitionStyle'], len(result['captures']))
            report += '\n'.join('  Partition %s: %s' % (x['number'], x['image_file'])
                                for x in result['captures'])
            report += '\n\n警告 / 尚未支援：\n' + '\n'.join('• ' + w for w in result['warnings'])
            report += '\n\n受保護磁碟辨識：\n' + '\n'.join(
                '• %s：%s' % (label, disk_no) for label, disk_no in result['protected_disks'].items())
            report += '\n\n磁區對應：\n' + '\n'.join(
                '• Source #%s → Target %s | WIM: %s | %s' % (
                    m['source_partition'], '#' + str(m['target_partition']) if m['target_partition'] is not None else '未對應',
                    '有' if m['image_available'] else '無', m['match_status'])
                for m in result['partition_mapping'])
            report += '\n\n禁止執行還原的原因：\n' + '\n'.join('• ' + b for b in result['blockers'])
            report += '\n\n此為唯讀檢查結果；實際 Restore 另需明確確認。'
        self.restore_result.configure(state='normal')
        self.restore_result.delete('1.0', 'end')
        self.restore_result.insert('1.0', report)
        self.restore_result.configure(state='disabled')
        if not error and self.restore_mode_combo.current() == 1:
            try:
                self._check_single_partition_ready()
                self.restore_apply_button.configure(state='normal')
                self.restore_status.configure(text='單一磁區條件符合；執行前仍會重新檢查')
            except Exception as exc:
                self.restore_status.configure(text='檢查完成；還原尚未允許：' + str(exc))

    def _invalidate_restore_ready(self):
        if self.restore_apply_button is not None:
            self.restore_apply_button.configure(state='disabled' if self.restore_running or self.restore_check_running else 'normal')

    def _populate_restore_choices(self):
        if self.active != 'Restore' or self.restore_source_combo is None:
            return
        self.restore_candidates = []
        try:
            with open(os.path.join(self.restore_folder, 'BackupInfo.json'), encoding='utf-8') as stream:
                info = json.load(stream)
            if info.get('schema_version') == 3 and info.get('status') in ('completed_file_level', 'completed_partial'):
                self.restore_candidates = list(info.get('captures') or [])
        except (OSError, ValueError, TypeError):
            pass
        src = ['Partition %s | %s | %s' % (p.get('number'), p.get('filesystem'), p.get('image_file'))
               for p in self.restore_candidates]
        self.restore_source_combo.configure(values=src or ['沒有有效備份映像'])
        self.restore_source_combo.current(0)
        self._update_restore_target_parts()

    def _update_restore_target_parts(self):
        if self.restore_target_combo is None:
            return
        try:
            disk = self.disks[self._selected_disk_index()] if self.disks else {}
        except (RuntimeError, IndexError):
            disk = {}
        self.restore_target_parts = list(disk.get('Partitions', []))
        values = ['Partition %s | %s | %s | %s' % (
            x['Number'], x.get('DriveLetter') or '無代號',
            x.get('FileSystem') or '?', capacity(x['Size'])) for x in self.restore_target_parts]
        self.restore_target_combo.configure(values=values or ['沒有目標磁區'])
        self.restore_target_combo.current(0)
        self._invalidate_restore_ready()

    def _check_single_partition_ready(self):
        if not is_winpe():
            raise RuntimeError('僅允許在 WinPE 執行還原')
        if not self.restore_candidates or not self.restore_target_parts:
            raise RuntimeError('沒有可選的來源或目標 Partition')
        source = self.restore_candidates[self.restore_source_combo.current()]
        target = self.restore_target_parts[self.restore_target_combo.current()]
        disk = self.disks[self._selected_disk_index()]
        return validate_partition_restore(self.restore_folder, source, disk, target)

    def _start_partition_restore(self):
        if self.restore_running or self.restore_check_running or self.restore_mode_combo.current() != 1:
            return
        try:
            source, disk, part, root = self._check_single_partition_ready()
        except Exception as exc:
            messagebox.showerror('Restore 安全檢查', str(exc))
            self._invalidate_restore_ready()
            return
        label = 'Disk %s / Partition %s (%s)' % (disk['Number'], part['Number'], root)
        if not self._backup_dialog('確認單一 Partition Restore',
            '即將覆寫以下目標 Partition 內的檔案：\n\n' + label +
            '\n\n僅允許空白 NTFS 測試磁區。此操作可能無法復原。\n\n確認開始？', confirm=True):
            return
        self.restore_running = True
        self._set_restore_controls_locked(True)
        self.restore_status.configure(text='正在執行還原，請勿關閉程式')
        folder = self.restore_folder
        def worker():
            try:
                log = apply_single_partition(folder, source, disk, part,
                    lambda msg: self.after(0, lambda m=msg: self._restore_status_update(m)))
                self.after(0, lambda: self._restore_apply_finished(None, log))
            except Exception as exc:
                self.after(0, lambda m=str(exc): self._restore_apply_finished(m, None))
        threading.Thread(target=worker, daemon=True).start()

    def _restore_apply_finished(self, error, log):
        self.restore_running = False
        self._set_restore_controls_locked(False)
        if self.active == 'Restore':
            self.restore_check_button.configure(state='normal') if self.restore_check_button else None
            self.restore_status.configure(text='還原失敗：' + error if error else 'DISM 套用完成（尚未驗證開機）')
            self._invalidate_restore_ready()
            messagebox.showerror('Restore', error) if error else messagebox.showinfo('Restore', 'DISM 已完成套用。Log：' + log)

    def _build_scan_controls(self, panel, include_details=True):
        scan_controls = tk.Frame(panel, bg=CARD)
        scan_controls.pack(fill='x', pady=(12, 8))
        self.scan_button = tk.Button(scan_controls, text='重新掃描磁碟 (F5)',
                                     command=self.refresh_disks,
                                     font=(self.chinese_font, 12), width=20, padx=12, pady=6)
        self.scan_button.pack(side='left')
        self.scan_status = tk.Label(scan_controls, text='準備就緒', bg=CARD, fg=MUTED,
                                    font=(self.chinese_font, 12))
        self.scan_status.pack(side='left', padx=16)
        # Native disk scan is fast; keep the scanning status text, no progress bar.
        if self.scanning:
            self._set_scanning_ui(True)
        if include_details:
            self._build_disk_details(panel)

    def _build_disk_details(self, panel):
        self.disk_details = tk.Text(panel, height=9, bg=PANEL, fg=TEXT,
                                    font=(self.chinese_font, 12), wrap='word', relief='flat')
        self.disk_details.pack(fill='both', expand=True)
        self._display_disk(self._selected_disk_index())

    def _row(self, parent, label, options):
        frame = tk.Frame(parent, bg=CARD)
        frame.pack(fill='x', pady=8)
        tk.Label(frame, text=label, width=12, anchor='w', bg=CARD, fg=TEXT,
                 font=(self.chinese_font, 13)).pack(side='left')
        combo = ttk.Combobox(frame, values=options, state='readonly', width=39, font=(self.chinese_font, 12))
        combo.current(0)
        combo.pack(side='left', fill='x', expand=True, padx=(12, 0))
        return combo



    def _selected_disk_index(self):
        if self.disk_selector is None:
            return 0
        current = max(0, self.disk_selector.current())
        if self.active == 'Restore' and hasattr(self, '_restore_disk_indices'):
            if not self._restore_disk_indices:
                raise RuntimeError('沒有可安全選擇的還原目標磁碟。')
            if current >= len(self._restore_disk_indices):
                raise RuntimeError('目標磁碟選擇無效。')
            return self._restore_disk_indices[current]
        return current

    def _on_disk_selected(self, event=None):
        index = self._selected_disk_index()
        if self.active == 'Backup' and index < len(self.disks):
            self.backup_disk_number = self.disks[index]['Number']
            self.backup_partition_number = None
            self._update_backup_partitions()
        self._display_disk(index)
        if self.active == 'Restore':
            self._update_restore_target_parts()

    def _build_backup(self, panel):
        self.backup_mode_combo = self._row(panel, '備份模式',
            ['Full Disk Backup', 'Single Partition Backup'])
        self.backup_mode_combo.set(self.backup_mode)
        self.backup_mode_combo.bind('<<ComboboxSelected>>', self._on_backup_mode)
        self._disk_row(panel, '來源磁碟')
        if self.disks:
            self.backup_disk_number = self.disks[self._selected_disk_index()]['Number']
        frame = tk.Frame(panel, bg=CARD)
        frame.pack(fill='x', pady=8)
        tk.Label(frame, text='來源磁區', width=12, anchor='w', bg=CARD, fg=TEXT,
                 font=(self.chinese_font, 13)).pack(side='left')
        self.backup_partition_combo = ttk.Combobox(frame, state='readonly', width=39,
                                                    font=(self.chinese_font, 12))
        self.backup_partition_combo.pack(side='left', fill='x', expand=True, padx=(12, 0))
        self.backup_partition_combo.bind('<<ComboboxSelected>>', self._on_partition_selected)
        self._update_backup_partitions()

        # Source disk/partition -> rescan controls, as requested.
        self._build_scan_controls(panel, include_details=False)

        frame = tk.Frame(panel, bg=CARD)
        frame.pack(fill='x', pady=8)
        tk.Label(frame, text='目的地', width=12, anchor='w', bg=CARD, fg=TEXT,
                 font=(self.chinese_font, 13)).pack(side='left')
        self.backup_dest_var = tk.StringVar(value=self.backup_destination or '尚未選擇備份資料夾')
        tk.Entry(frame, textvariable=self.backup_dest_var, state='readonly',
                 font=(self.chinese_font, 12), readonlybackground=PANEL, fg=TEXT).pack(
                 side='left', fill='x', expand=True, padx=(12, 8))
        tk.Button(frame, text='瀏覽', command=self._browse_backup_folder,
                  font=(self.chinese_font, 11)).pack(side='left', padx=(0, 5))

        frame = tk.Frame(panel, bg=CARD)
        frame.pack(fill='x', pady=8)
        tk.Label(frame, text='備份名稱', width=12, anchor='w', bg=CARD, fg=TEXT,
                 font=(self.chinese_font, 13)).pack(side='left')
        self.backup_name_var = tk.StringVar(value=self.backup_name)
        entry = tk.Entry(frame, textvariable=self.backup_name_var, font=(self.chinese_font, 12))
        entry.pack(side='left', fill='x', expand=True, padx=(12, 0))
        self.backup_name_var.trace_add('write', lambda *_: setattr(self, 'backup_name', self.backup_name_var.get()))
        self.backup_status = tk.Label(panel, text='僅 WinPE 可執行備份；Windows 11 可預覽設定。',
                                      bg=CARD, fg=MUTED, font=(self.chinese_font, 11))
        self.backup_status.pack(anchor='w', pady=(10, 0))
        self.backup_button = tk.Button(panel, text='開始備份', command=self._start_backup,
                                       font=(self.chinese_font, 12), width=20, padx=12, pady=6)
        self.backup_button.pack(anchor='w', pady=(7, 4))
        self.backup_progress = ttk.Progressbar(panel, mode='indeterminate')
        self.backup_progress.pack(fill='x', pady=(5, 5))
        self.backup_detail_button = tk.Button(panel, text='顯示細節',
            command=lambda: self._toggle_details('backup'), font=(self.chinese_font, 11))
        self.backup_detail_button.pack(anchor='w', pady=(2, 4))
        self.backup_detail_frame = tk.Frame(panel, bg=CARD)
        self.backup_metrics = tk.Label(self.backup_detail_frame, text='尚未開始備份', bg=CARD, fg=TEXT,
                         font=(self.chinese_font, 11), anchor='w', justify='left')
        self.backup_metrics.pack(fill='x', pady=(3, 5))
        self.backup_cancel_button = tk.Button(panel, text='取消備份', command=self._cancel_backup,
                         font=(self.chinese_font, 11), state='disabled')
        self.backup_cancel_button.pack(anchor='w', pady=(2, 5))
        self._build_disk_details(self.backup_detail_frame)
        if self.backup_running:
            self.backup_button.configure(state='disabled')
            self.backup_progress.start(12)

    def _completion_dialog(self, operation, summary, elapsed=None):
        """Only invoked after successful worker completion; never reboot automatically."""
        dialog = tk.Toplevel(self)
        dialog.title('Operation Completed')
        dialog.configure(bg=PANEL)
        dialog.transient(self)
        dialog.resizable(True, True)
        width = max(360, min(760, self.winfo_screenwidth() - 40))
        height = max(350, min(530, self.winfo_screenheight() - 65))
        dialog.geometry('%dx%d+%d+%d' % (width, height, max(0,(self.winfo_screenwidth()-width)//2), max(0,(self.winfo_screenheight()-height)//2)))
        title = '備份作業已完成' if operation == 'Backup' else '還原作業已完成'
        tk.Label(dialog, text=title, bg=PANEL, fg=TEXT,
                 font=(self.chinese_font, 15, 'bold')).pack(anchor='w', padx=16, pady=(15, 8))
        if elapsed is not None:
            summary += '\n總耗時：' + self._format_elapsed(elapsed)
        detail = tk.Text(dialog, wrap='word', bg=CARD, fg=TEXT,
                         font=(self.chinese_font, 11), relief='flat', padx=10, pady=8,
                         height=8)
        detail.pack(fill='both', expand=True, padx=16, pady=4)
        detail.insert('1.0', summary)
        detail.configure(state='disabled')
        tk.Label(dialog, text='請選擇接下來的操作（不會自動重新開機）', bg=PANEL,
                 fg=MUTED, font=(self.chinese_font, 10)).pack(anchor='w', padx=16, pady=8)
        footer = tk.Frame(dialog, bg=PANEL)
        footer.pack(fill='x', padx=16, pady=(0, 15))

        def remain():
            dialog.destroy()

        def power(action):
            label = '重新開機' if action == 'reboot' else '關機'
            if self.driver_loading or self.backup_running or self.restore_running or self.restore_check_running:
                self._backup_dialog('無法' + label, '仍有作業進行中，請等待完成。')
                return
            if not is_winpe():
                self._backup_dialog('無法' + label, '電源操作僅允許在 WinPE 中執行。')
                return
            try:
                # Windows PE native utility. No shell and no PowerShell dependency.
                proc = subprocess.Popen(['wpeutil.exe', action],
                                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            except (OSError, ValueError) as exc:
                self._backup_dialog(label + '失敗', '無法啟動 wpeutil：' + str(exc))
                return
            dialog.destroy()
            # wpeutil may reboot before returning; avoid blocking the GUI.
            self.after(1000, lambda: self._check_power_command(proc, label))

        tk.Button(footer, text='留在 WinPE', font=(self.chinese_font, 11),
                  command=remain).pack(side='left')
        tk.Button(footer, text='關機', font=(self.chinese_font, 11),
                  command=lambda: power('shutdown')).pack(side='right', padx=(8, 0))
        tk.Button(footer, text='重新開機', font=(self.chinese_font, 11),
                  command=lambda: power('reboot')).pack(side='right')
        dialog.protocol('WM_DELETE_WINDOW', remain)
        dialog.bind('<Escape>', lambda event: remain())
        dialog.update_idletasks()
        dialog.minsize(min(width, 360), min(height, 300))
        dialog.grab_set()
        dialog.focus_set()

    def _check_power_command(self, process, label):
        status = process.poll()
        if status is not None and status != 0:
            self._backup_dialog(label + '失敗', 'wpeutil 結束代碼：%s' % status)

    def _backup_dialog(self, title, message, confirm=False):
        """WinPE CJK dialog with fixed footer and safe cancel on X/Escape."""
        dialog = tk.Toplevel(self)
        dialog.title('Backup Message')  # Native title bar remains ASCII for WinPE.
        dialog.configure(bg=PANEL)
        dialog.transient(self)
        dialog.resizable(True, True)
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = max(300, min(780, screen_w - 48))
        height = max(240, min(540, screen_h - 70))
        dialog.geometry('%dx%d+%d+%d' % (width, height, max(0, (screen_w-width)//2), max(0, (screen_h-height)//2)))
        # Grid reserves an independent bottom row for buttons. The message
        # area is the only expanding region and may scroll on small screens.
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(1, weight=1)
        tk.Label(dialog, text=title, bg=PANEL, fg=TEXT,
                 font=(self.chinese_font, 14, 'bold'), anchor='w').grid(
                 row=0, column=0, sticky='ew', padx=14, pady=(12, 6))
        body = tk.Frame(dialog, bg=PANEL)
        body.grid(row=1, column=0, sticky='nsew', padx=14, pady=(0, 6))
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        detail = tk.Text(body, wrap='word', bg=CARD, fg=TEXT,
                         insertbackground=TEXT, font=(self.chinese_font, 11),
                         relief='flat', padx=10, pady=8)
        detail.grid(row=0, column=0, sticky='nsew')
        scroll = tk.Scrollbar(body, orient='vertical', command=detail.yview)
        scroll.grid(row=0, column=1, sticky='ns')
        detail.configure(yscrollcommand=scroll.set)
        detail.insert('1.0', str(message))
        detail.configure(state='disabled')
        footer = tk.Frame(dialog, bg=PANEL)
        footer.grid(row=2, column=0, sticky='ew', padx=14, pady=(4, 12))
        result = {'ok': False}
        closed = {'value': False}
        def close(ok=False):
            if closed['value']:
                return
            closed['value'] = True
            result['ok'] = bool(ok)
            try:
                dialog.grab_release()
            except tk.TclError:
                pass
            dialog.destroy()
        if confirm:
            no_button = tk.Button(footer, text='否 / 取消', font=(self.chinese_font, 11),
                                  command=lambda: close(False))
            no_button.pack(side='right', padx=(8, 0))
            tk.Button(footer, text='是 / 繼續', font=(self.chinese_font, 11),
                      command=lambda: close(True)).pack(side='right')
            focus_target = no_button
        else:
            focus_target = tk.Button(footer, text='確定', font=(self.chinese_font, 11),
                                     command=lambda: close(False))
            focus_target.pack(side='right')
        dialog.protocol('WM_DELETE_WINDOW', lambda: close(False))
        dialog.bind('<Escape>', lambda event: (close(False), 'break')[1])
        dialog.update_idletasks()
        # Keep buttons visible even when the window is resized or the text is long.
        dialog.minsize(min(width, 320), min(height, 190))
        dialog.grab_set()
        focus_target.focus_set()
        self.wait_window(dialog)
        return result['ok']

    def _start_backup(self):
        if self.backup_running:
            return
        if not is_winpe():
            self._backup_dialog('WinPE 限制', '備份功能只允許在 WinPE 執行。\nWindows 11 目前僅提供 GUI 與設定預覽。')
            return
        disk = next((d for d in self.disks if d['Number'] == self.backup_disk_number), None)
        if disk is None:
            self._backup_dialog('無法備份', '請先選擇來源磁碟。')
            return
        try:
            name = safe_backup_name(self.backup_name)
            captures, skipped = backup_plan(disk, self.backup_mode, self.backup_partition_number)
            if not self.backup_destination:
                raise RuntimeError('請先選擇備份目的地。')
        except (ValueError, RuntimeError, TypeError) as exc:
            self._backup_dialog('無法備份', str(exc))
            return
        summary = ('來源：Disk %s  %s\n模式：%s\n可擷取磁區：%s\n跳過磁區：%s\n目的地：%s\n名稱：%s\n\n'
                   '注意：WIM 是檔案層級備份，並非逐扇區完整磁碟映像。') % (
                   disk['Number'], disk['Model'], self.backup_mode,
                   ', '.join(str(p['number']) for p in captures),
                   ', '.join(str(p['number']) for p in skipped) or '無', self.backup_destination, name)
        if skipped:
            structural = [p for p in skipped if p.get('type') == 'Reserved'
                          and str(disk.get('PartitionStyle', '')).upper() == 'GPT'
                          and str(p.get('partition_type_guid', '')).lower() == 'e3c9e316-0b5c-4db8-817d-f92df00215ae']
            unsupported = [p for p in skipped if p not in structural]
            if structural:
                summary += ('\n\nMSR 為 GPT 系統保留磁區，不需擷取檔案內容；'
                            '其分割資訊會記錄於 BackupInfo.json，還原時需重新建立。')
            if unsupported:
                summary += ('\n\n警告：下列磁區無法擷取：%s。'
                            'Full Disk Backup 將拒絕執行，請先處理此問題。' %
                            ', '.join(str(p['number']) for p in unsupported))
        if not self._backup_dialog('確認開始備份', summary, confirm=True):
            return
        self.backup_running = True
        self.backup_cancel_event.clear()
        self.backup_runtime = {'completed': 0, 'stage': '準備中'}
        self.backup_started_at = time.monotonic()
        self.backup_last_bytes = 0
        self.backup_last_tick = self.backup_started_at
        self.backup_cancel_button.configure(state='normal')
        self._set_backup_controls_locked(True)
        self.after(1000, self._backup_monitor_tick)
        self.backup_button.configure(state='disabled')
        self.backup_progress.start(12)
        self.backup_status.configure(text='正在進行備份…')
        disk_snapshot = json.loads(json.dumps(disk))
        mode, part_number, destination = self.backup_mode, self.backup_partition_number, self.backup_destination
        def progress(message):
            self.after(0, lambda m=message: self._backup_progress_update(m))
        def worker():
            try:
                result = run_backup(disk_snapshot, mode, part_number, destination, name, progress, self.backup_cancel_event, self.backup_runtime)
                self.after(0, lambda r=result: self._backup_finished(r, None))
            except Exception as exc:
                error = str(exc)
                self.after(0, lambda e=error: self._backup_finished(None, e))
        threading.Thread(target=worker, daemon=True).start()

    def _backup_progress_update(self, message):
        if self.active == 'Backup' and self.backup_status and self.backup_status.winfo_exists():
            self.backup_status.configure(text=message)

    def _backup_finished(self, result, error):
        elapsed = time.monotonic() - self.backup_started_at if self.backup_started_at else 0
        self.backup_running = False
        self._set_backup_controls_locked(False)
        if self.active == 'Backup':
            self.backup_cancel_button.configure(state='disabled')
            self.backup_metrics.configure(text=self.backup_metrics.cget('text') + '\n總耗時：' + self._format_elapsed(elapsed))
        if self.active == 'Backup' and self.backup_button and self.backup_button.winfo_exists():
            self.backup_button.configure(state='normal')
            self.backup_progress.stop()
            self.backup_progress.configure(value=0)
            self.backup_status.configure(text='備份失敗' if error else '備份完成')
        if error:
            self._backup_dialog('備份已取消' if self.backup_cancel_event.is_set() else '備份失敗', error)
        else:
            folder, count, skipped = result
            self._completion_dialog('Backup',
                                '完成 %d 個 Partition，跳過 %d 個。\n備份位置：%s\n%s' % (
                                count, skipped, folder,
                                '這是部分備份，不能視為完整磁碟映像。' if skipped else
                                '這是檔案層級 WIM 備份，不是逐扇區完整磁碟映像。'), elapsed=elapsed)

    @staticmethod
    def _format_elapsed(seconds):
        seconds = max(0, int(seconds))
        return '%02d:%02d:%02d' % (seconds // 3600, seconds // 60 % 60, seconds % 60)

    def _set_restore_controls_locked(self, locked):
        """Lock Restore inputs during an active operation; keep details accessible."""
        for widget in self._walk_widgets(self.content):
            if widget is getattr(self, 'restore_detail_button', None):
                continue
            if isinstance(widget, (tk.Entry, ttk.Combobox, tk.Button)):
                try:
                    if locked:
                        widget._restore_previous_state = str(widget.cget('state'))
                        widget.configure(state='disabled')
                    elif hasattr(widget, '_restore_previous_state'):
                        widget.configure(state=widget._restore_previous_state)
                        del widget._restore_previous_state
                except tk.TclError:
                    pass
        for button in self.nav_buttons.values():
            button.configure(state='disabled' if locked else 'normal')

    def _set_backup_controls_locked(self, locked):
        # Lock the entire Backup configuration, including rescan and navigation.
        for widget in self._walk_widgets(self.content):
            if widget in (self.backup_cancel_button, self.backup_button):
                continue
            if isinstance(widget, (tk.Entry, ttk.Combobox, tk.Button)):
                try:
                    if locked:
                        widget._backup_previous_state = str(widget.cget('state'))
                        widget.configure(state='disabled')
                    elif hasattr(widget, '_backup_previous_state'):
                        widget.configure(state=widget._backup_previous_state)
                        del widget._backup_previous_state
                except tk.TclError:
                    pass
        for name, button in self.nav_buttons.items():
            button.configure(state='disabled' if locked else 'normal')

    def _backup_monitor_tick(self):
        if not self.backup_running:
            return
        runtime = self.backup_runtime
        now = time.monotonic()
        elapsed = now - self.backup_started_at
        folder = runtime.get('folder')
        total_bytes = 0
        if folder:
            try:
                total_bytes = sum(os.path.getsize(os.path.join(folder, fn))
                                  for fn in os.listdir(folder) if fn.lower().endswith('.wim'))
            except OSError:
                pass
        delta_t = max(0.1, now - (self.backup_last_tick or now))
        speed = max(0, total_bytes - self.backup_last_bytes) / delta_t
        self.backup_last_bytes, self.backup_last_tick = total_bytes, now
        index, count = runtime.get('index', 0), runtime.get('total', 0)
        stage = runtime.get('stage', '準備中')
        details = ('目前：Partition %s（%s/%s）  %s\n'
                   '已完成 Partition：%s\n'
                   'WIM 累計寫入：約 %.2f GiB\n'
                   'WIM 檔案增長速度：約 %.1f MiB/s（非磁碟讀取速度）\n'
                   '已花時間：%s  |  整體進度／ETA：無法可靠估算') % (
                    runtime.get('partition', '—'), index or '—', count or '—', stage,
                    runtime.get('completed', 0), total_bytes / 1024**3, speed / 1024**2,
                    self._format_elapsed(elapsed))
        if self.active == 'Backup' and self.backup_metrics.winfo_exists():
            self.backup_metrics.configure(text=details)
            self.backup_status.configure(text='目前：Partition %s（%s/%s） %s | 已花 %s | ETA：無法可靠估算' % (
                runtime.get('partition', '—'), index or '—', count or '—', stage,
                self._format_elapsed(elapsed)))
        self.after(1000, self._backup_monitor_tick)

    def _cancel_backup(self):
        if not self.backup_running or self.backup_cancel_event.is_set():
            return
        if not self._backup_dialog('確認取消備份',
                '確定取消正在進行的備份？\n未完成的 WIM 不能用於還原，診斷紀錄會保留。', confirm=True):
            return
        self.backup_cancel_event.set()
        self.backup_cancel_button.configure(state='disabled')
        self.backup_status.configure(text='正在取消備份，請等待 DISM 結束…')
        process = self.backup_runtime.get('process')
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

    def _on_app_close(self):
        if self.driver_loading:
            messagebox.showwarning("Driver 載入中", "請等待 Driver 載入完成。", parent=self)
            return
        if self.restore_running:
            messagebox.showwarning('Restore 正在執行', '還原正在執行，不可關閉程式或中斷電源。')
            return
        if self.backup_running:
            if self._backup_dialog('備份進行中',
                    '備份仍在執行。是否先取消備份？\n程式會保持開啟，直到作業結束。', confirm=True):
                self._cancel_backup_direct()
            return
        self.destroy()

    def _cancel_backup_direct(self):
        self.backup_cancel_event.set()
        if self.active == 'Backup':
            self.backup_cancel_button.configure(state='disabled')
        process = self.backup_runtime.get('process')
        if process is not None and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

    def _on_backup_mode(self, event=None):
        self.backup_mode = self.backup_mode_combo.get()
        self._update_backup_partitions()

    def _update_backup_partitions(self):
        combo = self.backup_partition_combo
        if combo is None or not combo.winfo_exists():
            return
        if self.backup_mode == 'Full Disk Backup':
            combo.configure(values=['全部磁區（包含 EFI / Recovery 等）'], state='disabled')
            combo.current(0)
            return
        disk = next((d for d in self.disks if d['Number'] == self.backup_disk_number), None)
        parts = disk.get('Partitions', []) if disk else []
        if not parts:
            combo.configure(values=['尚無磁區資訊'], state='disabled')
            combo.current(0)
            return
        options = [f"Partition {part['Number']} | {capacity(part['Size'])} | {part['Type']} | {part['FileSystem'] or '-'}"
                   for part in parts]
        combo.configure(values=options, state='readonly')
        index = next((i for i, part in enumerate(parts) if part['Number'] == self.backup_partition_number), 0)
        combo.current(index)
        self.backup_partition_number = parts[index]['Number']

    def _on_partition_selected(self, event=None):
        disk = next((d for d in self.disks if d['Number'] == self.backup_disk_number), None)
        parts = disk.get('Partitions', []) if disk else []
        index = self.backup_partition_combo.current()
        if 0 <= index < len(parts):
            self.backup_partition_number = parts[index]['Number']

    def _browse_backup_folder(self):
        path = self._choose_folder('選擇備份目的地資料夾', self.backup_destination)
        if path:
            self.backup_destination = path
            self.backup_dest_var.set(path)

    def _choose_folder(self, title, initial, selection_mode="folder"):
        """Explorer-style Tk picker; avoids missing WinPE shell fonts/title bar glyphs."""
        dialog = tk.Toplevel(self)
        dialog.title('Select Folder')  # Native title bar uses WinPE system font.
        dialog.configure(bg=PANEL)
        dialog.transient(self)
        dialog.resizable(True, True)
        screen_w, screen_h = dialog.winfo_screenwidth(), dialog.winfo_screenheight()
        w = min(930, max(450, screen_w - 48))
        h = min(650, max(360, screen_h - 90))
        dialog.geometry('%dx%d+%d+%d' % (w, h, max(0,(screen_w-w)//2), max(0,(screen_h-h)//2)))
        dialog.minsize(min(460,w), min(350,h))
        result = {'path': None}
        base = (initial if initial and os.path.isdir(initial) else
                os.path.dirname(initial) if initial and os.path.isfile(initial) else
                os.path.abspath(os.getcwd()))
        current = tk.StringVar(value=os.path.abspath(base))
        address = tk.StringVar(value=current.get())
        tk.Label(dialog, text=title, bg=PANEL, fg=TEXT,
                 font=(self.chinese_font, 14, 'bold')).pack(anchor='w', padx=14, pady=(12, 5))
        nav = tk.Frame(dialog, bg=PANEL)
        nav.pack(fill='x', padx=14, pady=(0, 6))
        # Reserve the footer before the expanding folder list; never let Treeview
        # requested geometry push confirmation buttons off-screen in WinPE.
        buttons = tk.Frame(dialog, bg=PANEL)
        buttons.pack(side='bottom', fill='x', padx=14, pady=(6,12))
        center = tk.Frame(dialog, bg=PANEL)
        center.pack(fill='both', expand=True, padx=14, pady=(0, 7))
        drives = tk.Frame(center, bg=CARD, width=135)
        drives.pack(side='left', fill='y', padx=(0, 7))
        drives.pack_propagate(False)
        tk.Label(drives, text='磁碟機', bg=CARD, fg=TEXT,
                 font=(self.chinese_font, 11, 'bold')).pack(fill='x', pady=8)
        self._picker_drive_icon = tk.PhotoImage(data=DRIVE_ICON_PNG)
        self._picker_folder_icon = tk.PhotoImage(data=FOLDER_ICON_PNG)
        tree_style = ttk.Style(dialog)
        previous_theme = tree_style.theme_use()
        # Windows 'vista'/'xpnative' theme ignores Treeview background/foreground.
        # Use the portable 'clam' theme only while the picker is open.
        if 'clam' in tree_style.theme_names():
            tree_style.theme_use('clam')
        # WinPE/Tk 8.6 can clip Treeview text when rowheight is smaller
        # than the actual CJK font ascent + descent after DPI scaling.
        # Treeview uses a ttk style font, NOT the font of its parent Tk widget.
        from tkinter import font as tkfont
        picker_font = tkfont.Font(root=dialog, family=self.chinese_font,
                                  size=11, weight='normal')
        dialog._picker_tree_font = picker_font  # Keep the Tk font alive.
        metrics_height = picker_font.metrics('linespace')
        # Explicit roomy rows avoid cropping on third-party WinPE builds.
        row_height = max(38, int(metrics_height * 1.8) + 10)
        tree_style.configure('Picker.Treeview', background=CARD, fieldbackground=CARD,
                             foreground=TEXT, rowheight=row_height,
                             font=picker_font, borderwidth=0, relief='flat')
        tree_style.map('Picker.Treeview',
                       background=[('selected', '#3979AB')],
                       foreground=[('selected', '#FFFFFF')])
        drive_container = tk.Frame(drives, bg=CARD)
        drive_container.pack(fill='both', expand=True, padx=5, pady=(0, 7))
        drive_scroll = tk.Scrollbar(drive_container, orient='vertical')
        drive_scroll.pack(side='right', fill='y')
        drive_list = ttk.Treeview(drive_container, show='tree', selectmode='browse',
                                  style='Picker.Treeview', height=5, yscrollcommand=drive_scroll.set)
        drive_list.pack(side='left', fill='both', expand=True)
        drive_scroll.configure(command=drive_list.yview)
        files_area = tk.Frame(center, bg=CARD)
        files_area.pack(side='left', fill='both', expand=True)
        tk.Label(files_area, text=('資料夾 / INF' if selection_mode == 'inf' else '資料夾'), anchor='w', bg=CARD, fg=MUTED,
                 font=(self.chinese_font, 11)).pack(fill='x', padx=10, pady=5)
        listing = ttk.Treeview(files_area, show='tree', selectmode='browse',
                               style='Picker.Treeview', height=5)
        bar = tk.Scrollbar(files_area, command=listing.yview)
        bar.pack(side='right', fill='y')
        listing.pack(side='left', fill='both', expand=True, padx=(8,0), pady=(0,8))
        listing.configure(yscrollcommand=bar.set)
        # Show an empty-state message only when the current directory has no subfolders.
        empty_message = tk.Label(files_area, text=('此資料夾沒有子資料夾或 INF' if selection_mode == 'inf' else '此資料夾沒有子資料夾'),
                                 bg=CARD, fg=MUTED, font=(self.chinese_font, 11))
        status = tk.Label(dialog, text='', bg=PANEL, fg=MUTED,
                          font=(self.chinese_font, 10), anchor='w')
        status.pack(side='bottom', fill='x', padx=14)
        names = []
        entry_paths = {}
        def picker_error(detail):
            # Tk's native Windows messagebox can show squares in minimal WinPE.
            alert = tk.Toplevel(dialog)
            alert.title('Folder Error')
            alert.configure(bg=PANEL)
            alert.transient(dialog)
            alert.resizable(False, False)
            alert.geometry('480x165')
            tk.Label(alert, text='資料夾操作失敗', bg=PANEL, fg=TEXT,
                     font=(self.chinese_font, 13, 'bold')).pack(anchor='w', padx=18, pady=(14,5))
            tk.Label(alert, text=str(detail), bg=PANEL, fg=TEXT, justify='left',
                     wraplength=445, font=(self.chinese_font, 10)).pack(fill='x', padx=18)
            tk.Button(alert, text='確定', font=(self.chinese_font, 10),
                      command=alert.destroy).pack(side='bottom', pady=12)
            alert.bind('<Return>', lambda e: alert.destroy())
            alert.bind('<Escape>', lambda e: alert.destroy())
            alert.grab_set()
            alert.focus_set()
            dialog.wait_window(alert)
        def available_drives():
            if os.name != 'nt':
                return ['/']
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            return [chr(65+i)+':\\' for i in range(26) if mask & (1 << i)]
        def refresh_drives():
            for item in drive_list.get_children():
                drive_list.delete(item)
            for item in available_drives():
                drive_list.insert('', 'end', text=item, image=self._picker_drive_icon)
        def go(path):
            path = os.path.abspath(os.path.expandvars(path.strip().strip('"')))
            if not os.path.isdir(path):
                picker_error('資料夾不存在或無法存取：\n' + path)
                return
            try:
                with os.scandir(path) as scan:
                    entries = sorted(((x.name, x.is_dir(follow_symlinks=False)) for x in scan
                                      if x.is_dir(follow_symlinks=False) or
                                      (selection_mode == 'inf' and x.is_file(follow_symlinks=False)
                                       and x.name.lower().endswith('.inf'))),
                                     key=lambda item: (not item[1], item[0].casefold()))
            except OSError as exc:
                picker_error(str(exc))
                return
            current.set(path)
            address.set(path)
            names[:] = [name for name, _ in entries]
            entry_paths.clear()
            for item in listing.get_children():
                listing.delete(item)
            for name, is_dir in entries:
                iid = listing.insert('', 'end', text=name,
                                     image=self._picker_folder_icon if is_dir else '')
                entry_paths[iid] = (os.path.join(path, name), is_dir)
            listing.yview_moveto(0)
            if entries:
                empty_message.place_forget()
            else:
                empty_message.place(relx=0.5, rely=0.5, anchor='center')
            status.configure(text='%s 個資料夾' % len(entries))
        def enter_folder(event=None):
            # Double-click or Enter opens a folder; single click only selects it.
            if event is not None and hasattr(event, 'y'):
                clicked = listing.identify_row(event.y)
                if not clicked:
                    return
                selected_id = clicked
            else:
                chosen = listing.selection()
                if not chosen:
                    return
                selected_id = chosen[0]
            selected_path, is_dir = entry_paths.get(selected_id, (None, False))
            if not selected_path:
                return
            if is_dir:
                go(selected_path)
            elif selection_mode == 'inf':
                result['path'] = selected_path
                dialog.destroy()
        def choose_drive(event=None):
            chosen = drive_list.selection()
            if chosen:
                go(drive_list.item(chosen[0], 'text'))
        def up():
            go(os.path.dirname(os.path.normpath(current.get())))
        def new_folder():
            from tkinter import simpledialog
            name = simpledialog.askstring('New Folder', '新資料夾名稱：', parent=dialog)
            if name is None:
                return
            name = name.strip()
            if not name or name in ('.','..') or any(c in name for c in '<>:"/\\|?*'):
                picker_error('資料夾名稱不合法。')
                return
            try:
                os.mkdir(os.path.join(current.get(), name))
                go(os.path.join(current.get(), name))
            except OSError as exc:
                picker_error(str(exc))
        def select():
            chosen = listing.selection()
            if selection_mode == 'inf':
                path, is_dir = entry_paths.get(chosen[0], (None, False)) if chosen else (None, False)
                if not path or is_dir or not os.path.isfile(path) or not path.lower().endswith('.inf'):
                    picker_error('請先選擇一個 INF 檔案。')
                    return
            else:
                path = (entry_paths.get(chosen[0], (None, False))[0]
                        if chosen and entry_paths.get(chosen[0], (None, False))[1]
                        else current.get())
                if not os.path.isdir(path):
                    picker_error('資料夾不存在或無法存取：\n' + path)
                    return
            result['path'] = path
            dialog.destroy()
        tk.Button(nav, text='上一層', font=(self.chinese_font, 10), command=up).pack(side='left', padx=(0,6))
        tk.Label(nav, text='路徑', bg=PANEL, fg=TEXT, font=(self.chinese_font, 11)).pack(side='left')
        entry = tk.Entry(nav, textvariable=address, font=(self.chinese_font, 11))
        entry.pack(side='left', fill='x', expand=True, padx=6)
        entry.bind('<Return>', lambda e: go(address.get()))
        tk.Button(nav, text='前往', font=(self.chinese_font, 10), command=lambda: go(address.get())).pack(side='left')
        listing.bind('<Double-Button-1>', enter_folder)
        listing.bind('<Return>', enter_folder)
        drive_list.bind('<<TreeviewSelect>>', choose_drive)
        # Independent mouse wheel scrolling for each pane, including its scrollbar.
        # Bind to these widgets only (not bind_all) to avoid affecting the main GUI.
        def wheel_for(tree):
            def on_wheel(event):
                delta = getattr(event, 'delta', 0)
                if delta:
                    units = -1 if delta > 0 else 1
                    tree.yview_scroll(units, 'units')
                elif getattr(event, 'num', None) in (4, 5):
                    tree.yview_scroll(-1 if event.num == 4 else 1, 'units')
                return 'break'
            return on_wheel
        for tree, scrollbar in ((drive_list, drive_scroll), (listing, bar)):
            callback = wheel_for(tree)
            for target in (tree, scrollbar):
                target.bind('<MouseWheel>', callback)
                target.bind('<Button-4>', callback)
                target.bind('<Button-5>', callback)
        tk.Button(buttons, text='新增資料夾', font=(self.chinese_font, 11),
                  command=new_folder).pack(side='left')
        tk.Button(buttons, text='取消', font=(self.chinese_font, 11),
                  command=dialog.destroy).pack(side='right', padx=(8,0))
        tk.Button(buttons, text=('選擇此 INF' if selection_mode == 'inf' else '選擇此資料夾'), font=(self.chinese_font, 11),
                  command=select).pack(side='right')
        dialog.bind('<Escape>', lambda e: dialog.destroy())
        refresh_drives()
        go(base)
        for widget in self._walk_widgets(dialog):
            try:
                spec = widget.cget('font')
                if spec:
                    from tkinter import font as tkfont
                    f = tkfont.Font(root=dialog, font=spec)
                    widget.configure(font=(f.actual('family'), max(8, round(abs(f.actual('size'))*0.8)),
                                           f.actual('weight')))
            except (tk.TclError, AttributeError, ValueError):
                pass
        dialog.grab_set()
        try:
            dialog.wait_window()
        finally:
            if tree_style.theme_use() != previous_theme:
                tree_style.theme_use(previous_theme)
        self._picker_drive_icon = None
        self._picker_folder_icon = None
        return result['path']

    def _disk_options(self):
        if not self.disks:
            return ['尚未掃描磁碟']
        if self.active == 'Restore':
            try:
                protected, errors = protected_disks(self.disks, self.restore_folder,
                                                      disk_for_path, is_winpe())
            except Exception as exc:
                protected, errors = {}, [str(exc)]
            self._restore_disk_indices = ([] if errors or not self.restore_folder else
                [i for i, d in enumerate(self.disks) if int(d['Number']) not in protected])
            return ([f"Disk {self.disks[i]['Number']} | {self.disks[i]['Model']} | {capacity(self.disks[i]['Size'])}"
                     for i in self._restore_disk_indices] or ['沒有安全的還原目標磁碟（請檢查來源與開機媒體）'])
        return [f"Disk {d['Number']} | {d['Model']} | {capacity(d['Size'])} | {d['BusType']}"
                for d in self.disks]

    def _disk_row(self, panel, label):
        self.disk_selector = self._row(panel, label, self._disk_options())
        if self.active == 'Restore' and not getattr(self, '_restore_disk_indices', []):
            self.disk_selector.configure(state='disabled')
        self.disk_selector.bind('<<ComboboxSelected>>', self._on_disk_selected)
        if self.active == 'Backup' and self.disks:
            selected = next((i for i, d in enumerate(self.disks) if d['Number'] == self.backup_disk_number), 0)
            self.disk_selector.current(selected)

    def _display_disk(self, index):
        if self.disk_details is None:
            return
        if not self.disks or index >= len(self.disks):
            content = '尚無磁碟資訊。'
        else:
            d = self.disks[index]
            content = (f"Disk {d['Number']}  {d['Model']}\n"
                       f"Capacity: {capacity(d['Size'])}  Bus: {d['BusType']}  "
                       f"Style: {d['PartitionStyle']}\n"
                       f"System/Boot marker: Not queried (native scan)\n\n"
                       'Partitions:\n')
            for part in d.get('Partitions', []):
                content += (f"  #{part['Number']} | {capacity(part['Size'])} | "
                            f"{part['Type']} | {part['FileSystem'] or '-'} | "
                            f"{part['DriveLetter'] or '-'} | {part['Label'] or '-'}\n")
            content += ('\nRestore 目標會依安全保護清單過濾；執行前仍會重新驗證。')
        self.disk_details.configure(state='normal')
        self.disk_details.delete('1.0', 'end')
        self.disk_details.insert('1.0', content)
        self.disk_details.configure(state='disabled')

    def _set_scanning_ui(self, running, message=None):
        if self.scan_button is not None:
            self.scan_button.configure(state='disabled' if running else 'normal')
        if self.scan_status is not None:
            self.scan_status.configure(text=message or ('正在掃描磁碟…' if running else '準備就緒'),
                                       fg=ACCENT if running else MUTED)

    def refresh_disks(self):
        if self.driver_loading:
            return
        if self.backup_running:
            return
        if self.scanning:
            return
        self.scanning = True
        self._set_scanning_ui(True)
        def worker():
            try:
                data = scan_disks()
                self.after(0, lambda: self._scan_finished(data, None))
            except Exception as error:
                msg = str(error)
                self.after(0, lambda: self._scan_finished(None, msg))
        threading.Thread(target=worker, daemon=True).start()

    def _scan_finished(self, data, error):
        self.scanning = False
        self._set_scanning_ui(False, '掃描失敗' if error else '掃描完成')
        if error:
            if self.disk_details:
                self.disk_details.configure(state='normal')
                self.disk_details.delete('1.0', 'end')
                self.disk_details.insert('1.0', '磁碟掃描失敗：\n' + error +
                    '\n\n請確認磁碟控制器驅動程式及存取權限。')
                self.disk_details.configure(state='disabled')
            return
        previous_number = None
        if self.disk_selector and self.disks:
            idx = self.disk_selector.current()
            if 0 <= idx < len(self.disks):
                previous_number = self.disks[idx].get('Number')
        self.disks = data
        if self.active == 'Backup' and previous_number is None:
            self.backup_disk_number = data[0]['Number'] if data else None
        chosen_index = next((i for i, d in enumerate(self.disks) if d.get('Number') == previous_number), 0)
        if self.disk_selector:
            options = self._disk_options()
            self.disk_selector.configure(values=options,
                state=('disabled' if self.active == 'Restore' and not self._restore_disk_indices else 'readonly'))
            if self.active == 'Restore':
                chosen_index = (self._restore_disk_indices.index(chosen_index)
                    if chosen_index in self._restore_disk_indices else 0)
            self.disk_selector.current(chosen_index)
        if self.active == 'Restore':
            self._display_disk(self._restore_disk_indices[chosen_index]
                if self._restore_disk_indices else len(self.disks))
        else:
            self._display_disk(chosen_index)
        if self.active == 'Backup':
            self.backup_disk_number = self.disks[chosen_index]['Number'] if self.disks else None
            self._update_backup_partitions()
        elif self.active == 'Restore':
            self._update_restore_target_parts()

if __name__ == '__main__':
    DiskTool().mainloop()
