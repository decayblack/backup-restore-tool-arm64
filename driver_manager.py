"""WinPE driver discovery and on-demand loading. No PowerShell dependency."""
from pathlib import Path
from datetime import datetime
import os
import platform
import re
import subprocess
import sys
import threading


def exe_directory():
    return Path(sys.executable if getattr(sys, 'frozen', False) else __file__).resolve().parent


def architecture():
    machine = platform.machine().lower()
    return 'arm64' if machine in ('arm64', 'aarch64') else 'amd64' if machine in ('amd64', 'x86_64') else machine


def find_infs(path, single=False):
    path = Path(path)
    if single:
        if not path.is_file() or path.suffix.lower() != '.inf':
            raise ValueError('請選擇有效的 .inf 檔案。')
        return [path.resolve()]
    if not path.is_dir():
        raise ValueError('找不到指定的 Driver 資料夾。')
    # Preserve original INF/SYS/CAT relative paths; do not copy or flatten packages.
    return sorted((p.resolve() for p in path.rglob('*') if p.is_file() and p.suffix.lower() == '.inf'),
                  key=lambda p: str(p).lower())


def check_arch(inf):
    """Conservative architecture guard based on INF decorated install sections.

    Ambiguous/undecorated INFs are left to drvload's authoritative validation.
    """
    try:
        data = inf.read_bytes()
        if data.startswith((b'\xff\xfe', b'\xfe\xff')):
            content = data.decode('utf-16', errors='replace')
        else:
            content = data.decode('utf-8-sig', errors='replace')
        # Strip INF comments; only check explicit NT platform decorations.
        content = '\n'.join(line.split(';', 1)[0] for line in content.splitlines())
        decorations = set(x.lower() for x in re.findall(r'\.NT(amd64|arm64|x86)\b', content, re.I))
        arch = architecture()
        if decorations and arch not in decorations:
            return False, 'INF 僅宣告其他 CPU 架構：' + ', '.join(sorted(decorations))
    except (OSError, UnicodeError) as exc:
        return False, '無法讀取 INF：' + str(exc)
    return True, ''


def load_drivers(path, single=False, notify=None, cancel=None):
    """Load in current WinPE session using pnputil first and drvload as fallback. Return structured summary.

    Never claim an installed device exists solely because a command returned 0.
    """
    notify = notify or (lambda message: None)
    cancel = cancel or threading.Event()
    source = Path(path)
    log_dir = exe_directory() / 'logs'
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_dir = Path(os.environ.get('TEMP', '.')) / 'BackupRestoreTool_logs'
        log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / ('driver_' + datetime.now().strftime('%Y%m%d_%H%M%S_%f') + '.log')
    result = {'found': 0, 'loaded': 0, 'failed': 0, 'skipped': 0, 'log': str(log_path), 'messages': []}
    def record(msg):
        result['messages'].append(msg)
        with log_path.open('a', encoding='utf-8') as stream:
            stream.write(msg + '\n')
        notify(msg)
    record('Driver source: ' + str(source))
    record('CPU architecture: ' + architecture())
    infs = find_infs(source, single)
    result['found'] = len(infs)
    record('INF count: ' + str(len(infs)))
    system32 = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32')
    pnputil = os.path.join(system32, 'pnputil.exe')
    drvload = os.path.join(system32, 'drvload.exe')
    if os.name != 'nt' or not (os.path.isfile(pnputil) or os.path.isfile(drvload)):
        record('WinPE pnputil.exe / drvload.exe 不存在；未執行載入。')
        result['skipped'] = len(infs)
        return result
    for idx, inf in enumerate(infs, 1):
        if cancel.is_set():
            record('作業取消；未處理其餘 INF。')
            result['skipped'] += len(infs) - idx + 1
            break
        ok, reason = check_arch(inf)
        if not ok:
            result['skipped'] += 1
            record('[SKIP] ' + str(inf) + ' | ' + reason)
            continue
        record('[LOAD %d/%d] %s' % (idx, len(infs), inf))
        attempts = []
        if os.path.isfile(pnputil):
            attempts.append(('pnputil', [pnputil, '/add-driver', str(inf), '/install']))
        if os.path.isfile(drvload):
            attempts.append(('drvload', [drvload, str(inf)]))
        succeeded = False
        for tool, command in attempts:
            try:
                proc = subprocess.run(command, capture_output=True, text=True,
                                      errors='replace', timeout=120,
                                      creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
                output = ((proc.stdout or '') + '\n' + (proc.stderr or '')).strip()
                record('%s exit=%d' % (tool, proc.returncode))
                if output:
                    record('Output: ' + output[:6000])
                if proc.returncode == 0:
                    succeeded = True
                    result['loaded'] += 1
                    record('[OK] %s succeeded; 已加入或已存在的驅動不代表磁碟必然可見，請重新掃描確認。' % tool)
                    break
                record('[WARN] %s failed; %s' % (tool, '嘗試備援載入' if tool == 'pnputil' and len(attempts) > 1 else ''))
            except (OSError, subprocess.TimeoutExpired) as exc:
                record('[WARN] %s: %s' % (tool, exc))
        if not succeeded:
            result['failed'] += 1
            record('[FAIL] 所有可用載入方式均失敗: ' + str(inf))
    record('SUMMARY found={found} loaded={loaded} failed={failed} skipped={skipped}'.format(**result))
    return result
