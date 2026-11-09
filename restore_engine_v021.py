"""Experimental GPT full-disk restore engine for WinPE. Destructive: requires explicit UI confirmation.
Only supports same/larger capacity, standard EFI/MSR/Windows/Recovery layout and 3 WIMs.
"""
import os, json, hashlib, subprocess, tempfile, time, re, threading, sys
from restore_safety import assert_restore_safe
from shrink_layout_v023 import calculate, LayoutError

EFI='c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
MSR='e3c9e316-0b5c-4db8-817d-f92df00215ae'
BASIC='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
RECOVERY='de94bba4-06d1-4d40-a16a-bfd50179d6ac'
MIB=1048576

class RestoreError(RuntimeError): pass

def plan(info, target):
    if info.get('schema_version') != 3 or info.get('status') != 'completed_file_level':
        raise RestoreError('僅支援已完成的 schema 3 Full Disk Backup。')
    if info.get('skipped_partitions') or info.get('required_boot_partitions_not_yet_captured'):
        raise RestoreError('備份有未擷取的必要磁區，拒絕還原。')
    layout=info['restore_layout']
    if layout.get('partition_style') != 'GPT' or target.get('PartitionStyle') not in ('GPT', 'RAW', 'MBR'):
        raise RestoreError('僅支援 GPT 備份還原至 GPT、RAW 或可清除的 MBR 目標磁碟。')
    parts=sorted(layout['partitions'],key=lambda p:int(p['offset_bytes']))
    if len(parts)!=4 or [p['partition_type_guid'].lower() for p in parts]!=[EFI,MSR,BASIC,RECOVERY]:
        raise RestoreError('分割配置非標準 EFI/MSR/Windows/Recovery 四磁區，本版拒絕還原。')
    for p in parts:
        if int(p['offset_bytes'])%MIB or int(p['size_bytes'])%MIB:
            raise RestoreError('Partition offset/size 不是整數 MiB，無法無損重建配置。')
    if int(parts[0]['offset_bytes']) != MIB:
        raise RestoreError('EFI 不是從 1MiB 開始，本版不支援。')
    for a,b in zip(parts,parts[1:]):
        if int(a['offset_bytes'])+int(a['size_bytes']) != int(b['offset_bytes']):
            raise RestoreError('磁區間存在未支援的空隙。')
    caps={int(c['number']):c for c in info['captures']}
    if set(caps)!={int(parts[i]['number']) for i in (0,2,3)}:
        raise RestoreError('EFI/Windows/Recovery WIM 對應不完整。')
    if any(caps[int(p['number'])]['filesystem'].upper()!=fs for p,fs in [(parts[0],'FAT32'),(parts[2],'NTFS'),(parts[3],'NTFS')]):
        raise RestoreError('WIM 檔案系統與預期不符。')
    try:
        parts,shrunk=calculate(parts, int(layout['disk_size_bytes']), int(target['Size']))
    except LayoutError as exc:
        raise RestoreError(str(exc)) from exc
    return parts,caps

def run_command(args, log, status, cwd=None):
    log('CMD: '+ ' '.join(args))
    proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,
                          text=True,encoding='mbcs',errors='replace',cwd=cwd,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    last=[]
    try:
        for line in proc.stdout:
            line=line.rstrip()
            if line:
                log(line)
                last.append(line)
                if len(last)>8:last.pop(0)
                m=re.search(r'(\d+(?:\.\d+)?)\s*%',line)
                if m: status(float(m.group(1)),line)
        rc=proc.wait()
    finally:
        if proc.poll() is None: proc.kill()
    if rc:
        raise RestoreError('%s 失敗 (exit %d): %s'%(args[0],rc,' | '.join(last[-3:])))

def diskpart(lines, log):
    with tempfile.NamedTemporaryFile(mode='w',suffix='.txt',prefix='disktool_restore_',encoding='ascii',delete=False) as f:
        path=f.name
        f.write('\n'.join(lines)+'\n')
    try: run_command(['diskpart','/s',path],log,lambda *_:None)
    finally:
        try: os.unlink(path)
        except OSError: pass

def free_letters():
    used={chr(x) for x in range(65,91) if os.path.exists(chr(x)+':\\')}
    pool=[x for x in 'STUVWYZQ' if x not in used and x!='X']
    if len(pool)<3:raise RestoreError('找不到 3 個可用磁碟代號。')
    return pool[:3]

def restore(folder,target, preflight, scan, disk_for_path, progress):
    """Called in background thread after user confirms. No cancellation after clean starts."""
    if os.name!='nt': raise RestoreError('僅支援 Windows/WinPE。')
    if not os.path.isfile(os.path.join(folder,'BackupInfo.json')): raise RestoreError('缺少 BackupInfo.json')
    with open(os.path.join(folder,'BackupInfo.json'),encoding='utf-8') as f: info=json.load(f)
    parts,caps=plan(info,target)
    number=int(target['Number'])
    logpath=os.path.join(folder,'Restore_%s.log'%time.strftime('%Y%m%d_%H%M%S'))
    start=time.monotonic()
    with open(logpath,'w',encoding='utf-8',buffering=1) as output:
        def log(msg): output.write('%s %s\n'%(time.strftime('%H:%M:%S'),msg))
        def notify(stage,pct,msg):
            elapsed=time.monotonic()-start
            progress(stage,pct,elapsed,msg,logpath)
        log('v0.23 EXPERIMENTAL RESTORE | TARGET Disk %d | %s'%(number,target.get('Model','')))
        if int(target['Size'])<int(info['restore_layout']['disk_size_bytes']):
            log('SHRINK TARGET: Windows partition resized. 64GiB minimum is NOT a verified WIM size; DISM may fail if actual files exceed free space.')
        notify('驗證備份',0,'正在重新執行完整 SHA-256 預檢')
        checked=preflight(folder,target,lambda m:notify('驗證備份',0,m))
        blockers=[b for b in checked['blockers'] if 'Preview 不包含' not in b]
        if blockers:raise RestoreError('安全預檢未通過：'+'; '.join(blockers))
        if int(checked['target']['Number'])!=number:raise RestoreError('目標磁碟號碼已變更。')
        # No backup, tool or host system volumes may be on target. X: RAM drive is not physical.
        for label,path in [('備份來源',folder),('程式',os.path.abspath(sys.executable if getattr(sys,'frozen',False) else __file__))]:
            if os.path.splitdrive(path)[0].upper()=='X:':continue
            if disk_for_path(path)==number:raise RestoreError(label+'位於目標 SSD，禁止還原。')
        # Recheck identity immediately before destructive action.
        fresh=next((d for d in scan() if int(d['Number'])==number),None)
        if not fresh or fresh.get('DiskIdentity')!=target.get('DiskIdentity') or int(fresh['Size'])!=int(target['Size']):
            raise RestoreError('目標 SSD 身分或容量改變，拒絕執行。')
        assert_restore_safe(scan(), fresh, folder, disk_for_path, True)
        letters=free_letters()
        notify('建立磁區',0,'開始清除目標磁碟並重建 GPT；此階段不可取消')
        # Exact MiB sizes/offsets, one diskpart transaction; explicitly choose target disk.
        lines=['select disk %d'%number,'clean','convert gpt']
        names=['efi','msr','windows','recovery']
        for idx,p in enumerate(parts):
            size=int(p['size_bytes'])//MIB
            if idx==0:
                lines+=['create partition efi size=%d'%size,'format quick fs=fat32 label=System','assign letter=%s'%letters[0]]
            elif idx==1:lines+=['create partition msr size=%d'%size]
            elif idx==2:
                lines+=['create partition primary size=%d'%size,'format quick fs=ntfs label=Windows','assign letter=%s'%letters[1]]
            else:
                lines+=['create partition primary size=%d'%size,'format quick fs=ntfs label=Recovery',
                        'set id=%s override'%RECOVERY,'assign letter=%s'%letters[2],'gpt attributes=0x8000000000000001']
        diskpart(lines,log)
        # Diskpart may return zero despite a command failing: verify every partition and mount before DISM.
        fresh=next((d for d in scan() if int(d['Number'])==number),None)
        if not fresh:raise RestoreError('DiskPart 後無法掃描目標磁碟。')
        actual=sorted(fresh['Partitions'],key=lambda p:int(p['Offset']))
        if len(actual)!=4:raise RestoreError('磁區數量錯誤；已停止套用 WIM。')
        for expected,found in zip(parts,actual):
            if (int(expected['offset_bytes'])!=int(found['Offset']) or
                int(expected['size_bytes'])!=int(found['Size']) or
                expected['partition_type_guid'].lower()!=found['PartitionTypeGuid'].lower()):
                raise RestoreError('DiskPart 配置不符；已停止套用 WIM。')
        for letter in letters:
            if not os.path.isdir(letter+':\\') or disk_for_path(letter+':\\')!=number:
                raise RestoreError('還原磁區代號無法驗證：'+letter)
        weights=[int(caps[int(parts[i]['number'])]['image_size_bytes']) for i in (0,2,3)]
        total=sum(weights)
        done=0
        for n,idx in enumerate((0,2,3)):
            p=parts[idx]; cap=caps[int(p['number'])]
            img=os.path.join(folder,cap['image_file'])
            letter=letters[n]
            def step(percent,line,base=done,weight=weights[n],label=letter):
                overall=100.0*(base+weight*min(100,max(0,percent))/100.0)/total
                notify('套用 WIM',min(97,overall), 'Partition %s → %s: %s'%(p['number'],label,line))
            notify('套用 WIM',100.0*done/total,'正在套用 '+cap['image_file'])
            run_command(['dism','/Apply-Image','/ImageFile:'+img,'/Index:1','/ApplyDir:'+letter+':\\'],log,step)
            done+=weights[n]
        notify('修復開機',98,'正在重新建立乾淨的 UEFI BCD（保留舊檔備份）')
        # The EFI WIM contains the source machine's BCD store. Its loader can
        # reference partition identities that no longer exist after DiskPart clean.
        # Preserve that store, then generate a fresh one for the restored Windows.
        bcd_dir=os.path.join(letters[0]+':\\','EFI','Microsoft','Boot')
        old_bcd=os.path.join(bcd_dir,'BCD')
        saved_bcd=os.path.join(bcd_dir,'BCD.DiskToolBackup')
        if not os.path.isfile(old_bcd):
            raise RestoreError('EFI WIM 中找不到原始 BCD；拒絕自動替換。')
        if os.path.exists(saved_bcd):
            raise RestoreError('EFI 已存在 BCD.DiskToolBackup，避免覆蓋既有備份。')
        run_command(['attrib','-s','-h','-r',old_bcd],log,lambda *_:None)
        os.replace(old_bcd,saved_bcd)
        log('原始 BCD 已備份至 '+saved_bcd)
        try:
            run_command(['bcdboot',letters[1]+':\\Windows','/s',letters[0]+':','/f','UEFI','/c'],log,lambda *_:None)
            if not os.path.isfile(old_bcd):
                raise RestoreError('BCDBoot 執行後未找到新 BCD。')
            run_command(['bcdedit','/store',old_bcd,'/enum','{default}'],log,lambda *_:None)
        except Exception:
            # Leave the previous store available if boot generation fails.
            if os.path.exists(old_bcd):
                os.replace(old_bcd,old_bcd+'.DiskToolFailed')
            os.replace(saved_bcd,old_bcd)
            log('BCD 建立/驗證失敗，已恢復來源 BCD。')
            raise

        notify('完成',100,'WIM 套用與 BCDBoot 已完成；請實際測試開機')
        log('COMPLETED. Boot not yet verified. Recovery registration may require reagentc.')
    return logpath
