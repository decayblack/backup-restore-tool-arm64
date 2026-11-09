"""Conservative GPT layout planner for WIM-based smaller-target restores.
No disk writes. This is NOT a guarantee that a WIM fits the destination.
"""
EFI='c12a7328-f81f-11d2-ba4b-00a0c93ec93b'
MSR='e3c9e316-0b5c-4db8-817d-f92df00215ae'
BASIC='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'
RECOVERY='de94bba4-06d1-4d40-a16a-bfd50179d6ac'
MIB=1048576
MIN_WINDOWS_MIB=64*1024
GPT_TAIL_MIB=2

class LayoutError(ValueError): pass

def calculate(parts, source_size, target_size):
    """Return four planned partitions; preserves same-size layout on larger disks.

    Smaller targets keep EFI/MSR/Recovery size and give Windows remaining space.
    Reserve 2 MiB at disk end for GPT metadata/alignment.
    """
    parts=sorted(parts,key=lambda p:int(p['offset_bytes']))
    if len(parts)!=4 or [str(p['partition_type_guid']).lower() for p in parts]!=[EFI,MSR,BASIC,RECOVERY]:
        raise LayoutError('僅支援標準 EFI/MSR/Windows/Recovery GPT 四磁區。')
    for p in parts:
        if int(p['offset_bytes'])%MIB or int(p['size_bytes'])%MIB or int(p['size_bytes'])<=0:
            raise LayoutError('來源 Partition 必須以 MiB 對齊。')
    if int(parts[0]['offset_bytes'])!=MIB:
        raise LayoutError('來源 EFI 起點不是 1MiB。')
    for a,b in zip(parts,parts[1:]):
        if int(a['offset_bytes'])+int(a['size_bytes'])!=int(b['offset_bytes']):
            raise LayoutError('來源 Partition 存在空隙，拒絕自動縮容。')
    planned=[dict(p) for p in parts]
    if target_size>=source_size:
        return planned,False
    disk_mib=int(target_size)//MIB
    efi_mib=int(parts[0]['size_bytes'])//MIB
    msr_mib=int(parts[1]['size_bytes'])//MIB
    recovery_mib=int(parts[3]['size_bytes'])//MIB
    win_mib=disk_mib-1-GPT_TAIL_MIB-efi_mib-msr_mib-recovery_mib
    if win_mib<MIN_WINDOWS_MIB:
        raise LayoutError('目標 SSD 容量不足：Windows Partition 至少保留 64GiB；此限制不代表 WIM 一定可放入。')
    if win_mib>=int(parts[2]['size_bytes'])//MIB:
        raise LayoutError('計算後 Windows Partition 未縮小，配置異常。')
    planned[2]['size_bytes']=win_mib*MIB
    planned[3]['offset_bytes']=planned[2]['offset_bytes']+planned[2]['size_bytes']
    if planned[3]['offset_bytes']+planned[3]['size_bytes']>int(target_size)-MIB:
        raise LayoutError('Recovery 超出目標 SSD 邊界。')
    return planned,True
