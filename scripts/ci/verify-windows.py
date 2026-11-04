#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
import pefile, sys
allowed = {
    'KERNEL32.dll', 'USER32.dll', 'GDI32.dll', 'ADVAPI32.dll',
    'WS2_32.dll', 'CRYPT32.dll', 'BCRYPT.dll', 'SHELL32.dll',
    'OLE32.dll', 'OLEAUT32.dll', 'COMDLG32.dll', 'IMM32.dll',
    'WINMM.dll', 'WINSPOOL.DRV', 'NETAPI32.dll', 'USERENV.dll',
    'VERSION.dll', 'UXTHEME.dll', 'DWMAPI.dll', 'D3D9.dll',
    'msvcrt.dll', 'AUTHZ.dll', 'WTSAPI32.dll', 'IPHLPAPI.dll',
    'DNSAPI.dll', 'MPR.dll',
    'DWrite.dll', 'SETUPAPI.dll', 'SHCORE.dll', 'SHLWAPI.dll',
    'Secur32.dll', 'WINHTTP.dll', 'd3d11.dll', 'd3d12.dll', 'dxgi.dll',
    'mscms.dll',  # Windows color management, used by Qt 6.12.
    'ncrypt.dll', 'ntdll.dll',
}
allowed_lower = {x.lower() for x in allowed}
# Windows API Sets (api-ms-win-*) are virtual forwarders to system DLLs.
def is_allowed(d):
    dl = d.lower()
    return dl in allowed_lower or dl.startswith('api-ms-win-')
pe = pefile.PE(sys.argv[1], fast_load=True)
pe.parse_data_directories(directories=[
    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
imports = sorted({e.dll.decode() for e in pe.DIRECTORY_ENTRY_IMPORT})
print('Imported DLLs:')
for d in imports:
    print(f'  {d}')
unexpected = [d for d in imports if not is_allowed(d)]
if unexpected:
    print(f'\nERROR: non-system DLL imports detected: {unexpected}')
    sys.exit(1)
print('\nOK: only Windows system DLLs are imported.')

dc = pe.OPTIONAL_HEADER.DllCharacteristics
flags = {
    'HIGH_ENTROPY_VA':  0x0020,
    'DYNAMIC_BASE':     0x0040,  # ASLR
    'NX_COMPAT':        0x0100,  # DEP
    'GUARD_CF':         0x4000,  # informational; mingw doesn't emit /guard:cf
}
print(f'DllCharacteristics = 0x{dc:04x}')
missing = []
for name, bit in flags.items():
    ok = bool(dc & bit)
    print(f'  {name:18s} {"YES" if ok else "no"}')
    # GUARD_CF is informational only.
    if not ok and name != 'GUARD_CF':
        missing.append(name)
if missing:
    print(f'\nERROR: missing required PE security flags: {missing}')
    sys.exit(1)
print('\nOK: ASLR + DEP + High-Entropy-VA all enabled.')
if pe.FILE_HEADER.TimeDateStamp != 0:
    sys.exit('ERROR: stripping reintroduced a PE build timestamp')
print('OK: PE build timestamp remains zero.')
