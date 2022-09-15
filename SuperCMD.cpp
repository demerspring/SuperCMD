// MinGW compile: g++ SuperCMD.cpp -o SuperCMD.exe -municode -luserenv -mconsole
// VC++ compile: cl SuperCMD_v2.cpp /D WIN32 /D _WINDOWS /D _UNICODE /D UNICODE /link /SUBSYSTEM:CONSOLE /OUT:SuperCMD.exe kernel32.lib user32.lib advapi32.lib userenv.lib

#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <Shellapi.h>
#include <winsvc.h>
#include <Userenv.h>

#pragma comment(lib, "userenv.lib")

bool GetPrivilege(HANDLE ProcessHandle, LPCWSTR lpName);
bool GetToken(HANDLE TokenHandle, LPCWSTR lpName);
bool GetAllTokens(HANDLE TokenHandle);
HANDLE CreateProcessFromToken(LPWSTR szCMDLine, DWORD dwProcessId, WORD wShowWindow, DWORD dwCreateFlags);
HANDLE CreateSystemProcess(LPWSTR szCMDLine, WORD wShowWindow, DWORD dwCreateFlags);
HANDLE CreateTrustedInstallerProcess(LPWSTR szCMDLine);
int GetCommandIndex(LPCWSTR szCommand);
void ShowHelp();

int wmain()
{
	wchar_t szCMDLine[260];
	int nIndex;
	
	if (!GetPrivilege(GetCurrentProcess(),SE_DEBUG_NAME))
	{
		printf("Error: GetPrivilege() failed! Error code: %d\n", GetLastError());
		return -1;
	}

	GetSystemWindowsDirectoryW(szCMDLine, 260);

	if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwWow64ReadVirtualMemory64"))
	{
		wcscat_s(szCMDLine, 260, L"\\SysNative\\");
	}
	else
	{
		wcscat_s(szCMDLine, 260, L"\\System32\\");
	}

	wcscat_s(szCMDLine, 260, L"cmd.exe");

	if ((nIndex = GetCommandIndex(L"/TIP")) != -1)
	{
		if (nIndex != __argc - 1)
		{
			wcscpy_s(szCMDLine, 260, L"");
			int i;
			for (i = nIndex + 1; i < __argc; i++)
			{
				wcscat_s(szCMDLine, 260, __wargv[i]);
				wcscat_s(szCMDLine, 260, L" ");
			} 
		}
		HANDLE hProcess = CreateTrustedInstallerProcess(szCMDLine);
		if (hProcess == INVALID_HANDLE_VALUE)
		{
			exit(GetLastError());
		}
	}
	else if ((nIndex = GetCommandIndex(L"/TI")) != -1 || (nIndex = GetCommandIndex(L"-TI")) != -1)
	{
		int i;
		GetModuleFileNameW(NULL, szCMDLine, 260);
		wcscat_s(szCMDLine, 260, L" /TIP");
		if (nIndex != __argc - 1)
		{
			for (i = nIndex + 1; i < __argc; i++)
			{
				wcscat_s(szCMDLine, 260, L" ");
				wcscat_s(szCMDLine, 260, __wargv[i]);
			} 
		}
		HANDLE hProcess = CreateSystemProcess(szCMDLine, SW_HIDE, CREATE_NO_WINDOW);
		if (hProcess != INVALID_HANDLE_VALUE)
		{
			WaitForSingleObject(hProcess, INFINITE);
			DWORD dwExitCode;
			GetExitCodeProcess(hProcess, &dwExitCode);
			if (dwExitCode != 0)
			{
				printf("Error: CreateTrustedInstallerProcess() failed! Error code: %d\n", dwExitCode);
			}
		}
	}
	else if ((nIndex = GetCommandIndex(L"/S")) != -1 || (nIndex = GetCommandIndex(L"-S")) != -1)
	{
		if (nIndex != __argc - 1)
		{
			wcscpy_s(szCMDLine, 260, L"");
			int i;
			for (i = nIndex + 1; i < __argc; i++)
			{
				wcscat_s(szCMDLine, 260, __wargv[i]);
				wcscat_s(szCMDLine, 260, L" ");
			} 
		}
		CreateSystemProcess(szCMDLine, SW_SHOWNORMAL, CREATE_NEW_CONSOLE);
	}
	else
	{
		ShowHelp();
	}
	return 0;
}

void ShowHelp()
{
	printf(	"SuperCMD v2.0\n"
			"Copyright (C) 2022\n\n"
			"Usage:\n"
			"\tSuperCMD <option> [commandline]\n\n"
			"Required options:\n"
			"\t-S\t\tCreate process with SYSTEM user.\n"
			"\t-TI\t\tCreate process with SYSTEM user and TrustedInstaller token.\n\n"
			"Optionals:\n"
			"\tcommandline\tCreate a process with a custom command.\n\n"
			);
}

int GetCommandIndex(LPCWSTR szCommand)
{/*
	int i;
	for (i = 1; i < __argc; i++)
	{
		if (wcsicmp(szCommand, __wargv[i]) == 0)
		{
			return i;
		}
	}*/
	if (__argc < 2) return -1;
	if (wcsicmp(szCommand, __wargv[1]) == 0)
	{
		return 1;
	}
	return -1;
}

HANDLE CreateSystemProcess(LPWSTR szCMDLine, WORD wShowWindow, DWORD dwCreateFlags)
{
	DWORD dwUserSessionId;
	DWORD dwWinLogonPID = -1;

	if ((dwUserSessionId = WTSGetActiveConsoleSessionId()) == 0xFFFFFFFF)
	{
		printf("Error: GetActiveConsoleSessionId() failed! Error code: %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("Error: CreateToolhelp32Snapshot() failed! Error code: %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	if (Process32FirstW(hSnapshot, &ProcessEntry))
	{
		do
		{
			if (wcsicmp(L"winlogon.exe", ProcessEntry.szExeFile) == 0)
			{
				DWORD dwSessionID;
				if (ProcessIdToSessionId(ProcessEntry.th32ProcessID, &dwSessionID))
				{
					if (dwSessionID != dwUserSessionId) continue;
					dwWinLogonPID = ProcessEntry.th32ProcessID;
					break;
				}
			}
		} while (Process32NextW(hSnapshot, &ProcessEntry));
	}
	CloseHandle(hSnapshot);

	if (dwWinLogonPID == -1)
	{
		printf("Error: Couldn't find winlogon.exe process.\n");
		return INVALID_HANDLE_VALUE;
	}
	HANDLE hProcess = CreateProcessFromToken(szCMDLine, dwWinLogonPID, wShowWindow, dwCreateFlags);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("Error: CreateProcessFromToken() failed! Error code: %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	return hProcess;
}

HANDLE CreateTrustedInstallerProcess(LPWSTR szCMDLine)
{
	SC_HANDLE hSC = OpenSCManagerW(NULL, NULL, GENERIC_EXECUTE);
	if (hSC != NULL)
	{
		SC_HANDLE hSvc = OpenServiceW(hSC, L"TrustedInstaller", SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
		if (hSvc != NULL)
		{
			SERVICE_STATUS status;
			if (QueryServiceStatus(hSvc, &status))
			{
				if (status.dwCurrentState == SERVICE_STOPPED)
				{
					if (StartServiceW(hSvc, NULL, NULL) == FALSE)
					{
						printf("Error: StartService() failed! Error code: %d\n", GetLastError());
						//return INVALID_HANDLE_VALUE;
					}
					while (::QueryServiceStatus(hSvc, &status) == TRUE)
					{
						Sleep(status.dwWaitHint);
						if (status.dwCurrentState == SERVICE_RUNNING)
						{
							break;
						}
					}
				}
			}
			CloseServiceHandle(hSvc);
		}
		CloseServiceHandle(hSC);
	}

	DWORD dwTIPID = -1;

	PROCESSENTRY32W ProcessEntry;
	ProcessEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		printf("Error: CreateToolhelp32Snapshot() failed! Error code: %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	if (Process32FirstW(hSnapshot, &ProcessEntry))
	{
		do
		{
			if (wcsicmp(L"TrustedInstaller.exe", ProcessEntry.szExeFile) == 0)
			{
				dwTIPID = ProcessEntry.th32ProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &ProcessEntry));
	}
	CloseHandle(hSnapshot);

	if (dwTIPID == -1)
	{
		printf("Error: Couldn't find TrustedInstaller.exe process.\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	HANDLE hProcess = CreateProcessFromToken(szCMDLine, dwTIPID, SW_SHOWNORMAL, CREATE_NEW_CONSOLE);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("Error: CreateProcessFromToken() failed! Error code: %d\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}
	return hProcess;
}

HANDLE CreateProcessFromToken(LPWSTR szCMDLine, DWORD dwProcessId, WORD wShowWindow, DWORD dwCreateFlags)
{
	wchar_t lpDesktop[] = L"WinSta0\\Default";
	bool bRet = true;
	STARTUPINFOW StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInfo = { 0 };
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (hProc != NULL)
	{
		HANDLE hToken, hDupToken;
		if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken))
		{
			if (DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityIdentification, TokenPrimary, &hDupToken))
			{
				LPVOID lpEnv;
				if (CreateEnvironmentBlock(&lpEnv, hToken, 1))
				{
					GetAllTokens(hDupToken);
					StartupInfo.lpDesktop = lpDesktop;
					StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
					StartupInfo.wShowWindow = wShowWindow;
					if (!CreateProcessWithTokenW(
						hDupToken,
						LOGON_WITH_PROFILE,
						NULL,
						szCMDLine,
						dwCreateFlags | CREATE_UNICODE_ENVIRONMENT,
						lpEnv,
						NULL,
						&StartupInfo,
						&ProcessInfo))
					{
						if (!CreateProcessAsUserW(hDupToken,
							NULL,
							szCMDLine,
							NULL,
							NULL,
							NULL,
							CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
							lpEnv,
							NULL,
							&StartupInfo,
							&ProcessInfo))
						{
							bRet = false;
						}
					}
					DestroyEnvironmentBlock(lpEnv);
				}
				else bRet = false;
				CloseHandle(hDupToken);
			}
			else bRet = false;
			CloseHandle(hToken);
		}
		else bRet = false;
		CloseHandle(hProc);
	}
	else bRet = false;
	if (bRet) return ProcessInfo.hProcess;
	return INVALID_HANDLE_VALUE;
}

bool GetPrivilege(HANDLE ProcessHandle,LPCWSTR lpName)
{
	bool bRet = false;
	HANDLE hCurrentProcessToken;
	if (OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hCurrentProcessToken))
	{
		if (GetToken(hCurrentProcessToken, lpName)) bRet = true;
		CloseHandle(hCurrentProcessToken);
	}
	return bRet;
}

bool GetToken(HANDLE TokenHandle, LPCWSTR lpName)
{
	bool bRet = false;
	if (TokenHandle != INVALID_HANDLE_VALUE)
	{
		LUID Luid;
		if (LookupPrivilegeValueW(NULL, lpName, &Luid))
		{
			TOKEN_PRIVILEGES TokenPrivileges;

			TokenPrivileges.PrivilegeCount = 1;
			TokenPrivileges.Privileges[0].Luid = Luid;
			TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TokenPrivileges), NULL, NULL)) bRet = true;
		}
	}
	return bRet;
}

bool GetAllTokens(HANDLE TokenHandle)
{
	return GetToken(TokenHandle, SE_CREATE_TOKEN_NAME) &&
		GetToken(TokenHandle, SE_ASSIGNPRIMARYTOKEN_NAME) &&
		GetToken(TokenHandle, SE_LOCK_MEMORY_NAME) &&
		GetToken(TokenHandle, SE_INCREASE_QUOTA_NAME) &&
		GetToken(TokenHandle, SE_UNSOLICITED_INPUT_NAME) &&
		GetToken(TokenHandle, SE_MACHINE_ACCOUNT_NAME) &&
		GetToken(TokenHandle, SE_TCB_NAME) &&
		GetToken(TokenHandle, SE_SECURITY_NAME) &&
		GetToken(TokenHandle, SE_TAKE_OWNERSHIP_NAME) &&
		GetToken(TokenHandle, SE_LOAD_DRIVER_NAME) &&
		GetToken(TokenHandle, SE_SYSTEM_PROFILE_NAME) &&
		GetToken(TokenHandle, SE_SYSTEMTIME_NAME) &&
		GetToken(TokenHandle, SE_PROF_SINGLE_PROCESS_NAME) &&
		GetToken(TokenHandle, SE_INC_BASE_PRIORITY_NAME) &&
		GetToken(TokenHandle, SE_CREATE_PAGEFILE_NAME) &&
		GetToken(TokenHandle, SE_CREATE_PERMANENT_NAME) &&
		GetToken(TokenHandle, SE_BACKUP_NAME) &&
		GetToken(TokenHandle, SE_RESTORE_NAME) &&
		GetToken(TokenHandle, SE_SHUTDOWN_NAME) &&
		GetToken(TokenHandle, SE_DEBUG_NAME) &&
		GetToken(TokenHandle, SE_AUDIT_NAME) &&
		GetToken(TokenHandle, SE_SYSTEM_ENVIRONMENT_NAME) &&
		GetToken(TokenHandle, SE_CHANGE_NOTIFY_NAME) &&
		GetToken(TokenHandle, SE_REMOTE_SHUTDOWN_NAME) &&
		GetToken(TokenHandle, SE_UNDOCK_NAME) &&
		GetToken(TokenHandle, SE_SYNC_AGENT_NAME) &&
		GetToken(TokenHandle, SE_ENABLE_DELEGATION_NAME) &&
		GetToken(TokenHandle, SE_MANAGE_VOLUME_NAME) &&
		GetToken(TokenHandle, SE_IMPERSONATE_NAME) &&
		GetToken(TokenHandle, SE_CREATE_GLOBAL_NAME) &&
		GetToken(TokenHandle, SE_TRUSTED_CREDMAN_ACCESS_NAME) &&
		GetToken(TokenHandle, SE_RELABEL_NAME) &&
		GetToken(TokenHandle, SE_INC_WORKING_SET_NAME) &&
		GetToken(TokenHandle, SE_TIME_ZONE_NAME) &&
		GetToken(TokenHandle, SE_CREATE_SYMBOLIC_LINK_NAME);
}
