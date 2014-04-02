// hookFsio.cpp : 定义控制台应用程序的入口点。
//


#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <string>
#include <Shlwapi.h>

#define		REGEDIT_THUNDER_SUB_KEY						L"SOFTWARE\\Thunder Network\\ThunderOem\\thunder_backwnd"
#define		REGEDIT_THUNDER_KEY_VALUE_PATH				L"Path"
#define		REGEDIT_THUNDER_KEY_VALUE_VERSION			L"Version"
#define		REGEDIT_THUNDER_KEY_VALUE_INTASLLDIR		L"instdir"

BOOL GetThunderInstallDir(std::wstring& wszInstallDir)
{
	const size_t cdwBufferSize = 512;
	wchar_t szBuffer[cdwBufferSize] = {0};
	DWORD dwBufferSize = cdwBufferSize;
	DWORD dwType = (DWORD)-1;

	if (ERROR_SUCCESS == SHGetValue(HKEY_LOCAL_MACHINE, REGEDIT_THUNDER_SUB_KEY, REGEDIT_THUNDER_KEY_VALUE_INTASLLDIR, &dwType, szBuffer, &dwBufferSize))
	{
		if (wcslen(szBuffer) > 0)
		{
			wszInstallDir = szBuffer;
			if (wszInstallDir[wszInstallDir.length()-1] != L'\\')
			{
				wszInstallDir += L"\\program\\thunder.exe";
			}
			return TRUE;
		}

		return FALSE;
	}

	return FALSE;
}

int _tmain(int argc, _TCHAR* argv[])
{

	std::wstring programPath;
	GetThunderInstallDir(programPath);
	
	programPath = L"\"" + programPath + L"\"";
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi = {0};
	BOOL isCreateSuccesss = CreateProcessW(NULL ,(LPWSTR)programPath.c_str(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	wchar_t fileName[MAX_PATH] = {0};
	GetModuleFileName(NULL, fileName, MAX_PATH);
	std::wstring strFileName = fileName;
	int index = strFileName.rfind(L"\\");
	strFileName = strFileName.substr(0, index+1);
	strFileName += L"hookFsioDll.dll";

	LPVOID pAddress = VirtualAllocEx(pi.hProcess,NULL, (strFileName.length()+1)*sizeof(wchar_t), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	SIZE_T sizeWrite = 0;
	WriteProcessMemory(pi.hProcess,pAddress,strFileName.c_str(),(strFileName.length()+1)*sizeof(wchar_t), &sizeWrite);
	DWORD threadId;
	CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, pAddress, 0, &threadId);

	return 0;
}

