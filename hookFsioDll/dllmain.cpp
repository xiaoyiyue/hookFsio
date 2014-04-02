// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <TlHelp32.h>
#include <string>
#include <DbgHelp.h>
#include <ShlObj.h>
#include <vector>
#include "detours\detours.h"
#include "xlfs.h"

typedef long (WINAPI *pfnXlfsOpen)  (const wchar_t * filePath, const wchar_t * openMode, XLFS_FILE_HANDLE *phFile,LPFileOpenCallBackData pCallBack);
typedef long (WINAPI *pfnXlfsMount) (const wchar_t* pDestPath,const wchar_t* pSrcPath,long mountOption,const wchar_t* mountCmd);
typedef long (WINAPI *pfnXlfsOpenDir) (const wchar_t * dirPath, XLFS_DIR_HANDLE *phDir,DirOpenCallBackData* pCallback);
typedef long (WINAPI *pfnXlfsReadDir) (XLFS_DIR_HANDLE hDir,XLFSDirEntry* pResult);

#define MOUNT_DEST_PATH L"c:\\fsioMount"

typedef std::vector<std::wstring>::iterator WSTRING_ITE;

pfnXlfsOpen trueFsOpen = NULL;

DWORD tickThunderBegin = 0;
std::vector<std::wstring> g_vecFileName;
BOOL g_bOnce = TRUE;

long WINAPI MyXlfsOpen(const wchar_t * filePath, const wchar_t * openMode, XLFS_FILE_HANDLE *phFile,LPFileOpenCallBackData pCallBack)
{
	if(GetTickCount() - tickThunderBegin < 10000)
	{

		std::wstring strFilePath = filePath;
		int index = strFilePath.find(L"\\", 0);
		if(index != std::wstring::npos)
		{
			do 
			{
				strFilePath.replace(index,1,L"/");
			} while ((index = strFilePath.find(L"\\", index+1)) != std::wstring::npos);
		}
		std::vector<std::wstring>::iterator ite = g_vecFileName.begin();
		for(; ite != g_vecFileName.end(); ++ite)
		{
			if(strFilePath.compare(*ite) == 0)
				break;
		}
		if(ite == g_vecFileName.end())
			g_vecFileName.push_back(strFilePath);
	}
	else if(g_bOnce)
	{
		g_bOnce = FALSE;

		wchar_t fileName[MAX_PATH] = {0};
		GetModuleFileName(NULL, fileName, MAX_PATH);
		std::wstring strFileName = fileName;
		int index = strFileName.rfind(L"\\");
		strFileName = strFileName.substr(0, index+1);
		
		std::wstring strXarPath = strFileName;

		SYSTEMTIME sys;
		GetLocalTime( &sys );
		wchar_t localTime[256] = {0};
		wsprintf(localTime, L"%04d-%02d-%02d-%02d-%02d-%02d", sys.wYear,sys.wMonth,sys.wDay,sys.wHour,sys.wMinute,sys.wSecond);

		strFileName = strFileName + localTime + L"\\";

		SHCreateDirectory(NULL, strFileName.c_str());

		std::wstring strNotUse = strFileName + L"noUse.txt";
		strFileName += L"inUse.txt";

		FILE* fp = _wfopen(strFileName.c_str(), L"a+");
		for(std::vector<std::wstring>::iterator ite = g_vecFileName.begin(); ite != g_vecFileName.end(); ++ite)
		{
			fwprintf(fp, L"%s\r\n", ite->c_str());
		}
		fclose(fp);


		std::vector<std::wstring> vec_xarFile;

		index = strXarPath.rfind(L"\\");
		strXarPath = strXarPath.substr(0,index);
		index = strXarPath.rfind(L"\\");
		strXarPath = strXarPath.substr(0,index+1);
		strXarPath += L"thunder\\xar\\ThunderCore.xar";

		std::wstring mountXarPath = strXarPath;

		mountXarPath = L"xar@file://" + strXarPath + L"$";

		HMODULE hXLFSIO = LoadLibrary(L"XLFSIO.dll");
		pfnXlfsMount mountProc = (pfnXlfsMount)GetProcAddress(hXLFSIO, "XLFS_MountDir");
		long lRet = mountProc(MOUNT_DEST_PATH, mountXarPath.c_str(), 0, NULL);
		if(lRet != 0)
		{
			MessageBox(NULL, L"Mount Failed", 0, 0);
		}
		else
		{
			XLFS_DIR_HANDLE hFSDir = NULL;
			pfnXlfsOpenDir openDirProc = (pfnXlfsOpenDir)GetProcAddress(hXLFSIO, "XLFS_OpenDirectory");
			long lRet = openDirProc(MOUNT_DEST_PATH, &hFSDir, NULL);
			if(lRet != 0)
			{
				MessageBox(NULL, L"OpenDir Failed", 0, 0);
			}
			else
			{
				pfnXlfsReadDir readDirProc = (pfnXlfsReadDir) GetProcAddress(hXLFSIO, "XLFS_ReadDirectory");
				XLFSDirEntry entry;
				lRet = readDirProc(hFSDir, &entry);
				while(readDirProc(hFSDir, &entry) == XLFS_RESULT_SUCCESS)
				{
					if(wcsicmp(entry.Name, L"..")  == 0 || wcsicmp(entry.Name, L".") == 0)
						continue;
					if(entry.Attributes != 1)
					{	
						vec_xarFile.push_back(entry.Name);
					}
				}
			}	
		}

		WSTRING_ITE ite = vec_xarFile.begin();
		FILE *fpNoUse = _wfopen(strNotUse.c_str(), L"a+b");
		for(;ite != vec_xarFile.end(); ++ite)
		{
			WSTRING_ITE ite2 = g_vecFileName.begin();
			for(; ite2 != g_vecFileName.end(); ++ite2)
			{
				if(wcsstr(ite2->c_str(), ite->c_str()) != NULL)
				{
					break;
				}
			}
			if(ite2 == g_vecFileName.end())
			{
				fwprintf(fpNoUse, L"%s\r\n", ite->c_str());
			}
		}
		fclose(fpNoUse);

	}

	if(trueFsOpen)
	{
		return trueFsOpen(filePath, openMode, phFile, pCallBack);
	}
	return 0;
}

BOOL HookFsIo()
{
	HMODULE hXLFSIO = LoadLibrary(L"XLFSIO.dll");
	FARPROC proc = GetProcAddress(hXLFSIO, "XLFS_OpenFile");
	trueFsOpen = (pfnXlfsOpen) proc;
	if ( NO_ERROR != DetourTransactionBegin() )
	{
		return FALSE;
	}
	DetourUpdateThread(GetCurrentThread());
	DetourAttach(&(PVOID&)trueFsOpen, MyXlfsOpen);
	if( NO_ERROR != DetourTransactionCommit())
	{
		return FALSE;
	}
	return TRUE;
}

void HookFsIo2()
{
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,0);
	MODULEENTRY32 me32 = {sizeof(me32)};

	HMODULE hXLFSIO = LoadLibrary(L"XLFSIO.dll");
	FARPROC proc = GetProcAddress(hXLFSIO, "XLFS_OpenFile");
	trueFsOpen = (pfnXlfsOpen) proc;

	if(Module32First(hModuleSnap, &me32))
	{
		do 
		{
			ULONG ulSize;
			PIMAGE_IMPORT_DESCRIPTOR pid = (PIMAGE_IMPORT_DESCRIPTOR) ImageDirectoryEntryToData(me32.hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);
			if(pid == NULL)
				continue;

			while(pid->Name)
			{
				PSTR pszModName = (PSTR) ((PBYTE) me32.hModule + pid->Name);
				if(stricmp(pszModName, "XLFSIO.dll") == 0) 
					break;
				++pid;
			}
			if(pid->Name == 0)
				continue;

			PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)( (PBYTE)me32.hModule + pid->FirstThunk);
			while(pThunk->u1.Function)
			{
				PIMAGE_THUNK_DATA pOThunk = (PIMAGE_THUNK_DATA)((PBYTE)me32.hModule + pid->OriginalFirstThunk);
				PIMAGE_IMPORT_BY_NAME pImName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)me32.hModule + *((DWORD*)pOThunk));
				if(stricmp("XLFS_OpenFile", (char*)pImName->Name))
				{
					PROC*	ppfnEntry = (PROC*)&(pThunk->u1.Function);
					MEMORY_BASIC_INFORMATION memInfo;
					if(::VirtualQuery(ppfnEntry, &memInfo, sizeof(memInfo)) > 0)
					{
						BOOL bProcectResult = FALSE;
						DWORD dwOldProctect;
						bProcectResult = VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, PAGE_READWRITE, &dwOldProctect);
						PROC* pMyFun = (PROC*) MyXlfsOpen;
						SIZE_T sByteWritten = 0;
						WriteProcessMemory(GetCurrentProcess(), ppfnEntry, &pMyFun, sizeof(PROC*), &sByteWritten );
						bProcectResult = VirtualProtect(memInfo.BaseAddress, memInfo.RegionSize, PAGE_READONLY, &dwOldProctect);
					}
					break;
				}
			}

			//HMODULE hCurrent = me32.hModule;
			//IMAGE_DOS_HEADER *pidh;
			//IMAGE_NT_HEADERS *pinh;
			//IMAGE_DATA_DIRECTORY *pSymbolTable;
			//IMAGE_IMPORT_DESCRIPTOR *piid;

			//pidh = (IMAGE_DOS_HEADER *)hCurrent; 
			//pinh = (IMAGE_NT_HEADERS *)((DWORD)hCurrent + pidh->e_lfanew);
			//pSymbolTable = &pinh->OptionalHeader.DataDirectory[1];
			//piid =(IMAGE_IMPORT_DESCRIPTOR *)((DWORD)hCurrent +  pSymbolTable->VirtualAddress);
			//do {
			//     IMAGE_THUNK_DATA *pitd,*pitd2;
			//	 pitd = (IMAGE_THUNK_DATA *)((DWORD)hCurrent + piid->OriginalFirstThunk);
			//	 pitd2 = (IMAGE_THUNK_DATA *)((DWORD)hCurrent + piid->FirstThunk);
			//	 do {
			//		 IMAGE_IMPORT_BY_NAME *piibn;
			//		 piibn = (IMAGE_IMPORT_BY_NAME *)((DWORD)hCurrent +  *((DWORD *)pitd));
			//		 PROC *ppfn = (PROC *)(pitd2->u1.Function);
			//		 if (!stricmp("XLFS_OpenFile",(char *)piibn->Name)) {
			//			  trueFsOpen = (pfnXlfsOpen)(ppfn);
			//			  DWORD addr = (DWORD)MyXlfsOpen;
			//			  DWORD written = 0;
			//			/* 改变内存读写状态 */
			//			  DWORD oldAccess;
			//			  VirtualProtect(&pitd2->u1.Function,sizeof(DWORD),PAGE_WRITECOPY,&oldAccess);
			//			/* 向内存映像写入数据 */
			//			  WriteProcessMemory(GetCurrentProcess(),&pitd2->u1.Function, &addr,sizeof(DWORD), &written);
			//			}
			//		 pitd++;pitd2++;
			//		} while (pitd->u1.Function);

			//	  piid++;
			//	} while (piid->FirstThunk + piid->Characteristics 
			//		+ piid->ForwarderChain + piid->Name + piid->TimeDateStamp);
		} while (Module32Next(hModuleSnap, &me32));
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			HookFsIo();
			HANDLE hPrcess = GetCurrentProcess();
			DWORD dwThreadID=0;
			DWORD dwProcessID = 0;
			dwProcessID = GetProcessId(hPrcess);
			THREADENTRY32 te32 = {sizeof(te32)};
			HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
			if( Thread32First( hThreadSnap, &te32) )
			{
				do{
					if( dwProcessID == te32.th32OwnerProcessID )
					{
						dwThreadID = te32.th32ThreadID;
						break;
					}
				}while( Thread32Next( hThreadSnap, &te32) );
			}
			HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, dwThreadID);
			ResumeThread(hThread);
			tickThunderBegin = GetTickCount();
			break;
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

