// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <windows.h>

void setHook();
void hook(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

DWORD origThunkPtr;


void hook(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {

	lpText = (LPCTSTR)"Hooked";
	
	int addr = (int)origThunkPtr;
	_asm {
		add esp, 0xE0
		jmp $+addr
	}

}

void setHook() {

	DWORD oldPrivilege;
	HMODULE module = GetModuleHandle(NULL);
	

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)dosHeader + (DWORD)dosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImpDecsriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)dosHeader + (DWORD)pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


	while (pImpDecsriptor->Name != NULL) {

		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD)dosHeader + (DWORD)pImpDecsriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pThunkFirst = (PIMAGE_THUNK_DATA)((DWORD)dosHeader + (DWORD)pImpDecsriptor->FirstThunk);
	
		while (pThunk->u1.AddressOfData != NULL) {

			PIMAGE_IMPORT_BY_NAME pImage = (PIMAGE_IMPORT_BY_NAME)((DWORD)dosHeader + (DWORD)pThunk->u1.Function);
	
			if (strcmp(pImage->Name, "MessageBoxA") == 0) {

				LPDWORD thunkPtr = (LPDWORD)&pThunkFirst->u1.AddressOfData;

				VirtualProtect(thunkPtr, sizeof(LPDWORD), PAGE_EXECUTE_READWRITE, &oldPrivilege);

				origThunkPtr = (DWORD)pThunkFirst->u1.AddressOfData;
			    *thunkPtr = (DWORD)hook;

				VirtualProtect(thunkPtr, sizeof(LPDWORD), oldPrivilege, &oldPrivilege);

			}
			pThunk++;
		}

		pImpDecsriptor++;
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
		setHook();
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

