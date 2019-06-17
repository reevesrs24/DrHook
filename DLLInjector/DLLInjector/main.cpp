#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>



void setHook(DWORD processID);


int main() {

	DWORD id;

	std::cout << "Enter Process ID: " << std::endl;
	std::cin >> id;
	setHook(id);

	system("pause");
}


void setHook(DWORD processID)
{
	std::cout << "Setting Hook..." << std::endl;

	// Get a handle to the process.
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

	if (hProcess != NULL)
	{
		HMODULE hMod;
		DWORD cbNeeded;

		const char* dll = "C:\\Users\\pip\\source\\repos\\IATHook\\Debug\\IATHOOK.dll";

		LPVOID Library = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");


		LPVOID Memory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dll), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (WriteProcessMemory(hProcess, Memory, dll, strlen(dll), NULL) == 0)
		{
			std::cout << "Write Process Memory Failed" << std::endl;
		}

		if (CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)Library, Memory, NULL, NULL) == 0)
		{
			std::cout << "Create Remote Thread Failed" << std::endl;
		}

		CloseHandle(hProcess);

	}
	std::cout << "Hook Set!" << std::endl;
}