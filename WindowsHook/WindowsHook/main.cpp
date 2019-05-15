#include <stdio.h>
#include <windows.h>
#include <string>


LRESULT CALLBACK HookCallBack(int nCode, WPARAM wParam, LPARAM lParam);
HHOOK hookID;


int main() {


	hookID = SetWindowsHookEx(WH_KEYBOARD_LL, HookCallBack, (HINSTANCE)NULL, 0);

	MSG msg;
	while (!GetMessage(&msg, NULL, NULL, NULL)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}


LRESULT CALLBACK HookCallBack(int nCode, WPARAM wParam, LPARAM lParam) {

	
	if (nCode == HC_ACTION)
	{
		if (wParam == WM_KEYDOWN)
		{

			KBDLLHOOKSTRUCT* kbStruct = (KBDLLHOOKSTRUCT*)(lParam);

			printf("%x\n", kbStruct->vkCode);
		}
	}

	return CallNextHookEx(hookID, nCode, wParam, lParam);
}




