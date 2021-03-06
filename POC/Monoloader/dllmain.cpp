#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include "logger.h"
#include "monofuncs.h"
#include "hwid.h"
#include "../MMap/mutexname.h"

PVOID ReadAllBytes(const char* filename, DWORD& size)
{

	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DWORD FileSize = GetFileSize(hFile, NULL);
	PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);

	size = FileSize;
	return FileBuffer;

}


bool DebugModeEnabled = true;

DWORD WINAPI MainThread(LPVOID params) {
	if (DebugModeEnabled) {
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
	}
	DebugLog("Initialized");
	DebugLog("HWID: $%s", getID().c_str());
	Sleep(1);
	HMODULE hMono = nullptr;

	while (hMono == nullptr) {
		DebugLog("Looking for mono.dll...");
		hMono = GetModuleHandleA("mono-2.0-bdwgc.dll");
		if (hMono == nullptr)
			Sleep(250);
	}
	DebugLog("Found mono.dll at 0x%X", hMono);

	DWORD file_size;
	PVOID file_data = ReadAllBytes("C:\\Users\\Keenan\\source\\repos\\ManualMapper\\POC\\x64\\Release\\Quicksilver.dll", file_size);

	DebugLog("Loaded DLL, file size 0x%X", file_size);

	MonoInject(hMono, file_data, file_size, "Quicksilver", "MonoLoader", "Hook");

	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
) {
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		{
			CreateMutexA(0, TRUE, GetMutexName().c_str()); // try to create a named mutex
			if (GetLastError() == ERROR_ALREADY_EXISTS) { return FALSE; } // did the mutex already exist?

			CreateThread(NULL, NULL, MainThread, NULL, NULL, NULL);
			break;
		}
	}
	return 0;
}


