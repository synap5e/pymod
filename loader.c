#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>

const char* DLL_NAME = "mod64.exe";

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	STARTUPINFO startup_info;
	PROCESS_INFORMATION process_info;

	memset(&startup_info, 0, sizeof(STARTUPINFO));
	startup_info.cb = sizeof(startup_info);

	if (CreateProcess(TEXT("notepad.exe"), NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info))
	{
		LPVOID load_library = (LPVOID) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
		LPVOID remote_string = (LPVOID) VirtualAllocEx(process_info.hProcess, NULL, strlen(DLL_NAME) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		WriteProcessMemory(process_info.hProcess, remote_string, DLL_NAME, strlen(DLL_NAME) + 1, NULL);

		HANDLE thread = CreateRemoteThread(process_info.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE) load_library, remote_string, CREATE_SUSPENDED, NULL);

		if (thread == NULL)
		{
			return 1;
		}

		ResumeThread(process_info.hThread);
		ResumeThread(thread);
		CloseHandle(thread);

		sleep(2);


		int ModuleArraySize = 100;
		HMODULE *ModuleArray = NULL;
		DWORD NumModules = 0;

		do {
			if (ModuleArray){
				ModuleArraySize *= 2;
				free(ModuleArray);
			}
			ModuleArray = malloc(ModuleArraySize * sizeof(HMODULE));

			EnumProcessModules(process_info.hProcess, ModuleArray, ModuleArraySize * sizeof(HMODULE), &NumModules);
			NumModules /= sizeof(HMODULE);
 		} while (NumModules > ModuleArraySize);


 		CHAR ModuleNameBuffer[MAX_PATH] = {0};
 		HMODULE *module;
 		for(DWORD i = 0; i <= NumModules; ++i){

			GetModuleBaseName(process_info.hProcess, ModuleArray[i], ModuleNameBuffer, sizeof(ModuleNameBuffer));

			printf("%s\n", ModuleNameBuffer);

			if (!strncmp(ModuleNameBuffer, DLL_NAME, sizeof(DLL_NAME))){
				printf("GOTCHYA!\n");
				module = ModuleArray[i];
				break;
			}
		}
		free(ModuleArray);


		/*LPVOID a = GetProcAddress(module, "attach");
		printf("%d\n", a);*/
		printf("Starting %d+0x00024cf\n", module);
		LPVOID attach = ((LPVOID)module)+9423;
		printf("Starting %d\n", attach);

		MessageBox(
			NULL,
			"Ready when you are!",
			"Go?",
			MB_ICONEXCLAMATION | MB_OK
		);

		thread = CreateRemoteThread(process_info.hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE) attach, NULL, 0, NULL);

		CloseHandle(process_info.hProcess);
		// CloseHandle(process_info.hThread);
		CloseHandle(thread);

		WaitForSingleObject(process_info.hThread, INFINITE); // for auto-restart scripts/programs/whatever

		return 0;
	}

	return 1;
}
