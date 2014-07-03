#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <stdlib.h>

#define MAX_FILESIZE 100*1024*1024

void unpack(char *exe, char *dst){
	FILE *input, *output;
	uint32_t cursor, end;
	char *fname, *fdata, *fbuff, *outname;
	int buflen, flen;

	input = fopen(exe, "rb");
	fseek(input, -4, SEEK_END);

	fread(&cursor, 4, 1, input);
	if (cursor != 0x70ac4bb6){
		printf("%s cannot be read - magic number (%d) incorrect\n", exe, cursor);
		exit(-1);
	}

	fbuff = malloc(MAX_FILESIZE);
	outname = malloc(MAX_PATH);

	fseek(input, -8, SEEK_END);
	end = ftell(input);
	fread(&cursor, 4, 1, input);

	while (cursor){
		buflen = end-(cursor+4);

		fseek(input, cursor, SEEK_SET);
		end = cursor;
		fread(&cursor, 4, 1, input);

		if (buflen > MAX_FILESIZE){
			printf("Exceeded max file size - %d\n", buflen);
			exit(-2);
		}
		fread(fbuff, 1, buflen, input);
		fname = fbuff;
		flen = strlen(fbuff)+1;
		fdata = fbuff+flen;
		buflen -= flen;

		if (strlen(dst) + flen > MAX_PATH){
			printf("Exceeded max path length\n");
			exit(-2);
		}

		strncpy(outname, dst, MAX_PATH);
		strncat(outname, fname, MAX_PATH-strlen(dst));

		output = fopen(outname, "wb");
		fwrite(fdata, 1, buflen, output);
		fclose(output);

	}

	free(fbuff); fbuff=NULL;
	free(outname); outname=NULL;
	fclose(input);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	srand(time(NULL));

	STARTUPINFO startup_info;
	PROCESS_INFORMATION process_info;

	memset(&startup_info, 0, sizeof(STARTUPINFO));
	startup_info.cb = sizeof(startup_info);

	char *temp = malloc(MAX_PATH+1);
	GetTempPath(MAX_PATH-20, temp);

	char *tempunpackdir = malloc(MAX_PATH+1);
	snprintf(tempunpackdir, MAX_PATH-10, "%spymod_tmp_%d\\", temp, rand());
	CreateDirectory(tempunpackdir, NULL);
	printf("%s\n", tempunpackdir);

	char *modname = malloc(MAX_PATH);
	GetModuleFileName(NULL, modname, MAX_PATH);
	unpack(modname, tempunpackdir);

	char *exe_name = malloc(MAX_PATH);
	snprintf(exe_name, MAX_PATH-10, "%sexe_name", tempunpackdir);
	FILE *exe_name_file = fopen(exe_name, "r");
	fgets(exe_name, MAX_PATH, exe_name_file);
	fclose(exe_name_file);

	printf("Launching %s\n", exe_name);
	if (CreateProcess(exe_name, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startup_info, &process_info))
	{

		char *unpackdir = malloc(MAX_PATH+1);
		snprintf(unpackdir, MAX_PATH, "%spymod_%d\\", temp, process_info.dwProcessId);
		MoveFile(tempunpackdir, unpackdir);

		char *path = malloc(MAX_PATH*102);
		GetEnvironmentVariable(TEXT("PATH"), path, MAX_PATH*100);
		strcat(path, ";");
		strcat(path, unpackdir);
		SetEnvironmentVariable(TEXT("PATH"), path);
		printf("Setting PATH to %s\n", path);

		char *dll_name = malloc(MAX_PATH);
		char *dll_path = malloc(MAX_PATH);
		snprintf(dll_name, MAX_PATH-10, "%sdll_name", unpackdir);
		FILE *dll_name_file = fopen(dll_name, "r");
		fgets(dll_name, MAX_PATH, dll_name_file);
		fclose(dll_name_file);
		snprintf(dll_path, MAX_PATH, "%s%s", unpackdir, dll_name);
		free(dll_name);

		LPVOID load_library = (LPVOID) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
		LPVOID remote_string = (LPVOID) VirtualAllocEx(process_info.hProcess, NULL, strlen(dll_path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(process_info.hProcess, remote_string, dll_path, strlen(dll_path) + 1, NULL);

		HANDLE thread = CreateRemoteThread(process_info.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) load_library, remote_string, CREATE_SUSPENDED, NULL);

		if (thread == NULL)
		{
			return 1;
		}

		ResumeThread(process_info.hThread);
		//sleep(20);
		ResumeThread(thread);

		CloseHandle(process_info.hProcess);
		// CloseHandle(process_info.hThread);
		CloseHandle(thread);

		FreeConsole();
		WaitForSingleObject(process_info.hThread, INFINITE); // for auto-restart scripts/programs/whatever

		// TODO: delete unpackdir


		return 0;
	} else {
		printf("Could not create process - %d\n", GetLastError());
	}

	return 1;
}
