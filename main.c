/*
Making the shared object:

lin32:

nasm -f elf32 -shared trampoline_perilogue_32.asm -o trampoline_perilogue_32.o
# from arch32 chroot
gcc -I/usr/include/python3.4m -lpthread -ldl -lutil -lm -lpython3.4m -std=c11 -masm=intel -fPIC -shared -O2 trampoline_perilogue_32.o main.c -o mod_lin32.so


lin64:

nasm -f elf64 -shared trampoline_perilogue_64.asm -o trampoline_perilogue_64.o
gcc -I/usr/include/python3.4m -lpthread -ldl  -lutil -lm -lpython3.4m -std=c11 -masm=intel -fPIC -shared -O2 trampoline_perilogue_64.o main.c -o mod_lin64.so


win64:

nasm -f win64 -shared trampoline_perilogue_64.asm -o trampoline_perilogue_64.obj
x86_64-w64-mingw32-gcc -I/usr/x86_64-w64-mingw32/include/python34/ -std=c11 -masm=intel -shared main.c -c -o main.o
x86_64-w64-mingw32-cc /usr/x86_64-w64-mingw32/lib/libpython34.dll.a trampoline_perilogue_64.obj main.o -lpython34 -shared -o mod_win64.dll

win32:
nasm -f win32 -shared trampoline_perilogue_32.asm -o trampoline_perilogue_32.obj
i686-w64-mingw32-gcc -I/usr/i686-w64-mingw32/include/python34/ -std=c11 -masm=intel -shared main.c -c -o main.o
i686-w64-mingw32-cc /usr/i686-w64-mingw32/lib/libpython34.dll.a trampoline_perilogue_32.obj main.o -lpython34 -shared -o mod_win32.dll

or (on windows with mingw64 installed) - the object file can be created with nasm on linux
gcc -IC:\Python34\include -std=c11 main.c trampoline_perilogue_32.obj C:\Python34\libs\libpython34.a -shared -static -o mod_win32.dll


*/




#include <Python.h>
#include <stdlib.h>
#include <sys/time.h>
#include "trampoline_perilogue.h"
#include <stdint.h>

#ifndef __MINGW32__

#include <dlfcn.h>
#include <sys/mman.h>

#else

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <fcntl.h>

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
int mprotect(void *addr, size_t len, int prot){
	DWORD dwOldProtect;
	if (prot == PROT_READ | PROT_WRITE | PROT_EXEC){
		VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	} else if (prot == PROT_READ | PROT_EXEC){
		VirtualProtect(addr, len, PAGE_EXECUTE_READ, &dwOldProtect);
	} else {
		printf("Memory flag %d not supported\n", prot);
		return 1;
	}
	return 0;
}
void *aligned_alloc(size_t alignment, size_t size){
	return malloc(size);
}
#define _SC_PAGESIZE 0
long sysconf(int name){
	return 1;
}

#undef PyObject_Print
#define PyObject_Print(x,y,z) puts("PyObject_Print TODO");

#endif

#if _WIN64 || __amd64__
#define TARGET_64_BIT
#define PyLong_AsUintptr_t(x) PyLong_AsUnsignedLongLong(x)
#else
#define TARGET_32_BIT
#define PyLong_AsUintptr_t(x) PyLong_AsUnsignedLong(x)
#endif

void patch();
void on_hook_c();
int text_copy(void *target, void *source, const size_t length);
void fix_asm();

PyObject *hooks_module, *internal_module;
PyObject *hooks_dict, *replaced_code_dict;

void *fpu = NULL;
void **replaced_code_ptr = NULL;
void **saved_called_from;
uintptr_t page = 0;

char *ppath = NULL;

void on_hook_c(void *sp){
	struct timeval t0, t1;
	gettimeofday(&t0, 0);

	void *stack = sp-16;
	#ifdef TARGET_32_BIT
		void **called_from = stack+52;
	#else
		void **called_from = stack+152;
	#endif

	*saved_called_from = *called_from;

	#ifdef TARGET_32_BIT
	printf("* 0x%08x hooked\n", *called_from-6);
	PyObject *key = PyLong_FromVoidPtr(*called_from-6);
	#else
	printf("* 0x%08x hooked\n", *called_from-7);
	PyObject *key = PyLong_FromVoidPtr(*called_from-7);
	#endif
	PyObject *value = PyDict_GetItem(replaced_code_dict, key);

	long iter = PyLong_AsLong(PyList_GetItem(value, 2));
	PyList_SetItem(value, 2, PyLong_FromLong(iter+1));
	int skip = iter % PyLong_AsLong(PyList_GetItem(value, 1));
	printf("# %d %d\n", iter, skip);

	if (!skip){
		printf("* running python hook\n");

		int i=0;
		#ifdef TARGET_32_BIT
		PyObject *registers_tuple = PyTuple_New(9);
		for (int o=48;o>=16;o-=4){
			uintptr_t *saved = stack+o;
			PyTuple_SetItem(registers_tuple, i++, PyLong_FromUnsignedLong(*saved));
		}
		#else
		PyObject *registers_tuple = PyTuple_New(17);
		for (int o=144;o>=16;o-=8){
			uintptr_t *saved = stack+o;
			PyTuple_SetItem(registers_tuple, i++, PyLong_FromUnsignedLongLong(*saved));
		}
		#endif

		PyObject *registers = PyObject_CallObject(PyObject_GetAttrString(internal_module, "Registers"), registers_tuple);
		PyErr_Print();

		PyObject *args = PyTuple_Pack(2, registers, PyList_GetItem(value, 2));
		PyObject *ret = PyObject_CallObject(PyTuple_GetItem(PyDict_GetItem(hooks_dict, key), 1), args);
		Py_DECREF(args);

		if (ret){
			Py_DECREF(ret);

			// restore registers from thing
			printf("* Restoring modified register state\n");

		} else {
			printf("!! Error running python hook\n");
			PyErr_Print();
			printf("* Restoring original register state\n");
		}

		registers_tuple = PyObject_CallObject(PyObject_GetAttrString(registers, "values"), NULL);

		i=0;
		#ifdef TARGET_32_BIT
		for (int o=48;o>=16;o-=4){
			uintptr_t *saved = stack+o;
			PyObject *py_long = PyTuple_GetItem(registers_tuple, i++);
			*saved = PyLong_AsUintptr_t(py_long);
			Py_DECREF(py_long);
		}
		#else
		for (int o=144;o>=16;o-=8){
			uintptr_t *saved = stack+o;
			PyObject *py_long = PyTuple_GetItem(registers_tuple, i++);
			*saved = PyLong_AsUintptr_t(py_long);
			Py_DECREF(py_long);
		}
		#endif

		Py_DECREF(registers_tuple);

	} else {
		printf("* Not running hook this iteration\n");
		#ifdef TARGET_32_BIT
		*((uintptr_t*)(stack+48))+=4;
		#else
		*((uintptr_t*)(stack+144))+=8;
		#endif
	}

	*replaced_code_ptr = PyLong_AsVoidPtr(PyList_GetItem(value, 0));
	PyErr_Print();


	gettimeofday(&t1, 0);
	long elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec;
	printf("* C/Python hook took %fms\n", elapsed/1000.0);
}

int text_copy(void *dest, void *source, size_t length)
{
	if (page==0)page = sysconf(_SC_PAGESIZE);
	void  *start = dest - ((uintptr_t)dest) % ((uintptr_t)page);
	uintptr_t memlen = length + ((uintptr_t)dest) % ((uintptr_t)page);


	if (memlen % (size_t)page)
		memlen = memlen + (size_t)page - ((uintptr_t)memlen) % ((uintptr_t)page);

	if (mprotect(start, memlen, PROT_READ | PROT_WRITE | PROT_EXEC))
		return errno;

	memcpy(dest, source, length);

	if (mprotect(start, memlen, PROT_READ | PROT_EXEC))
		return errno;

	return 0;
}

#ifdef TARGET_32_BIT
void fix_asm(){
	// To be PIC the assembly functions in main.asm require being patched to
	// use variables that we malloc here

	// update spin_lock and spin_unlock to use some bytes on the heap so it's PIC
	void **m = malloc(4);
	*m = 0;
	text_copy((void*)(*spin_lock + 7), &m, 4);
	text_copy((void*)(*spin_unlock + 7), &m, 4);

	// same for saving the FPU state
	fpu = malloc(108);
	text_copy((void*)(*on_hook_asm + 14+3), &fpu, 4);
	text_copy((void*)(*on_hook_asm + 31+2), &fpu, 4);

	// connect the call to on_hook_c
	m = malloc(4);
	*m = *on_hook_c;
	text_copy((void*)(*on_hook_asm + 22+2), &m, 4);

	// connect the call to run the replaced code (via a pointer)
	replaced_code_ptr = malloc(4);
	text_copy((void*)(*on_hook_asm + 51+2), &replaced_code_ptr, 4);
}
#else
void fix_asm(){

	// update spin_lock and spin_unlock to use some bytes on the heap so it's PIC
	void **m = malloc(8);
	*m = 0;
	text_copy((void*)(*spin_lock + 5+4), &m, 4);
	text_copy((void*)(*spin_unlock + 5+4), &m, 4);

	// same for saving the FPU state
	fpu = malloc(108);
	text_copy((void*)(*on_hook_asm + 30+4), &fpu, 4);
	text_copy((void*)(*on_hook_asm + 48+3), &fpu, 4);

	// connect the call to on_hook_c
	m = malloc(8);
	*m = *on_hook_c;
	text_copy((void*)(*on_hook_asm + 41+3), &m, 4);

	// connect the call to run the replaced code (via a pointer)
	replaced_code_ptr = malloc(8);
	text_copy((void*)(*on_hook_asm + 85+3), &replaced_code_ptr, 4);
}
#endif

int init_python(){

	#ifdef __MINGW32__
	Py_NoSiteFlag=1;
	Py_SetPythonHome(L".");
	#endif
	Py_SetProgramName(L"pymod");
	Py_InitializeEx(0);

	#ifdef __MINGW32__
	PyImport_ImportModule("c_stdout");
	#endif

	PyObject *sys_path = PySys_GetObject("path");
	if (sys_path == NULL || !PyList_Check(sys_path)) {
		printf("No path!\n");
		sys_path = PyList_New(0);
		PySys_SetObject("path",sys_path);
	}
	if (ppath){
		printf("Adding %s to path!\n", ppath);
		PyList_Insert(sys_path, 0, PyUnicode_FromString(ppath));
		strcat(ppath, "\\python.zip");
		printf("Adding %s to path!\n", ppath);
		PyList_Insert(sys_path, 0, PyUnicode_FromString(ppath));
	}
	PyList_Insert(sys_path, 0, PyUnicode_FromString("."));


	internal_module = PyImport_ImportModule("hook_internals");
	if (!internal_module){
		printf("Could not find hook_internals.py\n");
		return 1;
	}
	hooks_module = PyImport_ImportModule("main");
	if (!internal_module){
		printf("Could not find main.py\n");
		return 2;
	}
	PyErr_Print();
	replaced_code_dict = PyDict_New();

	hooks_dict = PyObject_GetAttrString(hooks_module, "hooks");
	if (!hooks_dict){
		printf("No hooks in main module\n");
		return 3;
	}

	if (PyCallable_Check(hooks_dict)){
		hooks_dict = PyObject_CallObject(hooks_dict, NULL);
		PyErr_Print();
	}
	if (!hooks_dict || !PyDict_Check(hooks_dict)){
		printf("Need a dictionary or function that returns a dictionary\n");
		return 4;
	}

	return 0;
}

void create_hook(PyObject *key, PyObject *val, void **saved_called_from_ptr, void** on_hook_asm_ptr){

	uintptr_t addr = PyLong_AsUintptr_t(key);

	if (PyTuple_Size(val)<2 || !PyIndex_Check(PyTuple_GetItem(val, 0)) || !PyCallable_Check(PyTuple_GetItem(val, 1))) {
		printf("Ignoring hook at 0x%08x as it does not specify an end address and a function\n", addr);
	}

	uintptr_t endadr = PyLong_AsUintptr_t(PyTuple_GetItem(val, 0));
	uintptr_t ilen = endadr-addr;

	PyObject *func = PyTuple_GetItem(val, 1);

	#ifdef TARGET_32_BIT
	if (ilen < 6){
	#else
	if (ilen < 7){
	#endif
		printf("There is not enough space between 0x%08x and 0x%08x to inject a call. At least 6 bytes are needed on 32bit and 7 bytes on 64bit\n", addr, endadr);
		return;
	}

	printf("Injecting hook at 0x%08x to call ", addr);
	PyObject_Print(val, stdout, 0);
	putchar('\n');


	if (page==0)page = sysconf(_SC_PAGESIZE);
	void* replaced = aligned_alloc(page, (ilen + 8) + page - ((ilen + 8) % page));
	memcpy(replaced, (void*)addr, ilen);
	#ifdef TARGET_32_BIT
	memcpy(replaced+ilen, "\xff\x25", 2); // jmp dword ptr
	memcpy(replaced+ilen+2, saved_called_from_ptr, 4); // [called_from]
	#else
	memcpy(replaced+ilen, "\xff\x24\x25", 3); // jmp qword ptr
	memcpy(replaced+ilen+3, saved_called_from_ptr, 8); // [called_from]
	#endif
	mprotect(replaced, ilen+1, PROT_READ | PROT_EXEC);

	PyObject *list = PyList_New(3);
	PyList_SetItem(list, 0, PyLong_FromVoidPtr((void*)replaced));
	if (PyTuple_Size(val) == 3 && PyLong_Check(PyTuple_GetItem(val, 2))) {
		PyList_SetItem(list, 1, PyTuple_GetItem(val, 2));
	} else {
		PyList_SetItem(list, 1, PyLong_FromLong(1));
	}
	PyList_SetItem(list, 2, PyLong_FromLong(0));
	PyDict_SetItem(replaced_code_dict, PyLong_FromVoidPtr((void*)addr), list);


	void *new_call = malloc(ilen);
	#ifdef TARGET_32_BIT
	memcpy(new_call, "\xff\x15", 2); // call dword ptr
	memcpy(new_call+2, &on_hook_asm_ptr, 4); // [on_hook_asm_ptr]
	memset(new_call+6, 0x90, ilen-6); // nop
	#else
	memcpy(new_call, "\xff\x14\x25", 3); // call qword ptr
	memcpy(new_call+3, &on_hook_asm_ptr, 4); // [on_hook_asm_ptr]
	memset(new_call+7, 0x90, ilen-7); // nop
	#endif
	text_copy((void*)addr, new_call, ilen);
}

void patch(){
	printf("I have successfully infiltrated the process!\n");
	fix_asm();

	if (init_python()){
		goto fail;
	}

	saved_called_from = malloc(8);
	void **saved_called_from_ptr = malloc(8);
	*saved_called_from_ptr = saved_called_from;

	void **on_hook_asm_ptr = malloc(8);
	*on_hook_asm_ptr = *on_hook_asm;

	PyObject *keys = PyDict_Keys(hooks_dict);
	for(Py_ssize_t i=0;i<PyList_Size(keys);i++){

		PyObject *key = PyList_GetItem(keys, i);
		PyObject *val = PyDict_GetItem(hooks_dict, key);
		if (!PyIndex_Check(key) || !PyTuple_Check(val)){
			printf("Ignoring hook as it is not a mapping from an integer to a tuple\n");
			continue;
		}

		create_hook(key, val, saved_called_from_ptr, on_hook_asm_ptr);

	}
	Py_DECREF(keys);
	free(saved_called_from_ptr);

	PyObject_Print(hooks_dict, stdout, 0);
	putchar('\n');
	PyObject_Print(replaced_code_dict, stdout, 0);
	putchar('\n');

	return;

	//Py_Finalize();
	fail:
		PyErr_Print();
		exit(-1);

}

#ifdef __MINGW32__

void CreateDebugConsole()
{
	HANDLE lStdHandle = 0;
	int hConHandle = 0;
	FILE *fp = 0;
	AllocConsole();
	lStdHandle = GetStdHandle(STD_OUTPUT_HANDLE);
	hConHandle = _open_osfhandle(PtrToUlong(lStdHandle), _O_TEXT);
	SetConsoleTitle(L"pymod");
	SetConsoleTextAttribute(lStdHandle, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
	system("cls");
	fp = _fdopen(hConHandle, "w");
	*stdout = *fp;
	setvbuf(stdout, NULL, _IONBF, 0);
}

PyObject* c_stdout_write(PyObject* self, PyObject* args){
    const char *data;
    if (!PyArg_ParseTuple(args, "s", &data))
        return NULL;
    printf("%s", data);
    return Py_BuildValue("");
}

PyObject* c_stdout_flush(PyObject* self, PyObject* args){
    return Py_BuildValue("");
}

PyMethodDef c_stdout_methods[] = {
    {"write", c_stdout_write, METH_VARARGS, "write(...)"},
    {"flush", c_stdout_flush, METH_VARARGS, "flush(...)"},
    {0, 0, 0, 0}
};


PyModuleDef c_stdout_module = {
    PyModuleDef_HEAD_INIT,
    "c_stdout",
    "doc",
    -1,
    c_stdout_methods,
};

PyMODINIT_FUNC PyInit_c_stdout(void) {
    PyObject* m = PyModule_Create(&c_stdout_module);
    PySys_SetObject("stdout", m);
    PySys_SetObject("stderr", m);
    return m;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{

		//CreateDebugConsole();
		freopen("pymod.log", "w", stdout);
		setvbuf(stdout, NULL, _IONBF, 0);
		PyImport_AppendInittab("c_stdout", PyInit_c_stdout);


		LPTSTR temp = (LPTSTR) malloc(MAX_PATH+1);;
		GetTempPath(MAX_PATH-20, temp);

		ppath = malloc(MAX_PATH+1);
		snprintf(ppath, MAX_PATH, "%spymod_%d\\", temp, GetCurrentProcessId());

		char *pppath = malloc(MAX_PATH+1);
		snprintf(pppath, MAX_PATH, "%spython.zip", ppath);

		SetEnvironmentVariable("PYTHONPATH", pppath);

		patch();
	}

}
#else
int (*_open)(const char * pathname, int flags, ...);
//void *(*_malloc)(size_t size);

volatile int patched = 0;

/*void *malloc(size_t size){
	if (!patched){
		_malloc = (void *(*)(size_t size)) dlsym(RTLD_NEXT, "malloc");
		patched = 1;
		printf("malloc(...)\n");
		patch();
	}
	return _malloc(size);
}*/

int open(const char * pathname, int flags, mode_t mode){
	if (!patched){
		_open = (int (*)(const char * pathname, int flags, ...)) dlsym(RTLD_NEXT, "open");
		patched = 1;
		printf("open(...)\n");
		patch();
	}
	if (pathname == (char*)0xbadf00d) return 0;
	return _open(pathname, flags, mode);
}

#endif


