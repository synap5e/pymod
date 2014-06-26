/*
Making the shared object:

nasm main.asm -f elf64 -shared -o main.o
gcc -I/usr/include/python3.4m -I/usr/include/python3.4m -march=x86-64 -mtune=generic -O2 \
-pipe -fstack-protector-strong --param=ssp-buffer-size=4 -DDYNAMIC_ANNOTATIONS_ENABLED=1 \
-DNDEBUG -g -fwrapv -L/usr/lib -lpthread -ldl -lutil -lm  -lpython3.4m -Xlinker \
-export-dynamic -g -std=c11 -masm=intel -fPIC  main.o main.c


Making the a.out (for testing)
nasm main.asm -f elf64 -shared -o main.o
gcc -I/usr/include/python3.4m -I/usr/include/python3.4m -march=x86-64 -mtune=generic -O0 \
-pipe -fstack-protector-strong --param=ssp-buffer-size=4 -DDYNAMIC_ANNOTATIONS_ENABLED=1 \
-DNDEBUG -g -fwrapv -L/usr/lib -lpthread -ldl  -lutil -lm  -lpython3.4m -Xlinker \
-export-dynamic -g -std=c11 -masm=intel -fPIC main.o main.c

*/




#include <Python.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/mman.h>
//#include <unistd.h>
//#include <bits/fcntl.h>


#if _WIN64 || __amd64__
#define TARGET_64_BIT
typedef unsigned long long vint;
#else
#define TARGET_32_BIT
typedef unsigned int vint;
#endif


extern void on_hook_asm();
extern void spin_lock();
extern void spin_unlock();

void patch();
void on_hook_c();
int text_copy(void *target, void *source, const size_t length);
void fix_asm();

int (*_open)(const char * pathname, int flags, ...);
//void *(*_malloc)(size_t size);

int (*_close)(int fildes);

volatile int patched = 0;

/*int close(int fildes){
	printf("close(...)\n");
	if (!patched){
		_close = (int (*)(int fides)) dlsym(RTLD_NEXT, "close");
		patched = 1;
		main();
	}
	return _close(fildes);
}*/

/*void *malloc(size_t size){
	if (!patched){
		_malloc = (void *(*)(size_t size)) dlsym(RTLD_NEXT, "malloc");
		patched = 1;
		printf("malloc(...)\n");
		patch();
	}
	return _malloc(size);
}*/

/*unsigned int sleep(unsigned int seconds){
	if (!patched){
		_sleep = (unsigned int (*)(unsigned int seconds)) dlsym(RTLD_NEXT, "sleep");
		patched = 1;
		printf("sleep(...)\n");
		patch();
	}
	return _sleep(seconds);
}
*/
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



PyObject *hooks_module, *internal_module;
PyObject *hooks_dict, *replaced_code_dict;

void *fpu = NULL;
void **replaced_code_ptr = NULL;
void **saved_called_from;
vint page = 0;

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


	int i=0;
	#ifdef TARGET_32_BIT
	printf("* 0x%08x hooked\n", *called_from-6);
	PyObject *key = PyLong_FromVoidPtr(*called_from-6);
	PyObject *registers_tuple = PyTuple_New(9);
	for (int o=48;o>=16;o-=4){ // [eflags, esp, ebp ... eax] are at [stack+40, stack+36, stack+32 ... stack+8]
		vint *saved = stack+o;
		PyTuple_SetItem(registers_tuple, i++, PyLong_FromUnsignedLong(*saved));
	}
	void* original = malloc(9*4);
	memcpy(original, stack+16, 9*4);
	#else
	printf("* 0x%08x hooked\n", *called_from-7);
	PyObject *key = PyLong_FromVoidPtr(*called_from-7);
	PyObject *registers_tuple = PyTuple_New(17);
	for (int o=144;o>=16;o-=8){ // [rflags, r15, r14 ... rax] are at [stack+144, stack+136, stack+128 ... stack+16]
		vint *saved = stack+o;
		PyTuple_SetItem(registers_tuple, i++, PyLong_FromUnsignedLongLong(*saved));
	}
	void* original = malloc(17*8);
	memcpy(original, stack+16, 17*8);
	#endif

	PyObject *registers = PyObject_CallObject(PyObject_GetAttrString(internal_module, "Registers"), registers_tuple);
	PyErr_Print();

	PyObject *args = PyTuple_Pack(1, registers);
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
		vint *saved = stack+o;
		PyObject *py_long = PyTuple_GetItem(registers_tuple, i++);
		*saved = PyLong_AsUnsignedLongLong(py_long);
		Py_DECREF(py_long);
	}
	#else
	for (int o=144;o>=16;o-=8){
		vint *saved = stack+o;
		PyObject *py_long = PyTuple_GetItem(registers_tuple, i++);
		*saved = PyLong_AsUnsignedLongLong(py_long);
		Py_DECREF(py_long);
	}
	#endif

	Py_DECREF(registers_tuple);

	*replaced_code_ptr = PyLong_AsVoidPtr(PyDict_GetItem(replaced_code_dict, key));
	PyErr_Print();

	gettimeofday(&t1, 0);
	long elapsed = (t1.tv_sec-t0.tv_sec)*1000000 + t1.tv_usec-t0.tv_usec;
	printf("* C/Python hook took %fms\n", elapsed/1000.0);
}

int text_copy(void *dest, void *source, size_t length)
{
	if (page==0)page = sysconf(_SC_PAGESIZE);
	void  *start = dest - ((vint)dest) % ((vint)page);
	vint memlen = length + ((vint)dest) % ((vint)page);


	if (memlen % (size_t)page)
		memlen = memlen + (size_t)page - ((vint)memlen) % ((vint)page);

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
void patch(){
	printf("I have successfully infiltrated the process!\n");
	fix_asm();

	Py_Initialize();

	PyObject *sys_path = PySys_GetObject("path");
	if (sys_path == NULL || !PyList_Check(sys_path)) {
		printf("No path!\n");
		exit(-1);
	}
	PyObject *path = PyUnicode_FromString(".");
	PyList_Insert(sys_path, 0, path);
	Py_DECREF(path);


	hooks_module = PyImport_ImportModule("main");
	PyErr_Print();
	internal_module = PyImport_ImportModule("hook_internals");
	PyErr_Print();
	replaced_code_dict = PyDict_New();
	if (!hooks_module || !internal_module | !replaced_code_dict) goto fail;

	hooks_dict = PyObject_GetAttrString(hooks_module, "hooks");
	if (!hooks_dict) goto fail;

	if (PyCallable_Check(hooks_dict)){
		hooks_dict = PyObject_CallObject(hooks_dict, NULL);
		PyErr_Print();
	}
	if (!hooks_dict || !PyDict_Check(hooks_dict)){
		printf("Need a dictionary or function that returns a dictionary\n");
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

		void *addr = (void*)PyNumber_AsSsize_t(key, NULL);
		if (PyTuple_Size(val)<2 || !PyIndex_Check(PyTuple_GetItem(val, 0)) || !PyCallable_Check(PyTuple_GetItem(val, 1))) {
			printf("Ignoring hook at 0x%08x as it does not specify an end address and a function\n", addr);
		}

		void * endadr = (void*)PyNumber_AsSsize_t(PyTuple_GetItem(val, 0), NULL);
		int ilen = endadr-addr;

		PyObject *func = PyTuple_GetItem(val, 1);

		#ifdef TARGET_32_BIT
		if (ilen < 6){
		#else
		if (ilen < 7){
		#endif
			printf("There is not enough space between 0x%08x and 0x%08x to inject a call. At least 6 bytes are needed on 32bit and 7 bytes on 64bit\n", addr, endadr);
			continue;
		}

		printf("Injecting hook at 0x%08x to call ", addr);
		PyObject_Print(val, stdout, 0);
		putchar('\n');


		if (page==0)page = sysconf(_SC_PAGESIZE);
		void* replaced = aligned_alloc(page, (ilen + 8) + page - ((ilen + 8) % page));
		memcpy(replaced, addr, ilen);
		#ifdef TARGET_32_BIT
		memcpy(replaced+ilen, "\xff\x25", 2); // jmp dword ptr
		memcpy(replaced+ilen+2, saved_called_from_ptr, 4); // [called_from]
		#else
		memcpy(replaced+ilen, "\xff\x24\x25", 3); // jmp qword ptr
		memcpy(replaced+ilen+3, saved_called_from_ptr, 8); // [called_from]
		#endif
		mprotect(replaced, ilen+1, PROT_READ | PROT_EXEC);

		PyDict_SetItem(replaced_code_dict, PyLong_FromVoidPtr(addr), PyLong_FromVoidPtr(replaced));



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
		text_copy(addr, new_call, ilen);

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
/*
void main(){
	//_malloc = (void *(*)(size_t size)) dlsym(RTLD_NEXT, "malloc");
	patch();
	on_hook_asm();
}
*/
