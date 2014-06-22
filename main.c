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
void **replaced_code_dict_ptr = NULL;
long page = 0;

void on_hook_c(void *rsp){
	void *stack = rsp-16;
	void **called_from = stack+152;

	printf("0x%08x hooked\n", called_from);
	PyObject *key = PyLong_FromVoidPtr(*called_from-7);

	PyObject *registers_tuple = PyTuple_New(17);
	int i=0;
	for (int o=144;o>=16;o-=8){ // [flags, r15, r14 ... rax] are at [stack+144, stack+136, stack+128 ... stack+16]
		long *saved = stack+o;
		PyTuple_SetItem(registers_tuple, i++, PyLong_FromUnsignedLong(*saved));
	}

	PyObject *registers = PyObject_CallObject(PyObject_GetAttrString(internal_module, "Registers"), registers_tuple);

	PyObject *args = PyTuple_Pack(1, registers);
	PyObject *ret = PyObject_CallObject(PyTuple_GetItem(PyDict_GetItem(hooks_dict, key), 1), args);
	if (!ret) PyErr_Print();
	Py_DECREF(args);
	Py_DECREF(ret);

	// restore registers from thing

	PyObject *registers_list = PyObject_CallObject(PyObject_GetAttrString(registers, "values"), NULL);
	if (!ret) PyErr_Print();
	//PyObject_Print(registers_list, stdout, 0);

	i=0;
	for (int o=144;o>=16;o-=8){
		long *saved = stack+o;
		PyObject *py_long = PyList_GetItem(registers_list, i++);
		*saved = PyLong_AsUnsignedLong(py_long);
		Py_DECREF(py_long);
	}
	//registers_tuple(registers);
	Py_DECREF(registers_tuple);

	*replaced_code_dict_ptr = PyLong_AsVoidPtr(PyDict_GetItem(replaced_code_dict, key));
}

int text_copy(void *dest, void *source, const size_t length)
{
	if (page==0)page = sysconf(_SC_PAGESIZE);
	void  *start = (char *)dest - ((long)dest % page);
	size_t memlen = length + (size_t)((long)dest % page);


	if (memlen % (size_t)page)
		memlen = memlen + (size_t)page - (memlen % (size_t)page);

	if (mprotect(start, memlen, PROT_READ | PROT_WRITE | PROT_EXEC))
		return errno;

	memcpy(dest, source, length);

	if (mprotect(start, memlen, PROT_READ | PROT_EXEC))
		return errno;

	return 0;
}

void fix_asm(){
	// To be PIC the assembly functions in main.asm require being patched to
	// use variables that we malloc here

	// update spin_lock and spin_unlock to use some bytes on the heap so it's PIC
	void **m = malloc(8);
	*m = 0;
	text_copy((void*)(*spin_lock + 9), &m, 4);
	text_copy((void*)(*spin_unlock + 8), &m, 4);

	// same for saving the FPU state
	fpu = malloc(108);
	text_copy((void*)(*on_hook_asm + 11), &fpu, 4);
	text_copy((void*)(*on_hook_asm + 78), &fpu, 4);

	// connect the call to on_hook_c
	m = malloc(8);
	*m = *on_hook_c;
	text_copy((void*)(*on_hook_asm + 46), &m, 4);

	// connect the call to run the replaced code (via a pointer)
	replaced_code_dict_ptr = malloc(8);
	text_copy((void*)(*on_hook_asm + 92), &replaced_code_dict_ptr, 4);
}

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
	internal_module = PyImport_ImportModule("hook_internals");
	replaced_code_dict = PyDict_New();
	if (!hooks_module || !internal_module | !replaced_code_dict) goto fail;

	hooks_dict = PyObject_GetAttrString(hooks_module, "hooks");
	if (!hooks_dict) goto fail;

	if (PyCallable_Check(hooks_dict)){
		hooks_dict = PyObject_CallObject(hooks_dict, NULL);
	}
	if (!hooks_dict || !PyDict_Check(hooks_dict)){
		printf("Need a dictionary or function that returns a dictionary\n");
		goto fail;
	}

	PyObject *keys = PyDict_Keys(hooks_dict);
	for(Py_ssize_t i=0;i<PyList_Size(keys);i++){

		PyObject *key = PyList_GetItem(keys, i);
		PyObject *val = PyDict_GetItem(hooks_dict, key);
		if (!PyTuple_Check(val) || PyTuple_Size(val)<2){
			printf("ignoring hook as it is not a mapping from an integer to a tuple of TODO\n");
			continue;
		}

		void *addr = (void*)PyNumber_AsSsize_t(key, NULL);
		void * endadr = (void*)PyNumber_AsSsize_t(PyTuple_GetItem(val, 0), NULL);
		int ilen = endadr-addr;

		if (ilen < 5){
			printf("There is not enough space between 0x%08x and 0x%08x to inject a jump/call\n", addr, endadr);
		}
		PyObject *func = PyTuple_GetItem(val, 1);

		/*if (!PyIndex_Check(key) || !PyCallable_Check(func)){
			printf("ignoring hook as it is not a mapping from an integer to a callable\n");
			continue;
		}*/

		printf("Injecting hook at 0x%08x to call ", addr);
		PyObject_Print(val, stdout, 0);
		putchar('\n');

		if (page==0)page = sysconf(_SC_PAGESIZE);
		void* replaced = aligned_alloc(page, (ilen + 8) + page - ((ilen + 8) % page));
		memcpy(replaced, addr, ilen);
		memcpy(replaced+ilen, "\xc3", 1); // ret
		mprotect(replaced, ilen+1, PROT_READ | PROT_EXEC);

		PyDict_SetItem(replaced_code_dict, PyLong_FromVoidPtr(addr), PyLong_FromVoidPtr(replaced));


		void **on_hook_asm_ptr = malloc(8);
		*on_hook_asm_ptr = *on_hook_asm;

		void *new_call = malloc(ilen);
		memcpy(new_call, "\xff\x14\x25", 3); // call
		memcpy(new_call+3, &on_hook_asm_ptr, 4); // qword ptr[*on_hook_asm_ptr]
		memset(new_call+7, 0x90, ilen-7); // nop
		text_copy(addr, new_call, ilen);

	}
	Py_DECREF(keys);

	/*PyObject_Print(hooks_dict, stdout, 0);
	putchar('\n');
	PyObject_Print(replaced_code_dict, stdout, 0);
	putchar('\n');*/

	return;

	//Py_Finalize();
	fail:
		PyErr_Print();
		exit(-1);

}

void main(){
	//_malloc = (void *(*)(size_t size)) dlsym(RTLD_NEXT, "malloc");
	patch();
	on_hook_asm();
}
