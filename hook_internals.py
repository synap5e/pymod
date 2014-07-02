import ctypes, struct, re, os
from collections import OrderedDict, namedtuple, defaultdict

is_32bit = struct.calcsize('P') == 4
is_windows = False

Mapping = namedtuple('Mapping', ['start', 'end', 'perms', 'offset', 'dev', 'inode', 'pathname'])
CollatedMapping = namedtuple('Mapping', ['start', 'end', 'pathname'])

try:
    libc = ctypes.cdll.LoadLibrary('libc.so.6')
    def get_mappings():
        mems = []
        with open('/proc/self/maps') as f:
            for l in f.readlines():
                data = re.split('\s+', l)
                #print(data)
                data += [''] * (6-len(data))
                addr = data[0].split('-')
                mems.append(Mapping(
                    int(addr[0], 16),
                    int(addr[1], 16),
                    data[1],
                    int(data[2], 16),
                    data[3],
                    int(data[4]),
                    data[5]))
        return mems
except OSError:
    is_windows = True
    libc = ctypes.cdll.LoadLibrary('msvcrt.dll')
    import ctypes.wintypes


    MEM_COMMIT = 0x1000
    PAGE_GUARD = 0x100
    PAGE_NOCACHE = 0x200
    PAGE_READONLY = 0x2
    PAGE_READWRITE = 0x4
    PAGE_WRITECOPY = 0x8
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x1
    MEM_IMAGE = 0x1000000
    MEM_MAPPED = 0x40000
    MEM_PRIVATE = 0x20000
    MAX_PATH = 260

    perms = {
        PAGE_READONLY: "r---",
        PAGE_READWRITE: "rw--",
        PAGE_WRITECOPY: "rw-p",
        PAGE_EXECUTE: "--x-",
        PAGE_EXECUTE_READ: "r-x-",
        PAGE_EXECUTE_READWRITE: "rwx-",
        PAGE_EXECUTE_WRITECOPY: "rwxp",
        PAGE_NOACCESS: "----"
    }

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
                        ("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.wintypes.DWORD),
                        ("RegionSize", ctypes.c_size_t),
                        ("State", ctypes.wintypes.DWORD),
                        ("Protect", ctypes.wintypes.DWORD),
                        ("Type", ctypes.wintypes.DWORD),
                    ]

        def __str__(self):
            s = ""
            s

    def get_mappings():
        mems = []

        info = MEMORY_BASIC_INFORMATION()
        module_name = ctypes.create_string_buffer(MAX_PATH)
        start = 0

        while ctypes.windll.kernel32.VirtualQuery(ctypes.wintypes.LPCVOID(start), ctypes.pointer(info), ctypes.sizeof(info)) == ctypes.sizeof(info):
            start += info.RegionSize
            if info.State == MEM_COMMIT:
                info.AllocationProtect &= ~(PAGE_GUARD | PAGE_NOCACHE)
                mem_perm = perms[info.AllocationProtect]

                if info.Type == MEM_IMAGE:
                    ctypes.windll.kernel32.GetModuleFileNameA(info.AllocationBase, ctypes.pointer(module_name), MAX_PATH)
                    mem_name = str(module_name.value.decode('utf-8'))
                elif info.Type == MEM_MAPPED:
                    mem_name = 'memory mapped file'
                elif info.Type == MEM_PRIVATE:
                    mem_name = 'private'

                mems.append(Mapping(
                    info.BaseAddress,
                    info.BaseAddress+info.RegionSize,
                    mem_perm,
                    0,
                    '00:00',
                    0,
                    mem_name))
        return mems


reg32 = ['esp', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eflags']
reg64 = ['rsp', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rflags']

class Registers(OrderedDict):
    __register_names = reg32 if is_32bit else reg64

    def __init__(self, *args):
        super(Registers, self).__init__(zip(self.__register_names, args))

        # because we got here with a call the sp pushed on in on_hook_asm is
        # sizeof(void*) less than what it should be
        if is_32bit:
            self.esp += 4
        else:
            self.rsp += 8

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        if name in self.__register_names:
            if not isinstance(value, int):
                raise ValueError(type(value))
            else:
                self[name] = value
        super(Registers, self).__setattr__(name, value)

    def __str__(self):
        s='('
        for k,v in self.items():
            s += k+'='+hex(v)+', '
        return s[:-2]+')'
    __repr__ = __str__

    def values(self):
        return tuple(super(Registers, self).values())

class Memory:
    def __init__(self):
        self.load_mappings()

    def load_mappings(self):
        self.mappings = []
        self.modules = {}
        for mem in get_mappings():
            if mem.pathname and os.path.exists(mem.pathname):
                name = os.path.basename(mem.pathname)
                if name not in self.modules:
                    self.modules[name] = CollatedMapping(mem.start, mem.end, mem.pathname)
                else:
                    old = self.modules[name]
                    self.modules[name] = CollatedMapping(min(mem.start, old.start), max(old.end, mem.end), mem.pathname)
            self.mappings.append(mem)

    def search_map(self, bytes, mem, reload_maps=True):
        if reload_maps:
            self.load_mappings()
        return self.search(bytes, mem.start, mem.end)

    def search(self, bytes, start, end):
        needle = ctypes.create_string_buffer(bytes)
        while start < end:
            found = ctypes.c_void_p(libc.memmem(ctypes.c_void_p(start), end-start, ctypes.byref(needle), len(bytes))).value
            if not found:
                break
            start = found+len(bytes)
            yield found

    def search_module(self, bytes, module_name, reload_maps=True):
        if reload_maps:
            self.load_mappings()
        return search_map(bytes, self.modules[module_name], reload_maps=False)

    def module_base(self, module_name, reload_maps=True):
        if reload_maps:
            self.load_mappings()
        return self.modules[module_name].start

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            if idx.step:
                raise IndexError('step unsupported')
            return ctypes.string_at(idx.start, idx.stop-idx.start)
        else:
            return ctypes.string_at(idx, 1)

    def __setitem__(self, idx, bytes):
        if isinstance(idx, slice):
            if idx.step:
                raise IndexError('step unsupported')
            if idx.stop-idx.start != len(bytes):
                raise ValueError('slice length not equal to length of bytes to set')
            start = idx.start
        else:
            start = idx
            if len(bytes) != 1:
                raise ValueError('got more than one byte')
        cbytes = ctypes.create_string_buffer(bytes)
        ctypes.memmove(start, ctypes.addressof(cbytes), len(bytes))

    def get(self, addr, fmt):
        size = struct.calcsize(fmt)
        return struct.unpack(fmt, ctypes.string_at(addr, size))

    def get_single(self, addr, fmt):
        return self.get(addr, fmt)[0]

    def set(self, addr, values, fmt):
        value_raw = struct.pack(fmt, *values)
        value_buffer = ctypes.create_string_buffer(value_raw)
        ctypes.memmove(addr, ctypes.addressof(value_buffer), len(value_raw))

    def set_single(self, addr, value, fmt):
        self.set(addr, (value,), fmt)

    def set_ptr(self, addr, value):
        self.set_single(addr, value, '@P')

    def get_ptr(self, addr):
        return self.get_single(addr, '@P')

    def new_buffer(self, bytes, fmt=None):
        if fmt:
            bytes = struct.pack(fmt, *bytes)
        string_buffer = ctypes.create_string_buffer(bytes)
        addr = libc.malloc(len(bytes)+1)
        ctypes.memmove(addr, ctypes.addressof(string_buffer), len(bytes)+1)
        return addr

    def free(self, addr):
        return libc.free(addr)


memory = Memory()


if __name__ == '__main__':
    import json
    print(json.dumps(memory.modules, indent=True))
