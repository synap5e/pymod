import ctypes, struct, re, os
from collections import OrderedDict, namedtuple

is_32bit = struct.calcsize('P') == 4
is_windows = False

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
        Mapping = namedtuple('Mapping', ['start', 'end', 'perms', 'offset', 'dev', 'inode', 'pathname'])
        self.mappings = []
        self.modules = {}
        with open('/proc/self/maps') as f:
            for l in f.readlines():
                data = re.split('\s+', l)
                #print(data)
                data += [''] * (6-len(data))
                addr = data[0].split('-')
                mem = Mapping(
                    int(addr[0], 16),
                    int(addr[1], 16),
                    data[1],
                    int(data[2], 16),
                    data[3],
                    int(data[4]),
                    data[5])
                if mem.pathname and os.path.exists(mem.pathname):
                    self.modules[os.path.basename(mem.pathname)] = mem
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


try:
    libc = ctypes.cdll.LoadLibrary('libc.so.6')
except OSError:
    is_windows = True
    libc = ctypes.cdll.LoadLibrary('msvcrt.dll')

memory = Memory()


