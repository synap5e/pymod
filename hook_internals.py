import ctypes, struct, re
from collections import OrderedDict, namedtuple

class Registers(OrderedDict):
    __register_names = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'eflags']

    def __init__(self, *args):
        super(Registers, self).__init__(zip(self.__register_names, args))
        self.__initialized = True

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
        return list(super(Registers, self).values())

class Memory:
    def __init__(self):
        Mapping = namedtuple('Mapping', ['start', 'end', 'perms', 'offset', 'dev', 'inode', 'pathname'])
        self.mappings = []
        with open('/proc/self/maps') as f:
            for l in f.readlines():
                data = re.split('\s+', l)
                #print(data)
                data += [''] * (6-len(data))
                addr = data[0].split('-')
                self.mappings.append(Mapping(
                    int(addr[0], 16),
                    int(addr[1], 16),
                    data[1],
                    int(data[2], 16),
                    data[3],
                    int(data[4]),
                    data[5]))

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
                raise ValueError('slice length not equal value')
            start = idx.start
        else:
            start = idx
            if len(bytes) != 1:
                raise ValueError('got more than one byte')
        cbytes = ctypes.create_string_buffer(bytes)
        ctypes.memmove(start, ctypes.addressof(cbytes), len(bytes))


libc = ctypes.cdll.LoadLibrary('libc.so.6')
memory = Memory()

def get_long(addr):
    return struct.unpack('<Q', ctypes.string_at(addr, 8))[0]

def set_long(addr, value):
    new_address_raw_bytes = struct.pack('<Q', value)
    new_address_buffer = ctypes.create_string_buffer(new_address_raw_bytes)
    ctypes.memmove(addr, ctypes.addressof(new_address_buffer), 8)

def new_buffer(bytes):
    string_buffer = ctypes.create_string_buffer(bytes)
    addr = libc.malloc(len(bytes)+1)
    ctypes.memmove(addr, ctypes.addressof(string_buffer), len(bytes)+1)
    return addr

def free(addr):
    return libc.free(addr)
