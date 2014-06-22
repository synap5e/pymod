import struct
from collections import OrderedDict

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
