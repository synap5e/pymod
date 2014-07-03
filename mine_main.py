import random, ctypes, struct, time
from hook_internals import *

r = random.Random()

#import sys
#sys.stdout = open('py.log', 'w')
print("start")

class Mod:
    def create_board(self, registers, call):
        # [something, width, height, mines, seed ]
        args = list(memory.get(registers.esp+4, '@5i'))
        print("create_board(", args, end=')\n')
        args[3] = -1
        memory.set(registers.esp+4, args, '@5i')
        #memory.set(0x407414, (10,), '@i')
        #       print(registers)
        #       time.sleep(1)

m = Mod()

def hooks():
    import json
    #print(json.dumps(memory.modules, indent=True))
#   print("test")
#   print(mod)
    # mv = 999999999999999
    # for a in mod:
    #   if b'minesweeper.exe' in a:
    #       cv = int(a.split(b'-')[0][2:], 16)
    #       mv = min(cv, mv)

    # print(mv)
    # print("%08x" % mv)
    return {
        memory.module_base('minesweeper.exe') + 0x20dd4: (memory.module_base('minesweeper.exe') + 0x20dd4+7, m.create_board, 1)
    }


# 006A0DD4  /$ 6A 04          PUSH 4

# 00440DD4  /$ 6A 04          PUSH 4

