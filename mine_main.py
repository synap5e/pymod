import random, ctypes, struct, time

# import the memory object so that we can manipulate the process memory
from hook_internals import *

r = random.Random()

class Mod:
    
    def create_board(self, registers, call):
        """ Replaces the number of mines generated for a board with 0 so that we win straight away """
        
        # This hooks directly after the function prelouge for a function that creates the Minesweeper board
        # the arguments to function are stored on the stack and are [?this?, width, height, mines, seed ]
        
        # get the memory address of the arguments - stack pointer + 4
        argument_location = registers.esp+4
        
        # read the 5 signed interger arguments in native byte order from memory
        args = list(memory.get(argument_location, '@5i'))
        
        print("create_board(", args, end=')\n')
        
        # change one of the values of the arguments
        args[3] = 0
        
        # and write it back to memory, replacing the passed in arguments to the function with our own
        memory.set(registers.esp+4, args, '@5i')

def hooks():
    m = Mod()
    
    # the address of where we want to inject our code
    create_board_function_address = memory.module_base('minesweeper.exe') + 0x20dd4
    
    return {
        create_board_function_address : create_board_function_address+7, m.create_board, 1)
    }


