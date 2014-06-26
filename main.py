#!/bin/env python

import random, ctypes, struct, time
from hook_internals import *

r = random.Random()


class Mod1:
    call = 0
    def f1(self, registers, hit_count):
        import pdb; pdb.set_trace()
        #print (registers)

        if is_32bit:
            string_address = memory.get_ptr(registers.esp+0x2c)
        else:
            string_address = memory.get_ptr(registers.rbp-0x30)

        self.call+=1
        if self.call == 1 and len(ctypes.string_at(string_address)) >= 3:
            # print(memory[string_address:string_address+5])
            memory[string_address:string_address+3] = b'HAX'
            registers.rax = 100

            heap_mapping = memory.mappings[2]
            heap = memory[heap_mapping.start:heap_mapping.end]
            tesa = heap.find(b'TESATIME')
            if tesa != -1:
                memory[heap_mapping.start+tesa:heap_mapping.start+tesa+3] = b'O_o'

        elif self.call == 2:
            memory.free(string_address) # the old string address is being overridden, making it dangling
            new_str_address = memory.new_buffer(b'Hello')
            if is_32bit:
                memory.set_ptr(registers.esp+0x2c, new_str_address)
            else:
                memory.set_ptr(registers.rbp-0x30, new_str_address)

            if is_32bit:
                spam_array_ptr = registers.esp+0x18
            else:
                spam_array_ptr = registers.rbp-0x50
            spam_array = memory.get(spam_array_ptr, '@5i')
            print('> the spam array is ', spam_array)
            memory.set(spam_array_ptr, (2, 3, 5, 7, 11), '@5i')

        elif self.call == 3:

            if is_32bit:
                loop_counter_address = registers.esp+0x3c
            else:
                loop_counter_address = registers.rbp-0x14

            # set the loop counter to -1. '@i' specified integer
            # note that memory.set(..., (-1,), '@i') is equivalent
            memory.set_single(loop_counter_address, -1, '@i')

            if not is_32bit:
                # the value at registers.rbp-0x28 holds the pointer to eggs
                eggs_array_ptr_ptr = memory.get_ptr(registers.rbp-0x28)
                eggs_array_ptr = memory.get_ptr(eggs_array_ptr_ptr)
                # eggs_array_ptr now points to the first element of the array
                eggs_array = memory.get(eggs_array_ptr, '@5i')
                print('> the eggs array is ', eggs_array)

                # free the old array
                memory.free(eggs_array_ptr)
                # and set the pointer to it to point to a new array of 5 signed integers
                memory.set_ptr(eggs_array_ptr_ptr, memory.new_buffer((-2, -3, -6, -7, -11), '@5i'))

        elif self.call == 6:

            # cause a div by 0 and see if the program still works
            print(1/0)

def f2(registers, hit_count):
    print (registers)

def hooks():

    for a in memory.mappings:
        if a.pathname == '[heap]':
            print(a)

    hooks64 = {
        0x400758 : (0x400762, f2),
        0x4007f4 : (0x400805, Mod1().f1, 2),
    }
    hooks32 = {
        0x8048634 : (0x8048644, Mod1().f1),
    }
    if is_32bit:
        return hooks32
    else:
        return hooks64


# set environment LD_PRELOAD=./mod32.so
