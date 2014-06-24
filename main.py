#!/bin/env python

import random, ctypes, struct, time
from hook_internals import *

r = random.Random()


class Mod1:
	my_str = ctypes.create_string_buffer(b"This is my string!")
	call = 0
	def f1(self, registers):
		string_address = memory.get_ptr(registers.rbp-0x30)

		self.call+=1
		if self.call == 1 and len(ctypes.string_at(string_address)) >= 3:
			#print(memory[string_address:string_address+5])

			memory[string_address:string_address+3] = b'HAX'
			registers.rax = 100

			heap_mapping = memory.mappings[2]
			heap = memory[heap_mapping.start:heap_mapping.end]
			tesa = heap.find(b'TESATIME')
			if tesa != -1:
				memory[heap_mapping.start+tesa:heap_mapping.start+tesa+3] = b'O_o'

			# for a in memory.mappings:
			# 	if a.pathname == '[heap]':
			# 		print(a)

		elif self.call == 2:
			memory.free(string_address) # the old string address is being overridden, making it dangling
			memory.set_ptr(registers.rbp-0x30, memory.new_buffer(b'Hello'))

			spam_array_ptr = memory.get(registers.rbp-0x50, '@5i')
			print('> the spam array is ', spam_array_ptr)
			memory.set(registers.rbp-0x50, (2, 3, 5, 7, 11), '@5i')

		elif self.call == 3:

			# set the loop counter back to 0. '@i' specified integer
			# note that memory.set(..., (0,), '@i') is equivalent
			memory.set_single(registers.rbp-0x14, 0, '@i')

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


		#import pdb; pdb.set_trace()

def hooks():
	hooks64 = {
		0x400834 : (0x400845, Mod1().f1),
	}
	if struct.calcsize('P') == 4:
		return hooks32
	else:
		return hooks64
