#!/bin/env python

import random, ctypes, struct, time
from hook_internals import *

r = random.Random()


class Mod1:
	my_str = ctypes.create_string_buffer(b"This is my string!")
	call = 0
	def f1(self, registers):
		string_address = get_long(registers.rbp-0x28)

		self.call+=1
		if self.call == 1 and len(ctypes.string_at(string_address)) >= 3:
			memory[string_address:string_address+3] = b'HAX'
			registers.rax = 100

			heap_mapping = memory.mappings[2]
			heap = memory[heap_mapping.start:heap_mapping.end]
			tesa = heap.find(b'TESATIME')
			if tesa != -1:
				memory[heap_mapping.start+tesa:heap_mapping.start+tesa+3] = b'O_o'

			for a in memory.mappings:
				if a.pathname == '[heap]':
					print(a)

		else:
			free(string_address) # the old string address is being overriden, making it dangling
			set_long(registers.rbp-0x28, new_buffer(b'Hello'))


		#import pdb; pdb.set_trace()


hooks = {
	0x40078d : (0x40079e, Mod1().f1),
}
