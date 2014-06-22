#!/bin/env python

import random
r = random.Random()


def f1(registers):
	registers.rax=r.randint(0, 5000)
	return 'aa'


hooks = {
	0x400578 : (0x40057f, f1),
}
