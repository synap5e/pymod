#!/usr/bin/env python

import struct, sys, os

signature = b'\xb6\x4b\xac\x70'


if len(sys.argv) < 2 or not sys.argv[1] in ['l', 'a', 'c']:
	print('argument 1 must be one of "l" (list), "a" (add), "c" (clear)')
	exit(-1)

opt = sys.argv[1]

if len(sys.argv) < 3 or not os.path.exists(sys.argv[2]):
	print('argument 2 must be a valid file')
	exit(-1)

path = sys.argv[2]

with open(path, 'rb') as f:
	data = f.read()

	files = {}

	if data[-4:] == signature:

		cursor = len(data)-8
		while True:
			end = cursor
			cursor = struct.unpack('<I', data[cursor:cursor+4])[0]
			if not cursor:
				break
			fpackeddata = data[cursor+4:end]
			fnameend = fpackeddata.find(b'\x00')
			fname = fpackeddata[:fnameend]
			fdata = fpackeddata[fnameend+1:]

			files[fname] = fdata

		data = data[:end]

if opt in ['a', 'c']:
	with open(path, 'r+b') as f:
		if opt == 'a':

			for newf in sys.argv[3:]:
				try:
					with open(newf, 'rb') as nf:
						files[bytes(os.path.basename(newf), 'utf-8')] = nf.read()
				except Exception as e:
					print(e)
					print("Ignoring %s" % newf)

			data += b'\x00'*4

			for fname, fdata in files.items():
				cursor = len(data)-4
				data += fname
				data += b'\x00'
				data += fdata
				data += struct.pack('<I', cursor)

			data += signature

			f.write(data)
		elif opt =='c':
			print("Clearing")
			f.write(data)
		f.truncate()

if opt == 'l':
	print('The files are:\n', *['\t' + x.decode('utf-8') + (' ' * (40-len(x))) + str(len(files[x])) + ' bytes\n' for x in files.keys()])


