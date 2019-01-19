#!/usr/bin/python3

import os
import sys
from elf2json import elf2json
from collections import OrderedDict # beacuse normal dictionary looses their order
import ealib #elf analysis library

def main():
	if len(sys.argv) < 2:
		print("Usage ",sys.argv[0]," <elf_file>")
		exit()

	

	elf_obj=elf2json(sys.argv[1])

	print("Start point found @ "+elf_obj['start_addr'])
	addr_dict=ealib.find_addr(elf_obj['start_addr'],elf_obj)
	print("["+addr_dict['section']+"] ["+addr_dict['func']+"]")
	if addr_dict is not None:
		for addr,inst in elf_obj[addr_dict['section']][addr_dict['func']].items():
			print(addr+"\t : "+inst)
	

if __name__ == '__main__':
	main()