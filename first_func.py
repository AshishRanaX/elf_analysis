#!/usr/bin/python3

import os
import sys
from elf2json import elf2json
from collections import OrderedDict # beacuse normal dictionary looses their order

def find_addr(addr,elf_obj):
	addr=addr.lstrip("0xX") # removing 0x pattern from starting of addr, as objdump instruction starting doesnt store addr in this format
	addr_dict={'section':None,'func':None,'asm':None}
	for sections,v in elf_obj.items():
		if isinstance(v,dict):
			for funcs,v1 in v.items():
				if isinstance(v1,dict):
					if addr in v1:
						addr_dict['section']=sections
						addr_dict['func']=funcs
						addr_dict['asm']=v1[addr]
						return addr_dict


	return None

def main():
	if len(sys.argv) < 2:
		print("Usage ",sys.argv[0]," <elf_file>")
		exit()

	

	elf_obj=elf2json(sys.argv[1])

	print("Start point found @ "+elf_obj['start_addr'])
	addr_dict=find_addr(elf_obj['start_addr'],elf_obj)
	print("["+addr_dict['section']+"] ["+addr_dict['func']+"]")
	if addr_dict is not None:
		for addr,inst in elf_obj[addr_dict['section']][addr_dict['func']].items():
			print(addr+"\t : "+inst)
	

if __name__ == '__main__':
	main()