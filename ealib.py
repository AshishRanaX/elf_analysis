#!/usr/bin/python3 -tt
from PXinteract import interact
import re

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

def find_func(func_name,elf_obj):
	addr_dict={'section':None,'addr':None}
	for sections,v in elf_obj.items():
		if isinstance(v,dict):
			for funcs,v1 in v.items():
				if funcs == func_name:
					addr_dict['section']=sections
					addr_dict['addr']=list(v1.keys())[0]
					return addr_dict

	return None


def print_asm(func_name,elf_obj):
	addr_dict=find_func(func_name,elf_obj)
	if addr_dict is not None:
		for addr,inst in elf_obj[addr_dict['section']][func_name].items():
			print(addr,":",inst)
	else:
		print(func_name,"not found.")
		return None
	return None

def find_mem_offset(elf_bin,elf_obj):
	#this function is with refernce to question asked here
	#https://stackoverflow.com/questions/54295129/elf-binary-analysis-static-vs-dynamic-how-does-assembly-code-instruction-memor

	#this function will return list, 0th ele is offset, 1st ele is True | Flase, True when result is with confidence and False without confidence
	loaded_start_addr=""
	first_func=find_addr(elf_obj['start_addr'],elf_obj)['func']
	op=interact("gdb -q "+elf_bin,["b "+first_func,"run","quit"])
	for line in op:
		try:
			loaded_start_addr=re.search(r'Breakpoint 1, (.+?) in _start',line).groups()[0]
		except:
			pass

	#guessing loaded_start_addr
	if int(loaded_start_addr,16) == int(elf_obj['start_addr'],16):
		return ["0x0",True]
	elif int(loaded_start_addr,16) == int(elf_obj['start_addr'],16)+int("0x400000",16): #adding 0x400000 according to answer in stackoverflow
		return ["0x400000",True]
	else:
		return [hex(int(loaded_start_addr,16) - int(elf_obj['start_addr'],16)),False]