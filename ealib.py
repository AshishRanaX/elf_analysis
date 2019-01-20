#!/usr/bin/python3 -tt

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