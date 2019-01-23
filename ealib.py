#!/usr/bin/python3 -tt
from PXinteract import interact
import re
from os import system

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
	start_addr=""
	first_func=find_addr(elf_obj['start_addr'],elf_obj)['func']
	#suppose first_func is main@@Base but while loading this in gdb, there is no such thing to get a breakpoint,
	#there is main @@Base is trimmed
	#experimental change
	first_func_n=first_func.split("@")[0]

	op=interact("gdb -q "+elf_bin,["b "+first_func_n,"run","quit"])
	for line in op:
		try:
			start_addr=re.search(r'Breakpoint 1 at (.+?)\n',line).groups()[0]
		except:
			pass
		try:
			loaded_start_addr=re.search(r'Breakpoint 1, (.+?) in '+first_func_n,line).groups()[0]
		except:
			pass
	if loaded_start_addr != "" and start_addr !="":
	#guessing loaded_start_addr
		
		if int(loaded_start_addr,16) == int(start_addr,16):
			return ["0x0",True]
		elif int(loaded_start_addr,16) == int(start_addr,16)+int("0x400000",16): #adding 0x400000 according to answer in stackoverflow
			return ["0x400000",True]
		else:
			return [hex(int(loaded_start_addr,16) - int(start_addr,16)),False]
	else:
		raise Exception("ealib find_mem_offset failed to find offset")

def guess_mem_offset(elf_bin,elf_obj):
	#based on find_mem_offset function
	result=[]
	for i in range(3):
		mem=None
		for j in range(2):
			try:
				mem=find_mem_offset(elf_bin,elf_obj)[0]
				break
			except:
				pass
		if mem:
			result.append(mem)

	if len(set(result)) == 1:
		return result[0]
	elif len(set(result)) == 0:
		return None
	else:
		raise Exception("Memory is randomized")


def find_first_func(elf_bin,elf_obj,mem_offset):
	text_addrs=[]
	for func in elf_obj['.text']:
		if (func[0] != "_") and (func != "register_tm_clones") and(func != "frame_dummy"):
			addr="0x"+list(elf_obj['.text'][func].keys())[0]
			text_addrs.append(hex(int(addr,16)+int(mem_offset,16)))


	first_func=find_addr(elf_obj['start_addr'],elf_obj)['func'] #first_func accordint to enry point
	first_func=first_func.split("@")[0]

	if first_func == "main":
		first_func_addr=hex(int(elf_obj['start_addr'],16)+int(mem_offset,16))
						#if first function in objdump is main or main@@Base

	else:
		system("echo -n '' > gdb.txt")
		if len(text_addrs)==1:
			first_func_addr=text_addrs[0]
		else:
			gdb_cmds=["b "+first_func,
					"run",
					"set logging on",
					"set logging redirect on",
					"while $eip"]
			for addr in text_addrs:
				gdb_cmds.append("if $eip == "+addr)
				gdb_cmds.append("set logging off")
				gdb_cmds.append("p \"found\"")
				gdb_cmds.append("x/x $eip")
				gdb_cmds.append("c")
				gdb_cmds.append("end")

			gdb_cmds.append("stepi")
			gdb_cmds.append("end")
			gdb_cmds.append("quit")
			
			op=interact("gdb -q "+elf_bin,gdb_cmds)
			system("echo -n '' > gdb.txt")
			try:
				first_func_addr=re.search(r'\$1 = \"found\"\n (.+?) ',' '.join(op)).groups()[0]
			except:
				#print("FFA : "+first_func_addr)
				#print(op)
				return None
	#return
	return find_addr(hex(int(first_func_addr,16)-int(mem_offset,16)),elf_obj)['func']