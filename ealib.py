#!/usr/bin/python3 -tt
from PXinteract import interact
import re
from os import system,path
from collections import OrderedDict
from random import choice as rand

non_userdefined_funcs=["deregister_tm_clones","register_tm_clones","frame_dummy"]

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



def find_all_func(elf_obj):
	#will return all user defined function and their address
	func_names=[]
	global non_userdefined_funcs
	for func in elf_obj['.text']:
		if (func[0] != "_") and (func not in non_userdefined_funcs):
			addr="0x"+list(elf_obj['.text'][func].keys())[0]
			func_names.append((addr,func))
	return func_names

def find_first_func(elf_bin,elf_obj,mem_offset):
	#will return tuple with addr,funcname :: addr will be without offset
	
	
	funcs_list=find_all_func(elf_obj)
	
	first_func=find_addr(elf_obj['start_addr'],elf_obj)['func'] #first_func accordint to enry point
	first_func=first_func.split("@")[0]

	if first_func == "main":
		first_func_addr=hex(int(elf_obj['start_addr'],16)+int(mem_offset,16))
						#if first function in objdump is main or main@@Base

	else:
		system("echo -n '' > gdb.txt")
		if len(funcs_list)==1:
			first_func_addr=funcs_list[0][0]
		else:
			gdb_cmds=["b "+first_func,
					"run",
					"set logging on",
					"set logging redirect on",
					"while $eip"]
			for func_tup in funcs_list:
				gdb_cmds.append("if $eip == "+func_tup[0])
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
	first_func_addr=hex(int(first_func_addr,16)-int(mem_offset,16))
	return (first_func_addr,find_addr(first_func_addr,elf_obj)['func'])





def count_stdin(elf_bin,max_inps=10):
	#will return no. of stdin inpput needed by the process
	op=[]
	inps=0
	inp_li=["x"]
	for i in range(1,max_inps+1): #taking as max stdin input
		try:
			#print("trying :",inp_li*i)
			op=interact("strace "+elf_bin,inp_li*i,2)
		except:
			for ln in op:
				try:
					fd=re.search(r'\Aread\((\d+?),',ln).groups()[0]
					
					if int(fd) == 0:
						inps+=1
				except:
					pass
			break
	if i == max_inps:
		return i
	else:
		return inps

def func_call_flow(elf_bin,elf_obj):
	#will return list of
		#mem_offset
		#function name in order of call tuple(addr,func_name)

	funcs_list=find_all_func(elf_obj)
	n_stdin=count_stdin(elf_bin)
	inps_file=open("inps/std_inps","w")

	for i in range(n_stdin): #creating input file accorindg to number of stdin
		inps_file.write("A\n")
	inps_file.close()

	gdb_cmds=[]
	for func in funcs_list:
		fname=func[1].split("@")[0]
		gdb_cmds.append("break "+fname)
	gdb_cmds.append("run < inps")		#so that stdin wont interrupt gdb commands
	for i in range(len(funcs_list)*len(funcs_list)): #adding continue n*n times, bcs there can be some recursive loop so giving max tries as n*n
		gdb_cmds.append("continue")
	#print(gdb_cmds)	
	op=interact("gdb -q "+elf_bin,gdb_cmds)
	break_points=[]
	break_point_hits=[]
	
	for l in op:
		if l.find("Breakpoint") != -1:
			mat=None
			try:
				mat=re.search(r'Breakpoint (\d+?) at (\w+?)\n',l).groups()
			except:
				pass
			else:
				break_points.append(mat)

			mat=None
			try:
				mat=re.search(r'Breakpoint (\d+?), (\w+?) in (.+?) \(\)\n',l).groups()
			except:
				pass
			else:
				break_point_hits.append(mat)
				
	#break_point list, adding func name for addrs
	for i in range(len(break_points)):
		bp=break_points[i]
		func=find_addr(bp[1],elf_obj)['func']
		break_points[i]=bp+(func,)

	#calculating offset
	offset=[]
	for bph in list(set(break_point_hits)):
		for bp in break_points:
			if bp[0] == bph[0]:
				offset.append(hex(int(bph[1],16)-int(bp[1],16)))
	
	offset=list(set(offset))
	if len(offset) == 1:
		mem_offset=offset[0]
	else:
		mem_offset=None

	func_flow=[]
	for bph in break_point_hits:
		for bp in break_points:
			if bp[0] == bph[0]:
				func_flow.append((bp[1],bp[2]))

	return [mem_offset,func_flow]


def dump_memory(func_name,end_addr,elf_bin):
	#will return stack memory dump from func start to end in a list of integer values
	gdb_cmds=[]
	gdb_cmds.append("break "+func_name)
	gdb_cmds.append("run < inps/std_inps")
	gdb_cmds.append("break *"+end_addr)
	gdb_cmds.append("continue")
	#dumping memory , will dump +0x8 bytes, to get return addr in dumped memory
	gdb_cmds.append("dump memory "+"mem_dumps/"+func_name+" $esp $ebp+0x8")

	op=interact("gdb -q "+elf_bin,gdb_cmds)
	#print(op)

	if path.isfile("mem_dumps/"+func_name):
		mem_dump=open("mem_dumps/"+func_name, "rb").read()
		mem_dump_int=[]
		for i in mem_dump:
			if not isinstance(i,int):
				i=ord(i)
			mem_dump_int.append(i)
		return mem_dump_int
	else:
		return None


def bof_analysis(elf_bin,elf_obj,mem_offset):
	func_flow=func_call_flow(elf_bin,elf_obj)
	#mem_offset=func_flow[0] #find mem_offset with guess mem_offset (if mem is randomize discontinue analysis)
	func_flow=func_flow[1]

	break_points=[]
	for fun_tup in func_flow:
		func=fun_tup[1]
		func_n=func.split("@")[0]
		func_dict=find_func(func,elf_obj)
		
		if func_dict:
			for a,i in OrderedDict(reversed(list(elf_obj[func_dict['section']][func].items()))).items():
				if i.find("xchg") != -1 or i.find("ret") != -1 or i.find("hlt") != -1 or i.find("repz") != -1 or i.find("leave") != -1 or i.find("lea") != -1 or i.find("pop") != -1 or i.find("nop") != -1:
					pass
				else:
					break_points.append((func_n,hex(int("0x"+a,16)+int(mem_offset,16))))
					break
		else:
			raise Exception("Func Flow's Function not found in elf_obj")

	print(break_points)
	#exit()
	#creating input files
	n_stdin=count_stdin(elf_bin)
	inps_file=open("inps/std_inps","wb")



	for i in range(n_stdin): #creating input file accorindg to number of stdin
		chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		rand_chars=rand(chars)+rand(chars)+rand(chars)+rand(chars)
		inps_file.write(rand_chars.encode('utf-8')+b"\n")
	inps_file.close()

	vuln_list=[]
	for brk_tup in break_points:
		
		end_breakpoint=brk_tup[1]
		for i in range(4):
			print("Dumping for "+brk_tup[0]+"-> "+end_breakpoint)
			mem_dump_int=dump_memory(brk_tup[0],end_breakpoint,elf_bin)

			if not mem_dump_int:
				#not able to dump memory, hence trying to break program with one instruction above [brk_tup[0]]
				static_addr=hex(int(brk_tup[1],16)-int(mem_offset,16))
				addr_dict=find_addr(static_addr,elf_obj)
				prev_addr=None
				for i in elf_obj[addr_dict['section']][addr_dict['func']]:
					#print(i,static_addr)
					if "0x"+i == static_addr:
						break
					prev_addr=i
					
				
				end_breakpoint=hex(int("0x"+str(prev_addr),16)+int(mem_offset,16))

			else:
				break

			continue

		inps=open("inps/std_inps").readlines()
		vuln_details={'ret_addr':None,'shell_len':None,'func':None,'egg':False,'nth_input':None}
		vuln_details["func"]=brk_tup[0]
		nth_input=0
		for inp in inps:
			nth_input+=1
			inpl=[]
			for i in range(4):
				inpl.append(ord(inp[i]))
			#need to check if inpl is present in mem_dump in same order or not
			#print(inpl)
			offset=None
			for i in range(len(mem_dump_int)):

				if inpl[0]==int(mem_dump_int[i]):
			
					if inpl[1] ==mem_dump_int[i+1] and inpl[2] ==mem_dump_int[i+2] and inpl[3] ==mem_dump_int[i+3]:
			
						offset=i
						break
			if offset:
				vuln_to_bof=False
				vuln_details['egg']=True
				print("found EGG in "+brk_tup[0])
				
				#checking if we can overwrite EIP

				#creating input file
				inps_file=open("inps/std_inps1","wb")

				shell_len=len(mem_dump_int)-offset
				for i in inps:
					if i.find(inp) != -1:
						inps_file.write(b"YEGG"+b"A"*(shell_len-4)+b"\n")
					else:
						inps_file.write("X"+"\n")
				inps_file.close()

				gdb_cmds=[]
				gdb_cmds.append("break "+brk_tup[0])
				gdb_cmds.append("run < inps/std_inps1")
				gdb_cmds.append("break *"+brk_tup[1])
				gdb_cmds.append("continue")
				#dumping memory , will dump +0x8 bytes, to get return addr in dumped memory
				gdb_cmds.append("dump memory "+"mem_dumps/"+brk_tup[0]+" $esp $ebp+0x8")
				gdb_cmds.append("find $esp, $ebp+0x8, 0x47474559") #hex for string YEGG

				op=interact("gdb -q "+elf_bin,gdb_cmds)
				print(op)
				mem_dump=open("mem_dumps/"+brk_tup[0], "rb").read()
				mem_dump_int=[]
				for i in mem_dump[-4:]:
					if not isinstance(i,int):
						i=ord(i)
					mem_dump_int.append(i)
				if mem_dump_int[0]==65 and mem_dump_int[1]==65 and mem_dump_int[2]==65 and mem_dump_int[3]==65:
					#print("EIP can be ovewritten")
					
					vuln_details["shell_len"]=shell_len
					vuln_details["nth_input"]=nth_input
					#vuln_details={"func":brk_tup[0],"shell_len":shell_len}
					vuln_to_bof=True

				if vuln_to_bof:
					print(op)
					#finding stack address to overwrite in EIP
					try:
						ind=op.index("1 pattern found.\n")
						ret_addr=re.search(r'0x.+',op[ind-1]).group()
						vuln_details['ret_addr']=ret_addr

					except:
						raise Exception("Error in finding stack return address")

		if vuln_details:
			vuln_list.append(vuln_details)

	return vuln_list


def clean_temp():
	if not path.isdir("mem_dumps"):
		system("mkdir mem_dumps")
	else:
		system("rm -rf mem_dumps/*")
	if not path.isdir("inps"):
		system("mkdir inps")
	else:
		system("rm -rf inps/*")