#!/usr/bin/python3 -tt
import os
import sys
import json
import re

def elf2json(elf_binary,output_file="output.json"):
	#check if sys.argv[1] file exists or not, if exists, is it ELF or similar
	if not os.path.isfile(elf_binary):
		raise FileNotFoundError('ELF binary not found')
		return None

	os.system("objdump -M intel -d "+elf_binary+" > objdump_op")
	wf=open(output_file,"w")
	opened_section=False  #for checking json curly brace is opened for section or not
	opended_func=False
	opened_instruction=False
	printed_instruction=False 	#varialbe will tell last iteration of loop wf.writeed instruction or not #for deciding to put comma at end or not
	fl=open("objdump_op","rU")
	wf.write("{\n")
	for line in fl:

		#for sections
		if line.find("Disassembly of section") != -1:
			section_name=re.search(r'Disassembly of section (.+?)\:',line).groups()[0]
			if opened_section:
				wf.write("\t}\n},\n\n")
				opened_section=False
				opended_func=False
			wf.write("\""+section_name+"\": { \n\n")
			printed_instruction=False
			opened_section=True
		

		# for functions
		mat_obj=re.search(r'.+?\<(.+?)\>\:',line)
		if mat_obj:
			if opended_func:
				wf.write("\t},\n\n")
				opended_func=False
			wf.write("\t\""+mat_obj.groups()[0]+"\": { \n\n")
			printed_instruction=False
			opended_func=True
		mat_obj=None
		
		#for instructions


		mat_obj=re.search(r'\s(\w+?):.+?\t(.+?)\n',line)
		if mat_obj:
			tup=mat_obj.groups()
			if printed_instruction:  #varialbe will tell last iteration of loop wf.writeed instruction or not
				wf.write(",\n")
			wf.write("\t\t\""+tup[0]+"\":\""+tup[1]+"\"")
			printed_instruction=True
		mat_obj=None

	wf.write("}}}\n")

	elf_obj=json.loads(open(output_file).read())
	return elf_obj