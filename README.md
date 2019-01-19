# elf_analysis
Perform Static and dynamic analysis on 32 bit ELF binary, and automate the process of stack based overflow exploitation.


efl2json.py
  convert objdump output of elf file to json.
  
  USAGE example,
   
  from elf2json import elf2json
  elf2json(PATH_2_BINARY,OUTPUT_JSON)
