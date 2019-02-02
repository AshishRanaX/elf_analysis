# elf_analysis
Perform Static and dynamic analysis on 32 bit ELF binary, and automate the process of stack based overflow exploitation.


###efl2json.py
	convert objdump output of elf file to json.
  
	USAGE example,
   
 	```from elf2json import elf2json
	elf2json(PATH_2_BINARY,OUTPUT_JSON)```

###PXinteract.py
	Interact with subprocess sends stdin in a list and receives stdout & stderr.

	USAGE example,

	```from PXinteract import intearct
	op=interact(cmd,inp_list=[],stream=1)```

###final.py
	Do complete analysis for buffer overflow vulnerabilyt and genearte exploit

	USAGE example,

	```./final.py ls```

	This will analyse user defined function statically and dynamically and will generate the report under folder ./shells_ls