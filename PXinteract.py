#!/usr/bin/python3 -tt
from subpxess import Popen,PIPE
from time import sleep
from threading import Thread
from os import kill
from signal import SIGSTOP

out_list=[]

def read_parallel(px):
    global out_list
    for line in iter(px.stdout.readline, b''):
        out_list.append(line.decode('utf-8'))

def interact(cmd,inp_list):
    global out_list
    px=Popen(cmd.split(" "),stdin=PIPE,stdout=PIPE,stderr=PIPE)

    t=Thread(target=read_parallel,args=(px,))
    t.start()
    
    for ix in inp_list:
        inp=ix+"\n"
        inp=inp.encode('utf-8')
        try:
            px.stdin.write(inp)
        except:
            print("Not able to write in stdin")
            return None
        try:
            px.stdin.flush()
        except:
            print("Not able to flush stdin")
            
        time.sleep(0.1)
        
    #output_reader(px)
    time.sleep(1)
    #print("out of loop")
    px.stdin.close()
    px.terminate()
    kill(px.pid,SIGSTOP)
    px.wait(timeout=0.2)
    t.join()
    return out_list