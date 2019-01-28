#!/usr/bin/python3 -tt

#RUN PROCESS and interact with its stdin , 
#send stdin command in list and get output of commands in a list
#refernce https://dzone.com/articles/interacting-with-a-long-running-child-process-in-p

from subprocess import Popen,PIPE
from time import sleep
from threading import Thread
from os import system


out_list=[]
err_list=[]

def read_parallel(px): #read stdout
    global out_list
    for line in iter(px.stdout.readline, b''):
        try:
            out_list.append(line.decode('utf-8'))
        except:
            pass
        #if unicode decode error
        #out_list.append(line.decode('ISO-8859-1'))

def readerr_parallel(px):
    global err_list
    for line in iter(px.stderr.readline, b''):
        try:
            err_list.append(line.decode('utf-8'))
        except:
            pass


#def kill_switch(t,px,th):
#    sleep(t)
#    print("here")
#    px.stdin.close()
#    px.terminate()
#    system("kill -9 "+str(px.pid))
#    th.join()


def interact(cmd,inp_list=[],stream=1): #stream parameter can be either 1(stdout) or 2(stderr) or 3(both) in 3 op will be [[stdout op],[stderr op]]
    global out_list
    global err_list
    out_list=[]
    err_list=[]

    px=Popen(cmd.split(" "),stdin=PIPE,stdout=PIPE,stderr=PIPE)

    t=Thread(target=read_parallel,args=(px,))
    t.start()

    t1=Thread(target=readerr_parallel,args=(px,))
    t1.start()
    #kt=Thread(target=kill_switch,args=(kill_time,px,t,))
    #kt.start()
    for ix in inp_list:
        inp=ix+"\n"
        inp=inp.encode('utf-8')
        try:
            px.stdin.write(inp)
        except:
            raise Exception("Not able to write in stdin")
            return None
        try:
            px.stdin.flush()
        except:
            raise Exception("Not able to flush stdin")
            return None
            
        sleep(0.1)
        
    #output_reader(px)
    sleep(0.5)
    
    px.stdin.close()
    px.terminate()
    system("kill -9 "+str(px.pid))
    t.join()
    t1.join()

    if stream==1:
        return out_list
    elif stream==2:
        return err_list
    elif stream==3:
        return [out_list,err_list]
    else:
        return out_list