#!/usr/bin/env python
# Desc: pssh.py -- utility to RUN CMD on  a list of machines
#       Usage:  python pssh.py   iplist CMD
# Author: brianguo
# Date: 2017-01-16

import getpass
import sys
import os
import pexpect
import time
import re

from pexpect import *
from multiprocessing import Pool

if len(sys.argv) < 2 :
     print "Usage: python pssh.py   iplist CMD"
     exit(0)

##############################################################
# global SSH Setting
iplist = sys.argv[1]
ssh_cmd = sys.argv[2]
ssh_user = os.popen('whoami').read()
ssh_user = ssh_user.strip()[2:]  # delete 'm_' in m_USER
ssh_passwd = getpass.getpass('Input Login passowrd: ')
MAX_TIMEOUT = 40
t1 = time.time()

if 'TIMEOUT' in os.environ:
    MAX_TIMEOUT = int(os.environ['TIMEOUT'])
##############################################################
## RUN TASK on specific host 
def f_ssh_execute(host):    
    print "------------ RUNN IP = ", host, " -----------"
    cmd = "ssh -p 36000   "  + ssh_user + "@" + host  + "  " + ssh_cmd
    resp = "Resp: " + host + " :Info "
    try:
        child = spawn(cmd)
        ret = child.expect( [ 'yes/no', 'assword'])
        if ret == 0:
                child.sendline("yes")
                child.expect("assword")
        child.sendline( ssh_passwd )               
        child.expect( pexpect.EOF,  timeout=MAX_TIMEOUT )
        resp = resp + child.before
    except Exception as e:
        resp = resp + str(e)
    return resp           
def f_match_IP(str):
    ptn = re.compile(r'Resp:\s+([\d\.]+)\s+')
    m = ptn.search(str)
    return m.group(1)
##############################################################
## Main func 

if __name__ == '__main__':
    ips  = [ x.strip() for x in open(iplist).readlines() ]
    print ips
    p = Pool(50)
    output = p.map(f_ssh_execute, ips)  
    success_out = [ x+"\n\n" for x in output if x.find("pexpect.exceptions.EOF") == -1]
    fail_host   = [ x+"\n\n" for x in output if x.find("pexpect.exceptions.EOF") != -1]
    fail_ip_list = [ f_match_IP(x) for x in fail_host ]

    print "----------- SUCCESS INFO \n"
    for s in success_out:
        print s + "\n\n"

    print "----------- FAILED INFO \n"
    for s in fail_host:
        print s + "\n\n"
    
    time_last = time.time() - t1
    print ("\n\n---Total %d hosts,  success %d  ;  fail %d  !!! Total  Time =  %.1f seconds !!!\n" % ( len(ips), len(success_out), len(fail_host), time_last ) )  
    
    if len(fail_ip_list) > 0:
        print "--- FAIL IP LIST = "
        for f_ip in fail_ip_list:
            print f_ip
