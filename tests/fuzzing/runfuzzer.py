#!/bin/python3

from posixpath import basename
from pty import STDERR_FILENO, STDOUT_FILENO
from socket import timeout
from stat import S_IRUSR, S_IWUSR
import sys
import os
import magic
import time
from pexpect import TIMEOUT
from pwn import *
from enum import Enum
from termcolor import colored


'''
fuzzing binaries and sources must respects the following format:
    fuzz_func_name.c
    fuzz-func_name
    
Makefile cleans all fuzz-* files in the fuzzing directory, so don't build your sources with this prefix

'''
PREFIX='fuzz-'

# pwntools logging level disabled (except for errors)
context.log_level = 'error'

class BugType(Enum):
    # Address Sanitizer bugs
    STACKOVERFLOW = 1
    HEAPOVERFLOW = 2
    MEMORYLEAK = 3
    USEAFTERFREE = 4
    DOUBLEFREE = 5
    
    # undefined behavior bugs
    INFINITELOOP = 100
    
    def __str__(self):
        return self.name


class Fuzzer:
    TIMEOUT = 3.0
    def __init__(self, pathname):
        self.path = pathname
        self.process = None
        self.bugs = []
        self.seed = 0
        
    
    """
        start fuzzer process and examinate output from it.
        logs every bugs found.
    """    
    def fuzz(self):
        # fork and start process (and redirecting its output to logfile)
        logfile = '.tmp-fuzz-' + self.getfunc() + '-logfile.txt'
        id = os.fork()
        if id == 0:
            fd = os.open(logfile, os.O_WRONLY|os.O_CREAT|os.O_TRUNC, S_IWUSR|S_IRUSR)
            os.dup2(fd, STDERR_FILENO)
            os.execvp(self.path, [self.path])

        start = time.time()
        cur = start
        while (cur-start) < self.TIMEOUT:
            pid,retcode = os.waitpid(id, os.WNOHANG)
            if pid == id:
                break
            cur = time.time()
        
        with open(logfile, 'r') as fp:
            self.seed = int(fp.readline().split(':')[-1])
            print(self.seed)
            
            if (cur-start) >= self.TIMEOUT:
                self.bugs.append(BugReport(basename(self.path), \
                    BugType.INFINITELOOP, self.seed, 'Infinite loop in binary (timed out after {} seconds)'.format(self.TIMEOUT)))

            trace = fp.read(4096)
            while len(trace) != 0:
                for line in trace.splitlines():
                    nexterr = line.find('ERROR')
                    if nexterr != -1:
                        reason = line.split(':')[-1].lstrip().split(' ')[0]
                        print(reason)
                trace = fp.read(4096)
        
    def getpath(self):
        return self.path
    
    def getfunc(self):
        return basename(self.path)[len(PREFIX):]
    
    def getBugsInfos(self):
        return self.bugs
    
    
class BugReport:
    def __init__(self, binary, bugType, seed, description):
        self.binary = binary
        self.type = bugType
        self.description = description
        self.seed = seed
        
    def getType(self):
        return self.type
    
    def __str__(self):
        return 'Binary: ' + self.binary + '\n' +  'Bug type: ' + str(self.type) + '\n' \
            + 'Seed: '+ str(self.seed) + '\n' + 'Description: ' + self.description 
        

def retrieve_fuzzers(path):
    files = os.listdir(path)
    fuzzers = []
    for file in files:
        pathname = path +'/'+ file
        if os.path.isdir(pathname):
            continue
        filetype = magic.from_file(pathname, mime=True)
        if filetype != 'application/x-executable' and filetype != 'application/x-dosexec':
            continue
        if file.find('fuzz-') != -1:
            fuzzers.append(Fuzzer(pathname))
    return fuzzers


def main(argc, argv):
    if argc < 2:
        print("Usage: {} <path-to-fuzzing-dir>".format(argv[0]))
        exit(1)
    path = argv[1]
    
    fuzzers = retrieve_fuzzers(path)
    if len(fuzzers) == 0:
        print('Cannot retrieve fuzzers from dir "{}"'.format(path))
        print('Make sure the fuzzer binaries are prefixed by "'+ PREFIX + '".')
        exit(1)
        
    print(colored('[Functions to be fuzzed]', 'yellow', attrs=['bold']))    
    bugReports = []
    for fuzzer in fuzzers:
        print('[-] ' + fuzzer.getfunc())
        fuzzer.fuzz()
        bugs = fuzzer.getBugsInfos()
        if len(bugs) > 0:
            for b in bugs:
                bugReports.append(b)
                
    if len(bugReports) == 0:
        print('No bugs found !')
        exit(0)                     # allowed to git push !

    nso = 0
    nho = 0
    nuaf = 0
    nml = 0
    ndf = 0
    nil = 0
    print(colored('[Bugs Report]', 'yellow', attrs=['bold']))
    with open('fuzzer-bug-reports.txt', 'w') as fp:
        for bug in bugReports:
            bugtype =  bug.getType()
            if bugtype == BugType.STACKOVERFLOW:
                nso += 1
            elif bugtype == BugType.HEAPOVERFLOW:
                nho += 1
            elif bugtype == BugType.MEMORYLEAK:
                nml += 1
            elif bugtype == BugType.USEAFTERFREE:
                nuaf += 1
            elif bugtype == BugType.DOUBLEFREE:
                ndf += 1
            elif bugtype == BugType.INFINITELOOP:
                nil += 1
            print(str(bug))
            fp.write(str(bug) + '\n')
            
    print(colored('[Statistics]', 'yellow', attrs=['bold']))
    print('[-] bugs found: ', len(bugReports))
    print('[-] stack overflows: ', nso)
    print('[-] heap overflows: ', nho) 
    print('[-] memory leaks: ', nml)
    print("[-] use after free's: ", nuaf)
    print("[-] double free's: ", ndf)
    print("[-] infinite loops: ", nil)
    
    exit(1)     # make git push fails
        
        
if __name__ == "__main__":
    main(len(sys.argv), sys.argv)