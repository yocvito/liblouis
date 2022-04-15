#!/bin/python3

import sys
import mmap
import argparse
import shutil
import os
from os import O_RDONLY, O_RDWR, O_WRONLY, O_TRUNC, O_CREAT, SEEK_END, SEEK_CUR, SEEK_SET

'''from pwn import *
context.quiet'''

DEFAULT_BINARY_NAME = 'fuzz_voice'
DEFAULT_CORPUS_NAME = 'corpus.txt'

def fd_get_size(fd):
    cur_off = os.lseek(fd, 0, SEEK_CUR)
    size = os.lseek(fd, 0, SEEK_END)
    os.lseek(fd, cur_off, SEEK_SET)
    return size


'''
    Check if a bytestring (should be a 2 letter bytestring) is an unicode character
    
    Returns the int value of the char and True if it is an unicode char, otherwise None and False
'''
def isUnicode(s):
    c=None
    if (not isAscii(s[0])) and (not isAscii(s[1])): 
        try:
            c=ord(s.decode('utf-8'))
            if (c > 0 and c < 0xffff) or (c > 0xe000 and c < 0x10ffff):
                return c, True
        except:
            pass
    return None, False


def isAscii(c):
    if c >= 32 and c <= 127:
        return True
    return False

'''
    Corpus class
    
    Allows to create corpus file from xx_list
'''
class Corpus:
    
    def __init__(self, files, output=DEFAULT_CORPUS_NAME):
        self.files = files
        self.output = output
        self.dict = ""
        self.dict_uni = ""
        self.ascii_lut = [False for i in range(0, 128)]
        self.unicode_lut = [False for i in range(0, 1112065)]
        
    '''
        build a dictonnary with all chars appearing in xx_list
    '''
    def retrieveDict(self):
        for filename in self.files:
            with open(filename, mode='rb') as fp:
                for line in fp.readlines():
                    for i in range(0, len(line)):
                        
                        if i != 0:
                            s = line[i-1: i+1] 
                            c, ret = isUnicode(s)
                            if ret == True and self.unicode_lut[c] is False:
                                self.unicode_lut[c] = True
                                self.dict_uni += chr(c)
                        
                        c = line[i]
                        if isAscii(c) and self.ascii_lut[c] is False:
                            self.ascii_lut[c] = True
                            self.dict += chr(c)
                    
                       
    
    '''
        Write dictionnary to output file
    '''
    def writeDictToFile(self):
        fd = os.open(self.output, O_WRONLY|O_CREAT|O_TRUNC, 0o644)
        print(self.dict)
        print(self.dict_uni)
        os.write(fd, self.dict.encode())
        os.write(fd, self.dict_uni.encode('utf-8'))
        os.close(fd)

        
'''
    Offsets class

    Retrieve all the offsets of the string xx (where xx is the language) in a binary
'''
class Offsets:
   
    def __init__(self, lang, binary):
        self.pattern = lang.encode() + b'\0'
        self.lang = lang
        self.fd = os.open(binary, O_RDWR)
        if self.fd < 0:
            raise Exception("File {} doesn't exist".format(binary))
        self.offsets = []
        self.__get_offsets()
        os.close(self.fd)
        
    '''
        Internal method to retrieve offsets from fuzzer binary file    
    '''
    def __get_offsets(self):
        size = fd_get_size(self.fd)
        #memsize = size + (mmap.PAGESIZE - (size % mmap.PAGESIZE))
        with mmap.mmap(self.fd , size, prot=mmap.PROT_READ|mmap.PROT_WRITE, flags=mmap.MAP_PRIVATE, offset=0) as mem:
            idx = 0
            bytelang = self.lang.encode() + b'\x00'
            while True:
                idx = mem.find(bytelang, idx+1, size)
                if idx < 0:
                    break
                self.offsets.append(idx)
                
    '''
        Get the offset list
    '''
    def getOffsets(self):
        return self.offsets


'''
    BinaryPatcher class
    
    Allows to patch a fuzzer binary, into multiple destination languages (could be usefull with a better args parsing)
'''
class BinaryPatcher:
     
    def __init__(self, fuzzbinary):
        self.binaryname = fuzzbinary
        if fuzzbinary[3:] != DEFAULT_BINARY_NAME:
            raise Exception("fuzzing binary model name doesn't respect requested format")
        self.offsets = Offsets(fuzzbinary[:2], fuzzbinary)
        
    def patch(self, language):
        self.patch(language, language + '_' + DEFAULT_BINARY_NAME)
        
    def patch(self, language, filename):
        path = shutil.copy(self.binaryname, filename)
        fd = os.open(path, O_RDWR)
        if fd < 0:
            raise Exception('Cannot achieved to open file ' + path)
        size = fd_get_size(fd)
        #memsize = size + (mmap.PAGESIZE - (size % mmap.PAGESIZE))
        with mmap.mmap(fd, size, prot=mmap.PROT_READ|mmap.PROT_WRITE, offset = 0) as mm:
            for off in self.offsets.getOffsets():
                self.__patch(mm, language, off)
    
    def __patch(self, mm, language, offset):
        mm.seek(offset, SEEK_SET)
        mm.write(language.encode())

def main(argc, argv):
    if argc < 3:
        print('Build corpus file(s) and voice fuzzer for a specified language.')
        print('Usage: {} <filename> <fuzzer-binary-model>'.format(argv[0]), file=sys.stderr)
        print('  filename               --  the filename of the dictsource/xx_list file')
        print('                             (The language will be extracted from this filename so respect format: xx_list)')
        print('  fuzzer-binary-model    --  the fuzzer binary (not source) for a language to be used as an example')
        print('                             (format: xx_fuzz_voice)')
        print('\nPLEASE Modify Corpus class if this script stop working after modifying fuzzer source code')
        exit(1)

    ap = argparse.ArgumentParser()

    # Add the arguments to the parser
    ap.add_argument("-f", "--files", required=True,
    help="the filenames list of the dictsource/xx_list files")
    ap.add_argument("-b", "--fuzz_binary", required=False,
    help="the fuzzer binary (not source) for a language to be used as an example")
    ap.add_argument("-l", "--language", required=True,
    help="the language of the created corpus and fuzzer binary")
    args = vars(ap.parse_args())

    files = []
    for file in args['files'].split(','):
        if file == '':
            print('Error in --files format', file=sys.stderr)
            exit(1)
        files.append(file)

    lang = args['language']
    binexample = args['fuzz_binary']
    
    c = Corpus(files, lang + '_corpus.txt')
    c.retrieveDict()
    c.writeDictToFile()
    
    if args['fuzz_binary'] is not None:
        bp = BinaryPatcher(binexample)
        bp.patch(lang, lang + '_fuzz_voice')
    
    

if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
