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

def main(argc, argv):
    if argc < 3:
        print('Summary: Build corpus from files', file=sys.stderr)
        print(f'Usage: {argv[0]} -f <file(s)> -o <output-filename>', file=sys.stderr)
        exit(1)

    ap = argparse.ArgumentParser()

    # Add the arguments to the parser
    ap.add_argument("-f", "--files", required=True,
    help="the filenames list to extract char from and build corpus")
    ap.add_argument("-o", "--output", required=True,
    help="the output filename for the corpus file. If size exceed 4096, corpus is splited into files called <your-filename>-N.<your-ext> (extension is automatically extracted)")
    args = vars(ap.parse_args())

    files = []
    for file in args['files'].split(','):
        if file == '':
            print('Error in --files format', file=sys.stderr)
            print('Format is : --files=file0,file1,file2', file=sys.stderr)
            exit(1)
        files.append(file)
    
    c = Corpus(files, args['output'])
    c.retrieveDict()
    c.writeDictToFile()


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
