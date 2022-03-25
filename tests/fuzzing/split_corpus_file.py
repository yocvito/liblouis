#!/bin/python3

import sys

import os
from os import *
from os.path import *

def main(argc, argv):
    if argc < 3:
        print('Usage: {} <file> <newfiles-size>'.format(argv[0]))
        exit(1)

    size = int(argv[2])
    corpus = argv[1]
    fd = open(corpus, O_RDONLY)
    totalsize = lseek(fd, 0, SEEK_END)
    lseek(fd, 0, SEEK_SET)
    nb_files = totalsize // size + 1

    for i in range(0, nb_files):
        path, ext = splitext(corpus)
        cur = open(basename(path) + '-{}.txt'.format(i), O_WRONLY|O_CREAT|O_TRUNC, 0o644)
        write(cur, read(fd, size))
        close(cur)

    print('Corpus file splitted !')


if __name__ == "__main__":
    main(len(sys.argv), sys.argv)
