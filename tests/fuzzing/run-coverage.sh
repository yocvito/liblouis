#!/bin/bash

if [[ $# < 2 ]]
then
    echo "Usage: ${0} <fuzzer>"
    exit 1
fi


LLVM_PROFILE_FILE="${1}.profraw" `$1`
llvm-profdata merge -sparse $1.profraw -o $1.profdata
llvm-cov report $1 -instr-profile=$1.profdata 
llvm-cov show $1 -instr-profile=$1.profdata --show-branches=count --show-expansions