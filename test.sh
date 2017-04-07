#! /bin/bash

if [ $# -ne 2 ]; then
    echo "needs to have 2 parameter"
    echo ""
    echo " * one for the number of key to generate"
    echo " * one for the threshold for the pvss command"
    exit 2
fi

[ -d .tmp ] && rm -rf .tmp

mkdir .tmp

for i in $(seq 1 1 ${1})
do
    echo "genarating key ${i}"
    if [ ${i} -lt 10 ]; then
        stack exec -- secretprime-cli generate -o .tmp/key-0$i.pem -p ""
    else
        stack exec -- secretprime-cli generate -o .tmp/key-$i.pem -p ""
    fi
done


stack exec -- secretprime-cli pvss ${2} $(echo .tmp/key-*.pem)

