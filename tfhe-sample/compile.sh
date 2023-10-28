#!/bin/env bash

gcc alice.c -o alice -ltfhe-spqlios-fma 
gcc cloud.c -o cloud -ltfhe-spqlios-fma 
gcc verif.c -o verif -ltfhe-spqlios-fma 
echo "Done"