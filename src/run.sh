#!/bin/bash

ghc main.hs Tfhe/tfhe.hs Tfhe/c/tfhe_functions.c -ltfhe-spqlios-fma && ./main