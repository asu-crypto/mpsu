#!/bin/bash

# make and build
mkdir -p build
cd build
cmake -DTHREADING=ON ..
make 
cd ..