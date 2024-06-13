# mpsu_emp_libote

we have two dependency for mpsu project

1. libOTe v1.5.1 of
   
commit 2363505431f744539027a873c2536b9ae3630ff7
  
  with Cryptotools of
  
  commit 139a4b0b53d2f2ed0bee53f8e9e6775d141ddb50

2. To have garble circuit we use a custimized library of emptools.
https://github.com/personwhofloat/emptool_private_compare/tree/master


to run the project,

mkdir build

cd build

cmake ..

make && ./mpsu.exe

There will be an error messages for the first time to run the code. It's due to the emp and libOTe both contain class of block.
To fix that, go to every file in the emp containing "block" mentioned in the error messages, and change all the usage to "emp::block".
