#!/bin/bash

# Download emp-toolkit libraries
echo "Downloading emp-toolkit libraries"
echo "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
cd emp
python3 download.py --deps --tool --ot --sh2pc
# modify emp-toolkit libraries so it is compatible with libOTe
echo "Modifying emp-toolkit libraries"
echo "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
python3 modify_block.py --directory emp-tool
python3 modify_block.py --directory emp-ot
python3 modify_block.py --directory emp-sh2pc
#change c++11 to c++14
python3 modify_cmake.py --file emp-tool/cmake/emp-base.cmake

# update sudo read
chmod 777 -R emp-tool/install_manifest.txt
chmod 777 -R emp-ot/install_manifest.txt
chmod 777 -R emp-sh2pc/install_manifest.txt


# Install emp-toolkit libraries
echo "Installing emp-toolkit libraries"
echo "python root_install.py --deps --tool --ot --sh2pc"
python3 root_install.py --deps --tool --ot --sh2pc


