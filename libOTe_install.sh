#!/bin/bash

# Install libOTe
git submodule update --init

# Checkout correct version
cd libOTe
git submodule update --init

# Build libOTe
python3 build.py --setup --boost --relic --sodium --bitpolymul
python3 build.py -- -D ENABLE_RELIC=ON -D ENABLE_ALL_OT=ON -D ENABLE_SODIUM=ON

# install libOTe's packages
python3 build.py --setup --boost --relic --sodium  --bitpolymul --install
python3 build.py --install