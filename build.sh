#!/bin/sh

g++ $@ ./src/main.cpp ./src/encrypt.cpp ./src/pos_fs.cpp ./src/posix.cpp -o main -std=c++20 -lssl -lcrypto -lncurses -fno-delete-null-pointer-checks -Wtrampolines -Wshadow