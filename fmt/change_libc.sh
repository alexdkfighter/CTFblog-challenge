#!/bin/sh
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./pwn
patchelf --replace-needed libc.so.6 ./libc.so.6 ./pwn
patchelf --print-interpreter ./pwn
patchelf --print-needed ./pwn
