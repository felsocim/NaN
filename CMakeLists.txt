cmake_minimum_required(VERSION 3.9)
project(NaN)

set(CMAKE_CXX_STANDARD 11)

add_executable(NaN
        include/capture.h
        include/common.h
        src/capture.c
        src/common.c
        src/main.c)
