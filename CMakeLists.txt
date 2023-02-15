cmake_minimum_required(VERSION 3.10)
project(simba_parser)

set(PROJECT_NAME "simba-parser")

set(DEBUG_LEVEL "-g0")
set(OPT_LEVEL "-O3")
set(GCC_FLAGS "${DEBUG_LEVEL} ${OPT_LEVEL} -Wall -fno-exceptions")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  ${GCC_FLAGS}")

add_executable(${PROJECT_NAME} src/main.cpp)
