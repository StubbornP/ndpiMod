cmake_minimum_required(VERSION 3.7)
project(modNDPI)

set(CMAKE_C_STANDARD 99)
set( CMAKE_C_FLAGS  ${CMAKE_C_FLAGS} -fPIC)

set(SOURCE_FILES modNDPI.c ndpi_util.c modNDPI.h ndpi_util.h)

find_library(
        LUALIB
        NAMES lua
        PATHS /usr/lib /usr/local/lib
)

add_library(modNDPI SHARED  ${SOURCE_FILES})

target_link_libraries(modNDPI libndpi.a ${LUALIB} )