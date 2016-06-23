cmake_minimum_required(VERSION 3.2)

project(sporkel)

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)

add_subdirectory(ext)
add_subdirectory(sporkel)
add_subdirectory(deltagen)

