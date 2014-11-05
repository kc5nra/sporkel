cmake_minimum_required(VERSION 2.8.12)

project(3rdparty-dependencies)

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include(sodium.cmake)
include(bsdiff.cmake)

add_subdirectory(boost)