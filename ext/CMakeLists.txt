cmake_minimum_required(VERSION 2.8.12)

project(3rdparty-dependencies)

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include(bsdiff.cmake)
include(cereal.cmake)
include(sodium.cmake)

find_package(BZip2 QUIET)
if (NOT BZIP2_FOUND)
	message("-- BZIP2 not found, compiling statically")
	include(bz2.cmake)
endif()

add_subdirectory(boost)

