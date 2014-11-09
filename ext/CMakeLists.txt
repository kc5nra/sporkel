cmake_minimum_required(VERSION 2.8.12)

project(3rdparty-dependencies)

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include(bsdiff.cmake)
include(cereal.cmake)
include(sodium.cmake)

if (NOT BUILD_BZIP2)
	find_package(BZip2 QUIET)
endif()
if (NOT BZIP2_FOUND)
	message("-- BZIP2 not found or forced to build, compiling statically")
	include(bz2.cmake)
endif()

if (NOT BUILD_LZMA)
	find_package(LibLZMA QUIET)
endif()
if (NOT LIBLZMA_FOUND)
	message("-- LibLZMA not found or forced to build, compiling statically")
	add_subdirectory(lzma)
endif()

add_subdirectory(boost)
