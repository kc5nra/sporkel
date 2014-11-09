cmake_minimum_required(VERSION 2.8.12)

project(3rdparty-dependencies)

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include(bsdiff.cmake)
include(cereal.cmake)
include(sodium.cmake)

if (NOT BUILD_LZMA)
	find_package(LibLZMA QUIET)
endif()
if (NOT LIBLZMA_FOUND)
	message("-- LibLZMA not found or forced to build, compiling statically")
	add_subdirectory(lzma)
endif()

add_subdirectory(boost)
