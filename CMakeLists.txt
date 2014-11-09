cmake_minimum_required(VERSION 2.8.12)

project(sporkel)

include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)

CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++0x" COMPILER_SUPPORTS_CXX0X)
CHECK_C_COMPILER_FLAG("-std=c99" COMPILER_SUPPORTS_C99)

if(COMPILER_SUPPORTS_CXX11)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
elseif(COMPILER_SUPPORTS_CXX0X)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
elseif("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    # MSVC should support necessary C++11 features 
else()
		message(STATUS "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

if(COMPILER_SUPPORTS_C99)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
    # MSVC should support necessary C99 features 
else()
		message(STATUS "The compiler ${CMAKE_C_COMPILER} has no C99 support. Please use a different C99 compiler.")
endif()

add_subdirectory(ext)
add_subdirectory(deltagen)



