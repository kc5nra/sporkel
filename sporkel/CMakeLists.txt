cmake_minimum_required(VERSION 3.2)

project(sporkel)

add_definitions(
	-DSODIUM_STATIC
	-DBOOST_ALL_NO_LIB)

if(LIBLZMA_CONFIG)
	add_definitions(
		-DLZMA_API_STATIC
		-DHAVE_CONFIG_H)
endif()

include_directories(SYSTEM
	${BOOST_INCLUDE_DIRS}
	${BSDIFF_INCLUDE_DIRS}
	${CEREAL_INCLUDE_DIRS}
	${LIBLZMA_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS})

set(sporkel_SOURCES
	src/keypair.cpp
	src/crypto.cpp
	src/sign.cpp
	src/patch.cpp)

set(sporkel_HEADERS
	src/common.h
	include/sporkel.h)

add_library(sporkel STATIC
	${LIBLZMA_CONFIG}
	${sporkel_SOURCES}
	${sporkel_HEADERS})

if (UNIX AND NOT APPLE)
	set_target_properties(sporkel PROPERTIES LINK_FLAGS -pthread)
endif()

target_link_libraries(sporkel
	bsdiff
	sodium
	${BOOST_LIBRARIES})

set(SPORKEL_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/include
		CACHE PATH "sporkel include directories")

mark_as_advanced(SPORKEL_INCLUDE_DIRS)

set(SPORKEL_LIBRARY
	sporkel
		CACHE STRING "sporkel library")

mark_as_advanced(SPORKEL_LIBRARY)
