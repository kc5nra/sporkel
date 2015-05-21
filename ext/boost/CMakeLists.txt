cmake_minimum_required(VERSION 2.8.7)

project(boost)

add_definitions(
	-DBOOST_ALL_NO_LIB)

SET(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})

set(BOOST_INCLUDE_DIRS
	${CMAKE_CURRENT_SOURCE_DIR}/any/include
	${CMAKE_CURRENT_SOURCE_DIR}/array/include
	${CMAKE_CURRENT_SOURCE_DIR}/assert/include
	${CMAKE_CURRENT_SOURCE_DIR}/bind/include
	${CMAKE_CURRENT_SOURCE_DIR}/math/include
	${CMAKE_CURRENT_SOURCE_DIR}/concept_check/include
	${CMAKE_CURRENT_SOURCE_DIR}/config/include
	${CMAKE_CURRENT_SOURCE_DIR}/container/include
	${CMAKE_CURRENT_SOURCE_DIR}/core/include
	${CMAKE_CURRENT_SOURCE_DIR}/detail/include
	${CMAKE_CURRENT_SOURCE_DIR}/filesystem/include
	${CMAKE_CURRENT_SOURCE_DIR}/function/include
	${CMAKE_CURRENT_SOURCE_DIR}/functional/include
	${CMAKE_CURRENT_SOURCE_DIR}/integer/include
	${CMAKE_CURRENT_SOURCE_DIR}/io/include
	${CMAKE_CURRENT_SOURCE_DIR}/iostreams/include
	${CMAKE_CURRENT_SOURCE_DIR}/iostreams_lzma/include
	${CMAKE_CURRENT_SOURCE_DIR}/iterator/include
	${CMAKE_CURRENT_SOURCE_DIR}/lexical_cast/include
	${CMAKE_CURRENT_SOURCE_DIR}/move/include
	${CMAKE_CURRENT_SOURCE_DIR}/mpl/include
	${CMAKE_CURRENT_SOURCE_DIR}/numeric_conversion/include
	${CMAKE_CURRENT_SOURCE_DIR}/optional/include
	${CMAKE_CURRENT_SOURCE_DIR}/predef/include
	${CMAKE_CURRENT_SOURCE_DIR}/preprocessor/include
	${CMAKE_CURRENT_SOURCE_DIR}/program_options/include
	${CMAKE_CURRENT_SOURCE_DIR}/range/include
	${CMAKE_CURRENT_SOURCE_DIR}/smart_ptr/include
	${CMAKE_CURRENT_SOURCE_DIR}/static_assert/include
	${CMAKE_CURRENT_SOURCE_DIR}/system/include
	${CMAKE_CURRENT_SOURCE_DIR}/throw_exception/include
	${CMAKE_CURRENT_SOURCE_DIR}/tokenizer/include
	${CMAKE_CURRENT_SOURCE_DIR}/type_index/include
	${CMAKE_CURRENT_SOURCE_DIR}/type_traits/include
	${CMAKE_CURRENT_SOURCE_DIR}/utility/include
		CACHE PATH "boost include directories")

include_directories(
	${BOOST_INCLUDE_DIRS})

include(iostreams.cmake)
include(filesystem.cmake)
include(program_options.cmake)
include(system.cmake)

mark_as_advanced(BOOST_INCLUDE_DIRS)

set(BOOST_LIBRARIES
	boost-filesystem
	boost-iostreams
	boost-program_options
	boost-system
		CACHE STRING "boost libraries")

mark_as_advanced(BOOST_LIBRARIES)