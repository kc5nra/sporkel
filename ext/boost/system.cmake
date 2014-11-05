project(boost-system)

set(boost-system_SOURCES
	system/src/error_code.cpp)

add_library(boost-system
	${boost-system_SOURCES})

set(BOOST_SYSTEM_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/system/include" CACHE PATH "boost system include path")
mark_as_advanced(BOOST_SYSTEM_INCLUDE_DIRS)