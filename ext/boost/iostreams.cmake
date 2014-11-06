project(boost-iostreams)

set(boost-iostreams_SOURCES
	iostreams/src/bzip2.cpp)

add_library(boost-iostreams
	${boost-iostreams_SOURCES})

target_link_libraries(boost-iostreams
	${BZIP2_LIBRARIES})

set(BOOST_IOSTREAMS_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/system/include" CACHE PATH "boost system include path")
mark_as_advanced(BOOST_IOSTREAMS_INCLUDE_DIRS)

