project(boost-filesystem)

set(boost-filesystem_SOURCES
	filesystem/src/codecvt_error_category.cpp
	filesystem/src/operations.cpp
	filesystem/src/path.cpp
	filesystem/src/path_traits.cpp
	filesystem/src/portability.cpp
	filesystem/src/unique_path.cpp
	filesystem/src/utf8_codecvt_facet.cpp
	filesystem/src/windows_file_codecvt.cpp)

set(boost-filesystem_HEADERS
	filesystem/src/windows_file_codecvt.hpp)

add_library(boost-filesystem
	${boost-filesystem_SOURCES}
	${boost-filesystem_HEADERS})

set(BOOST_FILESYSTEM_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/filesystem/include" CACHE PATH "boost system include path")
mark_as_advanced(BOOST_FILESYSTEM_INCLUDE_DIRS)