project(boost-iostreams)

if(LIBLZMA_CONFIG)
	add_definitions(
		-DLZMA_API_STATIC)
endif()

include_directories(
	${LIBLZMA_INCLUDE_DIRS})

set(boost-iostreams_SOURCES
	iostreams_lzma/src/lzma.cpp)

add_library(boost-iostreams
	${LIBLZMA_CONFIG}
	${boost-iostreams_SOURCES})

target_link_libraries(boost-iostreams
	${LIBLZMA_LIBRARIES})
