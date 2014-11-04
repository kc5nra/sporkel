project(deltagen)

include_directories(
	${BSDIFF_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS})

set(deltagen_SOURCES
	deltagen.cpp)

add_executable(deltagen
	${deltagen_SOURCES})

target_link_libraries(deltagen
	bsdiff
	sodium)