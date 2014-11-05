project(deltagen)

add_definitions(
	-DSODIUM_STATIC)

include_directories(
	${BSDIFF_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS})

set(deltagen_SOURCES
	deltagen.cpp
	deltacommon.cpp
	base64.cpp)

set(deltagen_HEADERS
	deltagen.h
	deltacommon.h
	base64.h)

add_executable(deltagen
	${deltagen_SOURCES}
	${deltagen_HEADERS})

target_link_libraries(deltagen
	bsdiff
	sodium)