project(deltagen)

add_definitions(
	-DSODIUM_STATIC
	-DBOOST_ALL_NO_LIB)

include_directories(
	${BOOST_INCLUDE_DIRS}
	${BSDIFF_INCLUDE_DIRS}
	${CEREAL_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS})

set(deltagen_SOURCES
	deltagen.cpp
	deltacommon.cpp)

set(deltagen_HEADERS
	deltagen.h
	deltacommon.h)

add_executable(deltagen
	${deltagen_SOURCES}
	${deltagen_HEADERS})

target_link_libraries(deltagen
	bsdiff
	sodium
	${BOOST_LIBRARIES})