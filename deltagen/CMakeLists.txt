project(deltagen)

add_definitions(
	-DSODIUM_STATIC
	-DBOOST_ALL_NO_LIB)

if(LIBLZMA_CONFIG)
	add_definitions(
		-DLZMA_API_STATIC
		-DHAVE_CONFIG_H)
endif()

include_directories(
	${BOOST_INCLUDE_DIRS}
	${BSDIFF_INCLUDE_DIRS}
	${CEREAL_INCLUDE_DIRS}
	${LIBLZMA_INCLUDE_DIRS}
	${SODIUM_INCLUDE_DIRS})

set(deltagen_SOURCES
	deltagen.cpp
	deltacommon.cpp)

set(deltagen_HEADERS
	deltagen.h
	deltacommon.h)

add_executable(deltagen
	${LIBLZMA_CONFIG}
	${deltagen_SOURCES}
	${deltagen_HEADERS})

if (UNIX AND NOT APPLE)
	set_target_properties(deltagen PROPERTIES LINK_FLAGS -pthread)
endif()

target_link_libraries(deltagen
	bsdiff
	sodium
	${BOOST_LIBRARIES})
