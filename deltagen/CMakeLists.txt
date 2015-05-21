cmake_minimum_required(VERSION 2.8.7)

project(deltagen)

add_definitions(
	-DBOOST_ALL_NO_LIB)

include_directories(SYSTEM
	${BOOST_INCLUDE_DIRS}
	${SPORKEL_INCLUDE_DIRS})

set(deltagen_SOURCES
	deltagen.cpp)

add_executable(deltagen
	${LIBLZMA_CONFIG}
	${deltagen_SOURCES})

if (UNIX AND NOT APPLE)
	set_target_properties(deltagen PROPERTIES LINK_FLAGS -pthread)
endif()

target_link_libraries(deltagen
	${BOOST_LIBRARIES}
	${SPORKEL_LIBRARY})
