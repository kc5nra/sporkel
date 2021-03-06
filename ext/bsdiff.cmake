project(bsdiff)

add_definitions(-D_CRT_SECURE_NO_WARNINGS)

include_directories(
	bsdiff)

set(bsdiff_SOURCES
	bsdiff/sais.c
	bsdiff/bsdiff.c
	bsdiff/bspatch.c)

SET_SOURCE_FILES_PROPERTIES(${bsdiff_SOURCES} PROPERTIES LANGUAGE C)

add_library(bsdiff
	${bsdiff_SOURCES})

set(BSDIFF_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/bsdiff" CACHE PATH "bsdiff include path")
mark_as_advanced(BSDIFF_INCLUDE_DIRS)
