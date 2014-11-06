project(bz2)

set(BZIP2_INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/bz2" CACHE PATH "bz2 include path")

include_directories(
  ${BZIP2_INCLUDE_DIRS}
)

set(bz2_SOURCES
	bz2/blocksort.c
	bz2/bzlib.c
	bz2/compress.c
	bz2/crctable.c
	bz2/decompress.c
	bz2/huffman.c
	bz2/randtable.c)

SET_SOURCE_FILES_PROPERTIES(${bz2_SOURCES} PROPERTIES LANGUAGE C)

add_library(bz2 ${bz2_SOURCES})

set(BZIP2_LIBRARIES
	bz2
		CACHE STRING "bz2 libraries")

mark_as_advanced(BZIP2_INCLUDE_DIRS)