project(boost-program_options)

set(boost-program_options_SOURCES
	program_options/src/cmdline.cpp
	program_options/src/config_file.cpp
	program_options/src/convert.cpp
	program_options/src/options_description.cpp
	program_options/src/parsers.cpp
	program_options/src/positional_options.cpp
	program_options/src/split.cpp
	program_options/src/utf8_codecvt_facet.cpp
	program_options/src/value_semantic.cpp
	program_options/src/variables_map.cpp
	program_options/src/winmain.cpp)

add_library(boost-program_options
	${boost-program_options_SOURCES})