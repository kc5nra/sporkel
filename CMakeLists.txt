cmake_minimum_required(VERSION 3.2)

include(ucm/cmake/ucm.cmake)

project(sporkel)

set (CMAKE_C_STANDARD 99)
set (CMAKE_CXX_STANDARD 11)

set(RUNTIME_TYPE "" CACHE STRING "Select type of runtime: DYNAMIC or STATIC")
set_property(CACHE RUNTIME_TYPE PROPERTY STRINGS "" DYNAMIC STATIC)

if (RUNTIME_TYPE)
    ucm_set_runtime(${RUNTIME_TYPE})
    ucm_print_flags()
endif()

if (MSVC)
    option(MP_COMPILATION "Enable multi processor compilation" TRUE)
    if (MP_COMPILATION)
        ucm_add_flags(/MP)
    endif()
endif()

add_subdirectory(ext)
add_subdirectory(sporkel)
add_subdirectory(deltagen)

