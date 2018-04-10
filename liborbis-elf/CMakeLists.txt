cmake_minimum_required(VERSION 3.0)

project(liborbis-elf)

set(SRC source/orbis-elf-api.c)
set(INCLUDE
        include/orbis-elf-api.h
        include/orbis-elf-enums.h
        include/orbis-elf-types.h)

add_library(${PROJECT_NAME} STATIC ${SRC} ${INCLUDE})

target_include_directories(${PROJECT_NAME} PUBLIC include)
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "")
set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE on)
