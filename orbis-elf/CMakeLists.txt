cmake_minimum_required(VERSION 3.0)

project(orbis-elf)

add_executable(${PROJECT_NAME} orbis-elf.c)
target_link_libraries(${PROJECT_NAME} liborbis-elf)
