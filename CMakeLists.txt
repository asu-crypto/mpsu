cmake_minimum_required(VERSION 3.15)
project(MPSU)
add_executable(mpsu_make mpsu.cpp)
find_package(libOTe REQUIRED)
target_link_libraries(mpsu_make oc::libOTe)
target_link_libraries(mpsu_make oc::libOTe_Tests)
# add_subdirectory(libOTe/libOTe_Tests)
find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)
find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})
target_link_libraries(mpsu_make ${EMP-OT_LIBRARIES})


