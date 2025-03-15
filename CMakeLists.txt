cmake_minimum_required(VERSION 3.10)
project(fireplace C)

set(CMAKE_C_STANDARD 11)

# TODO: Split to another cmake file?
find_package(SDL2 REQUIRED)
include_directories(${SDL2_INCLUDE_DIRS})

# Add source files
file(GLOB_RECURSE SRCS *.cpp)
file(GLOB_RECURSE HDRS *.h)

ADD_EXECUTABLE(fireplace  ${SRCS} ${HDRS})
target_link_libraries(fireplace ${SDL2_LIBRARIES})
