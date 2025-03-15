cmake_minimum_required(VERSION 3.10)
project(fireplace C)

set(CMAKE_C_STANDARD 11)

# Include include directory (what a tongue-twister)
add_subdirectory(include)

# Include root subdirectory CMakeLists
add_subdirectory(emulator)
add_subdirectory(gui)

# add_executable and linking is handled by emulator/core/CMakeLists.txt
# See you there!