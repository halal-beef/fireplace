# Include interface for other CMakeLists to use

add_library(fireplace_include INTERFACE)

target_include_directories(fireplace_include INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})