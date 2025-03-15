# Core emulator components

add_executable(fireplace main.c)
target_link_libraries(fireplace PUBLIC fireplace_gui)