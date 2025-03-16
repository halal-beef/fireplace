# Core emulator components

find_package(PkgConfig REQUIRED)
pkg_check_modules(UNICORN REQUIRED unicorn)

add_executable(fireplace main.c emulator.c)
target_include_directories(fireplace PRIVATE ${UNICORN_INCLUDE_DIRS})
target_link_libraries(fireplace PUBLIC fireplace_gui fireplace_soc ${UNICORN_LIBRARIES})