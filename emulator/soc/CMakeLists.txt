# SoC libraries for the emulator

# External libs
find_package(PkgConfig REQUIRED)
pkg_check_modules(UNICORN REQUIRED unicorn)

#add_library(fireplace_soc STATIC gui_core.c)
#target_include_directories(fireplace_soc PRIVATE ${UNICORN_INCLUDE_DIRS})
#target_link_libraries(fireplace_soc PRIVATE ${UNICORN_LIBRARIES})
