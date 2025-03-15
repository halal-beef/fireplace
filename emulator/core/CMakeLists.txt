# Core emulator components

# SDL2/OpenGL stuff

# TODO: Split to another cmake file?
find_package(SDL2 REQUIRED)
include_directories(${SDL2_INCLUDE_DIRS})

find_package(OpenGL REQUIRED)
include_directories( ${OPENGL_INCLUDE_DIRS}  ${GLUT_INCLUDE_DIRS} )

add_executable(fireplace main.c)
target_link_libraries(fireplace PUBLIC fireplace_include m ${SDL2_LIBRARIES} ${OPENGL_LIBRARIES} ${GLUT_LIBRARY})