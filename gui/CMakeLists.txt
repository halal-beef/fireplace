# GUI libraries for the emulator

# External libs
find_package(SDL2 REQUIRED)
include_directories(${SDL2_INCLUDE_DIRS})

set(OpenGL_GL_PREFERENCE LEGACY)

find_package(OpenGL REQUIRED)
include_directories( ${OPENGL_INCLUDE_DIRS}  ${GLUT_INCLUDE_DIRS} )

add_library(fireplace_gui STATIC gui_core.c)
target_link_libraries(fireplace_gui PUBLIC fireplace_include m ${SDL2_LIBRARIES} ${OPENGL_LIBRARIES} ${GLUT_LIBRARY})