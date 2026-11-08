cmake_minimum_required(VERSION 3.22)

project(TorProxyLauncher VERSION 2.0.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Keep the tiny bootstrap at the portable package root. The Qt application
# and its runtime are installed separately so they cannot shadow PySide6.
set(CMAKE_INSTALL_BINDIR "launcher-runtime/bin" CACHE STRING "Qt launcher runtime directory" FORCE)
if(WIN32)
    # Windows loads dependent DLLs from beside the Qt GUI executable.
    set(CMAKE_INSTALL_LIBDIR "launcher-runtime/bin" CACHE STRING "Qt launcher DLL directory" FORCE)
else()
    set(CMAKE_INSTALL_LIBDIR "lib" CACHE STRING "Qt launcher library directory" FORCE)
endif()

find_package(Qt6 6.8 REQUIRED COMPONENTS Widgets Network)
qt_standard_project_setup()

add_executable(TorProxyLauncher WIN32 src/bootstrap.cpp)
target_compile_features(TorProxyLauncher PRIVATE cxx_std_17)
if(WIN32)
    target_link_libraries(TorProxyLauncher PRIVATE Shell32)
endif()
install(TARGETS TorProxyLauncher RUNTIME DESTINATION .)

# The Qt UI and its dependencies are isolated from PySide6's private Qt
# runtime, preventing DLL/plugin/qt.conf collisions with the main app.
qt_add_executable(TorProxyLauncherUI
    WIN32
    src/main.cpp
    src/splash_window.cpp
    src/splash_window.h
)
target_link_libraries(TorProxyLauncherUI PRIVATE Qt6::Widgets Qt6::Network)
target_compile_definitions(TorProxyLauncherUI PRIVATE
    TORPROXY_VERSION="${PROJECT_VERSION}"
)
set_target_properties(TorProxyLauncherUI PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/launcher-runtime/bin"
)

if(MSVC)
    target_compile_options(TorProxyLauncher PRIVATE /W4 /permissive-)
    target_compile_options(TorProxyLauncherUI PRIVATE /W4 /permissive-)
else()
    target_compile_options(TorProxyLauncher PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(TorProxyLauncherUI PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS TorProxyLauncherUI
    BUNDLE DESTINATION launcher-runtime/bin
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

qt_generate_deploy_app_script(
    TARGET TorProxyLauncherUI
    OUTPUT_SCRIPT deploy_script
    NO_TRANSLATIONS
)
install(SCRIPT "${deploy_script}")
