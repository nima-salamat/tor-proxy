cmake_minimum_required(VERSION 3.22)

project(TorProxyLauncher VERSION 1.3.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(WIN32)
    enable_language(RC)
    # The Windows launcher is a small Win32/GDI application. It deliberately
    # has no Qt dependency so users do not wait for a second Qt runtime before
    # Python starts. The ICO remains the native Explorer/taskbar icon; the
    # splash artwork itself is loaded from the higher-resolution PNG asset.
    add_executable(TorProxyLauncher WIN32 src/bootstrap.cpp)
    target_compile_features(TorProxyLauncher PRIVATE cxx_std_17)
    target_compile_definitions(TorProxyLauncher PRIVATE _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    target_link_libraries(TorProxyLauncher PRIVATE Shell32 Ole32 Gdiplus Advapi32)

    # The kill switch uses native WFP filters rather than editing every
    # pre-existing Windows Firewall rule through PowerShell/CIM.
    add_executable(TorProxyWfpHelper src/wfp_helper.cpp)
    target_compile_features(TorProxyWfpHelper PRIVATE cxx_std_17)
    target_compile_definitions(TorProxyWfpHelper PRIVATE _WIN32_WINNT=0x0A00 WINVER=0x0A00)
    target_link_libraries(TorProxyWfpHelper PRIVATE Fwpuclnt Iphlpapi Ole32)
    install(TARGETS TorProxyWfpHelper RUNTIME DESTINATION .)

    set(TORPROXY_ICON_RESOURCE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../assets/icon.ico")
    file(TO_CMAKE_PATH "${TORPROXY_ICON_RESOURCE_PATH}" TORPROXY_ICON_RESOURCE_PATH)
    configure_file(src/torproxy.rc.in "${CMAKE_CURRENT_BINARY_DIR}/torproxy.rc" @ONLY)
    target_sources(TorProxyLauncher PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/torproxy.rc")
    install(TARGETS TorProxyLauncher RUNTIME DESTINATION .)
else()
    # Linux keeps the Qt splash UI, isolated from the PySide6 runtime used by
    # the actual application.
    set(CMAKE_INSTALL_BINDIR "launcher-runtime/bin" CACHE STRING "Qt launcher runtime directory" FORCE)
    set(CMAKE_INSTALL_LIBDIR "lib" CACHE STRING "Qt launcher runtime library directory" FORCE)

    find_package(Qt6 6.8 REQUIRED COMPONENTS Widgets Network)
    qt_standard_project_setup()

    add_executable(TorProxyLauncher src/bootstrap.cpp)
    target_compile_features(TorProxyLauncher PRIVATE cxx_std_17)
    install(TARGETS TorProxyLauncher RUNTIME DESTINATION .)

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
endif()

if(MSVC)
    # Launcher UI strings use Unicode wide literals. Keep MSVC's source
    # character set explicit so UTF-8 punctuation is never decoded as CP1252.
    target_compile_options(TorProxyLauncher PRIVATE /W4 /permissive- /utf-8)
    if(TARGET TorProxyLauncherUI)
        target_compile_options(TorProxyLauncherUI PRIVATE /W4 /permissive-)
    endif()
    if(TARGET TorProxyWfpHelper)
        target_compile_options(TorProxyWfpHelper PRIVATE /W4 /permissive-)
    endif()
else()
    target_compile_options(TorProxyLauncher PRIVATE -Wall -Wextra -Wpedantic)
    if(TARGET TorProxyLauncherUI)
        target_compile_options(TorProxyLauncherUI PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif()
