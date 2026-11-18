cmake_minimum_required(VERSION 3.16)
project(plasmanetworkmanagement_fuckfortiui LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Core)
set(CMAKE_AUTOMOC ON)

# Arch/most distros: /usr/lib/qt6/plugins
set(QT_PLUGIN_INSTALL_DIR "lib/qt6/plugins" CACHE STRING "Qt plugin directory, relative to the prefix")

add_library(plasmanetworkmanagement_fuckfortiui MODULE fuckfortiui.cpp)
set_target_properties(plasmanetworkmanagement_fuckfortiui PROPERTIES PREFIX "")
target_link_libraries(plasmanetworkmanagement_fuckfortiui PRIVATE Qt6::Core)

install(TARGETS plasmanetworkmanagement_fuckfortiui DESTINATION ${QT_PLUGIN_INSTALL_DIR}/plasma/network/vpn)
