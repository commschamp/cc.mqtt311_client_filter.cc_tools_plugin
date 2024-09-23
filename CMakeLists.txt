cmake_minimum_required (VERSION 3.11)
project ("cc_tools_plugin_mqtt311_client_filter")

# Available options
option (OPT_WARN_AS_ERR "Treat warning as error" ON)
option (OPT_USE_CCACHE "Use ccache if it's available" OFF)
option (OPT_WITH_DEFAULT_SANITIZERS "Build with sanitizers" OFF)

# Extra configuration variables
# OPT_QT_MAJOR_VERSION - Major Qt version. Defaults to 5
# OPT_CCACHE_EXECUTABLE - Custom ccache executable

# Extra standard CMake configuration
# CMAKE_CXX_STANDARD - C++ standard to use, defaults (and min required) to 17

#######################################################################

if ("${CMAKE_CXX_STANDARD}" STREQUAL "")
    set (CMAKE_CXX_STANDARD 17)
endif ()

if ("${OPT_QT_MAJOR_VERSION}" STREQUAL "")
    set (OPT_QT_MAJOR_VERSION 5)
endif ()

find_package(LibComms REQUIRED NO_MODULE)
find_package(cc_tools_qt REQUIRED NO_MODULE)
find_package(cc_mqtt311_client REQUIRED NO_MODULE)
find_package(Qt${OPT_QT_MAJOR_VERSION} REQUIRED COMPONENTS Widgets Core)

if (Qt${OPT_QT_MAJOR_VERSION}_VERSION VERSION_LESS 5.15)
    message(FATAL_ERROR "Minimum supported Qt version is 5.15!")
endif()

#######################################################################

# Compiler options
set (extra_opts)
if (OPT_WARN_AS_ERR)
    list (APPEND extra_opts WARN_AS_ERR)
endif ()

if (OPT_USE_CCACHE)
    list (APPEND extra_opts USE_CCACHE)
    if (NOT "${OPT_CCACHE_EXECUTABLE}" STREQUAL "")
        list(APPEND extra_opts CCACHE_EXECUTABLE "${OPT_CCACHE_EXECUTABLE}")
    endif()    
endif ()

if (OPT_WITH_DEFAULT_SANITIZERS)
    list(APPEND extra_opts DEFAULT_SANITIZERS)
endif()

include (${LibComms_DIR}/CC_Compile.cmake)
cc_compile(${compile_opts})
cc_msvc_force_warn_opt("/W4")

#######################################################################

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

include(GNUInstallDirs)
set (PLUGIN_INSTALL_REL_DIR ${CMAKE_INSTALL_LIBDIR}/cc_tools_qt/plugin)
set (PLUGIN_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/${PLUGIN_INSTALL_REL_DIR})

set (src
    src/Mqtt311ClientFilter.cpp
    src/Mqtt311ClientFilterConfigWidget.cpp
    src/Mqtt311ClientFilterPlugin.cpp
    src/Mqtt311ClientFilterSubConfigWidget.cpp
    src/ui.qrc
)

add_library (${CMAKE_PROJECT_NAME} MODULE ${src})
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE cc::cc_mqtt311_client cc::cc_tools_qt Qt::Widgets Qt::Core)
install (
    TARGETS ${CMAKE_PROJECT_NAME}
    DESTINATION ${PLUGIN_INSTALL_DIR})


