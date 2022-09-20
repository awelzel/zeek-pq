cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(ZeekPluginPQ)

list(PREPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

find_package(PostgreSQL REQUIRED)

include_directories(BEFORE ${PostgreSQL_INCLUDE_DIRS} ${PostgreSQL_TYPE_INCLUDE_DIR})

include(ZeekPlugin)

zeek_plugin_begin(Zeek PQ ${ZEEK_PLUGIN_BEGIN_OPTS})
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_bif(src/pq.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_scripts(
        scripts/__load__.zeek
        scripts/__preload__.zeek
        scripts/types.zeek
        scripts/Zeek/PQ/__load__.zeek
)
zeek_plugin_link_library(${PostgreSQL_LIBRARIES})
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
