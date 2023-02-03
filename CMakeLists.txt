cmake_minimum_required(VERSION 3.21)
project(tc_tea VERSION 0.1.2 LANGUAGES CXX)

option(TC_TEA_BUILD_TESTING "Build library tests" ON)

find_program(CCACHE_TOOL_PATH ccache) # Optional

include(cmake/CPM-Loader.cmake)
include(cmake/git-info.cmake)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS YES CACHE BOOL "Export all symbols")

configure_file (
    "${PROJECT_SOURCE_DIR}/src/version.cpp.in"
    "${PROJECT_BINARY_DIR}/src/version.cpp"
    @ONLY
)

file(GLOB_RECURSE SOURCES
  "src/*.h"
  "src/*.cpp"
  "${PROJECT_BINARY_DIR}/src/*.h"
  "${PROJECT_BINARY_DIR}/src/*.cpp"
)

# Add source to this project's executable.
add_library(${PROJECT_NAME} STATIC ${SOURCES})
add_library("JixunMoe::LibTcTEA" ALIAS ${PROJECT_NAME})

target_include_directories(${PROJECT_NAME}
  PUBLIC
    $<INSTALL_INTERFACE:include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  PRIVATE
    src
    "${PROJECT_BINARY_DIR}/src"
)
target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_17)

include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})

install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
set_target_properties(${PROJECT_NAME} PROPERTIES EXPORT_NAME LibTcTea)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT ${PROJECT_NAME}-targets
  FILE
    LibTcTeaTargets.cmake
  NAMESPACE
    LibTcTea::
  DESTINATION
    ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# Tests!
if(TC_TEA_BUILD_TESTING)
  enable_testing()
  CPMAddPackage(
    NAME googletest
    GITHUB_REPOSITORY google/googletest
    GIT_TAG release-1.12.1
    VERSION 1.12.1
    OPTIONS
        "INSTALL_GTEST OFF"
        "gtest_force_shared_crt ON"
  )

  file(GLOB_RECURSE TESTS_SOURCE src/*.test.cc src/*.test.hh)
  add_executable(${PROJECT_NAME}_test ${TESTS_SOURCE})
  target_include_directories(${PROJECT_NAME}_test PRIVATE src)
  target_compile_features(${PROJECT_NAME}_test PRIVATE cxx_std_17)
  target_link_libraries(${PROJECT_NAME}_test 
    GTest::gmock
    GTest::gtest
    GTest::gmock_main
    GTest::gtest_main
    ${PROJECT_NAME}
  )

  include(GoogleTest)
  gtest_discover_tests(${PROJECT_NAME}_test)
endif()
