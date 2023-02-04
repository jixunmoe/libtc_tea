cmake_minimum_required(VERSION 3.21)
set(tc_tea_VERSION 0.1.4)
project(tc-tea VERSION ${tc_tea_VERSION} LANGUAGES CXX)
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

option(TC_TEA_BUILD_TESTING "Build library tests" ON)

include(cmake/git-info.cmake)

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS YES CACHE BOOL "Export all symbols")

configure_file (
    "${PROJECT_SOURCE_DIR}/src/version.cpp.in"
    "${PROJECT_BINARY_DIR}/src/version.cpp"
    @ONLY
)

file(GLOB_RECURSE HEADER_INTERFACES
  "include/*.h"
  "${PROJECT_BINARY_DIR}/include/*.h"
)

file(GLOB_RECURSE SOURCES
  "src/*.h"
  "src/*.cpp"
  "${PROJECT_BINARY_DIR}/src/*.h"
  "${PROJECT_BINARY_DIR}/src/*.cpp"
)

# Add source to this project's executable.
add_library(tc-tea STATIC ${SOURCES} ${HEADER_INTERFACES})
add_library(tc-tea::tc-tea ALIAS tc-tea)

target_compile_features(tc-tea PUBLIC cxx_std_17)
target_include_directories(tc-tea
	PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        src
        "${PROJECT_BINARY_DIR}/src"
)

configure_package_config_file(cmake/config.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/tc-tea-config.cmake
	INSTALL_DESTINATION ${CMAKE_INSTALL_DATADIR}/tc-tea
	NO_SET_AND_CHECK_MACRO)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/tc-tea-config-version.cmake
    VERSION ${tc_tea_VERSION}
    COMPATIBILITY SameMajorVersion)

install(
	FILES
		${CMAKE_CURRENT_BINARY_DIR}/tc-tea-config.cmake
		${CMAKE_CURRENT_BINARY_DIR}/tc-tea-config-version.cmake
	DESTINATION
		${CMAKE_INSTALL_DATADIR}/tc-tea)

install(TARGETS tc-tea EXPORT tc-tea-targets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT tc-tea-targets
	NAMESPACE tc-tea::
	DESTINATION ${CMAKE_INSTALL_DATADIR}/tc-tea)


# Tests!
if(TC_TEA_BUILD_TESTING)
  enable_testing()
  include(cmake/CPM-Loader.cmake)
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
  add_executable(tc-tea_test ${TESTS_SOURCE})
  target_include_directories(tc-tea_test PRIVATE src)
  target_compile_features(tc-tea_test PRIVATE cxx_std_17)
  target_link_libraries(tc-tea_test 
    GTest::gmock
    GTest::gtest
    GTest::gmock_main
    GTest::gtest_main
    tc-tea
  )

  include(GoogleTest)
  gtest_discover_tests(tc-tea_test)
endif()
