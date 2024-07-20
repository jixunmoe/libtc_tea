cmake_minimum_required(VERSION 3.21)
set(tc_tea_VERSION 0.2.1)
project(tc-tea VERSION ${tc_tea_VERSION} LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
include(FetchContent)

option(BUILD_SHARED_LIBS "Build Shared Libraries" OFF)
option(TC_TEA_BUILD_TEST "Build library tests" ON)
option(TC_TEA_BUILD_INSECURE "Build extra, insecure version of CBC encrypt method" OFF)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
include(cmake/git-info.cmake)

configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/include/tc_tea/version.h.in"
        "${CMAKE_CURRENT_SOURCE_DIR}/include/tc_tea/version.h"
        @ONLY
)

set(SOURCES
        tc_tea/ecb.c
        tc_tea/cbc_encrypt.c
        tc_tea/cbc_decrypt.c
)

if (BUILD_SHARED_LIBS)
    add_library(tc_tea SHARED ${SOURCES})
    target_compile_definitions(tc_tea PRIVATE TC_TEA_BUILD_SHARED)
else ()
    add_library(tc_tea STATIC ${SOURCES})
    target_compile_definitions(tc_tea PRIVATE TC_TEA_BUILD_STATIC)
endif ()
if (TC_TEA_BUILD_INSECURE)
    target_compile_definitions(tc_tea PRIVATE TC_TEA_BUILD_INSECURE)
endif ()
target_include_directories(tc_tea
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_definitions(tc_tea PRIVATE TC_TEA_BUILDING_LIBRARY)

add_library(JixunMoe::tc_tea ALIAS tc_tea)

# Install
install(TARGETS tc_tea
        EXPORT tc_tea-targets
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})


# Testing
if (TC_TEA_BUILD_TEST)
    FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.15.0
    )
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    add_executable(tc_tea_test
            tc_tea/ecb.test.cc
            tc_tea/cbc.test.cc
    )
    target_link_libraries(
            tc_tea_test
            tc_tea
            gtest_main
            gmock_main
    )
    add_test(NAME tc_tea_test COMMAND tc_tea_test)
endif ()
