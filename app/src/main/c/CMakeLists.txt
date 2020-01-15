# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

set(can_use_assembler TRUE)
enable_language(ASM)

set(OLLVM_PATH ${CMAKE_HOME_DIRECTORY}/../../../../../build/bin)
set(OLLVM_C_COMPILER ${OLLVM_PATH}/clang)
set(OLLVM_CXX_COMPILER ${OLLVM_PATH}/clang++)

set(OLLVM_C_FLAGS "-mllvm -sub -mllvm -bcf -mllvm -fla")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OLLVM_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OLLVM_C_FLAGS}")
set(CMAKE_C_COMPILER ${OLLVM_C_COMPILER})
set(CMAKE_CXX_COMPILER ${OLLVM_CXX_COMPILER})

#Set flags to detect arm32 bit or arm64 bit for switching between elf structures
if(${ANDROID_ABI} STREQUAL "armeabi-v7a" OR ${ANDROID_ABI} STREQUAL "x86")
    add_definitions("-D_32_BIT")
elseif(${ANDROID_ABI} STREQUAL "arm64-v8a" OR ${ANDROID_ABI} STREQUAL "x86_64")
    add_definitions("-D_64_BIT")
endif()


add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             native-lib.c)

target_include_directories(native-lib PRIVATE arch/${ANDROID_ABI})

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       native-lib

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )

add_custom_command( TARGET native-lib
        POST_BUILD
        COMMAND "${ANDROID_TOOLCHAIN_PREFIX}strip" -R .comment -g -S -d --strip-unneeded ${CMAKE_HOME_DIRECTORY}/../../../build/intermediates/cmake/${CMAKE_BUILD_TYPE}/obj/${ANDROID_ABI}/libnative-lib.so
        COMMENT "Stripped native library")