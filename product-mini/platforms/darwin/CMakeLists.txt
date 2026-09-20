# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project (iwasm)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

set (WAMR_BUILD_PLATFORM "darwin")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

# Set WAMR_BUILD_TARGET, currently values supported:
# "X86_64", "AMD_64", "X86_32", "AARCH64[sub]", "ARM[sub]", "THUMB[sub]",
# "MIPS", "XTENSA", "RISCV64[sub]", "RISCV32[sub]"
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
    set (WAMR_BUILD_TARGET "AARCH64")
  elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "riscv64")
    set (WAMR_BUILD_TARGET "RISCV64")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
    # Build as X86_32 by default in 32-bit platform
    set (WAMR_BUILD_TARGET "X86_32")
  else ()
    message(SEND_ERROR "Unsupported build target platform!")
  endif ()
endif ()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_CXX_STANDARD 17)

if (NOT DEFINED WAMR_BUILD_INTERP)
  # Enable Interpreter by default
  set (WAMR_BUILD_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_AOT)
  # Enable AOT by default.
  set (WAMR_BUILD_AOT 1)
endif ()

if (NOT DEFINED WAMR_BUILD_JIT)
  # Disable JIT by default.
  set (WAMR_BUILD_JIT 0)
endif ()

if (NOT DEFINED WAMR_BUILD_FAST_JIT)
  # Disable Fast JIT by default
  set (WAMR_BUILD_FAST_JIT 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_BUILTIN)
  # Enable libc builtin support by default
  set (WAMR_BUILD_LIBC_BUILTIN 1)
endif ()

if (NOT DEFINED WAMR_BUILD_LIBC_WASI)
  # Enable libc wasi support by default
  set (WAMR_BUILD_LIBC_WASI 1)
endif ()

if (NOT DEFINED WAMR_BUILD_FAST_INTERP)
  # Enable fast interpreter
  set (WAMR_BUILD_FAST_INTERP 1)
endif ()

if (NOT DEFINED WAMR_BUILD_MULTI_MODULE)
  # Disable multiple module by default
  set (WAMR_BUILD_MULTI_MODULE 0)
endif ()

if (NOT DEFINED WAMR_BUILD_LIB_PTHREAD)
  # Disable pthread library by default
  set (WAMR_BUILD_LIB_PTHREAD 0)
endif ()

if (NOT DEFINED WAMR_BUILD_MINI_LOADER)
  # Disable wasm mini loader by default
  set (WAMR_BUILD_MINI_LOADER 0)
endif ()

if (NOT DEFINED WAMR_BUILD_SIMD)
  # Enable SIMD by default
  set (WAMR_BUILD_SIMD 1)
endif ()

if (NOT DEFINED WAMR_BUILD_REF_TYPES)
  # Enable reference types by default
  set (WAMR_BUILD_REF_TYPES 1)
endif ()

if (NOT DEFINED WAMR_BUILD_DEBUG_INTERP)
  # Disable Debug feature by default
  set (WAMR_BUILD_DEBUG_INTERP 0)
endif ()

if (WAMR_BUILD_DEBUG_INTERP EQUAL 1)
  set (WAMR_BUILD_FAST_INTERP 0)
  set (WAMR_BUILD_MINI_LOADER 0)
  set (WAMR_BUILD_SIMD 0)
endif ()

set (CMAKE_SHARED_LINKER_FLAGS "-Wl,-U,_get_ext_lib_export_apis")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")

set (CMAKE_MACOSX_RPATH True)

# if enable wasi-nn, both wasi-nn-backends and iwasm
# need to use same WAMR (dynamic) libraries
if (WAMR_BUILD_WASI_NN EQUAL 1)
  set (BUILD_SHARED_LIBS ON)
endif ()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

# Option 2 (runtime-as-imports): the 6 pure Clay runtime .c files
# (clay_panic, clay_format, clay_check, clay_intrinsics, clay_string,
# clay_f16) compile into iwasm as native C and provide the function
# bodies that user wasms now import under module "clay_rt". The
# wrapper layer is Clay/runtime/natives/clay_rt_natives.c, auto-generated
# from clay_runtime.h by Clay/runtime/natives/gen_clay_rt_natives.py —
# rerun that script after editing the header. Without these sources,
# iwasm can't instantiate any wasm built with -DCLAY_RUNTIME_AS_IMPORTS.
set (CLAY_RUNTIME_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../../Clay/runtime)
set (CLAY_NATIVES_DIR ${CLAY_RUNTIME_DIR}/natives)
set (CLAY_RUNTIME_SOURCES
  ${CLAY_RUNTIME_DIR}/clay_panic.c
  ${CLAY_RUNTIME_DIR}/clay_format.c
  ${CLAY_RUNTIME_DIR}/clay_check.c
  ${CLAY_RUNTIME_DIR}/clay_intrinsics.c
  ${CLAY_RUNTIME_DIR}/clay_string.c
  ${CLAY_RUNTIME_DIR}/clay_f16.c
)

add_executable (iwasm main.c
                ${CLAY_NATIVES_DIR}/clay_mock_natives.c
                ${CLAY_NATIVES_DIR}/clay_rt_natives.c
                ${CLAY_RUNTIME_SOURCES} ${UNCOMMON_SHARED_SOURCE})
target_compile_definitions (iwasm PRIVATE CLAY_MOCK_NATIVES=1)
target_include_directories (iwasm PRIVATE ${CLAY_RUNTIME_DIR})

set_version_info (iwasm)

install (TARGETS iwasm DESTINATION bin)

target_link_libraries (iwasm vmlib)

add_library (vmlib ${WAMR_RUNTIME_LIB_SOURCE})

set_version_info (vmlib)

target_include_directories(vmlib INTERFACE
  $<INSTALL_INTERFACE:include>
)

set (WAMR_PUBLIC_HEADERS
  ${WAMR_ROOT_DIR}/core/iwasm/include/wasm_c_api.h
  ${WAMR_ROOT_DIR}/core/iwasm/include/wasm_export.h
  ${WAMR_ROOT_DIR}/core/iwasm/include/lib_export.h
)

set_target_properties (vmlib PROPERTIES
  OUTPUT_NAME iwasm
  PUBLIC_HEADER "${WAMR_PUBLIC_HEADERS}"
)

target_link_libraries (vmlib ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS} -lm -ldl -lpthread)

install (TARGETS vmlib
  EXPORT iwasmTargets
  DESTINATION lib
  PUBLIC_HEADER DESTINATION include
)

install_iwasm_package ()
