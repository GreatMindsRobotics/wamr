# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

cmake_minimum_required (VERSION 3.14)

project (iwasm C ASM CXX)
# set (CMAKE_VERBOSE_MAKEFILE 1)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

set (WAMR_BUILD_PLATFORM "windows")

# Reset default linker flags
set (CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set (CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "")

set(CMAKE_CXX_STANDARD 17)

# Set WAMR_BUILD_TARGET, currently values supported:
# "X86_64", "AMD_64", "X86_32", "AARCH64[sub]", "ARM[sub]", "THUMB[sub]", "MIPS", "XTENSA"
if (NOT DEFINED WAMR_BUILD_TARGET)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    # Build as X86_64 by default in 64-bit platform
    set (WAMR_BUILD_TARGET "X86_64")
  elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
    # Build as X86_32 by default in 32-bit platform
    set (WAMR_BUILD_TARGET "X86_32")
  else ()
    message(FATAL_ERROR "Unsupported build target platform!")
  endif ()
endif ()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif ()

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
  # Enable multiple modules
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

if (NOT DEFINED WAMR_BUILD_DEBUG_INTERP)
  # Disable Debug feature by default
  set (WAMR_BUILD_DEBUG_INTERP 0)
endif ()

if (WAMR_BUILD_DEBUG_INTERP EQUAL 1)
  set (WAMR_BUILD_FAST_INTERP 0)
  set (WAMR_BUILD_MINI_LOADER 0)
  set (WAMR_BUILD_SIMD 0)
endif ()

if (WAMR_BUILD_LIBC_WASI EQUAL 1)
  set (CMAKE_C_STANDARD 11)
  if (MSVC)
    add_compile_options(/experimental:c11atomics)
  endif()
else()
  set (CMAKE_C_STANDARD 99)
endif()

set (WAMR_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..)

include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)

# WAMR's wasm_export.h defines WASM_RUNTIME_API_EXTERN as
# __declspec(dllimport) when _MSC_BUILD is defined (MSVC or clang.exe
# in Windows mode — plain LLVM Windows clang sets _MSC_BUILD=1 to
# mimic MSVC). But this platform build produces a STATIC library
# (libiwasm.lib) and links iwasm.exe against it — no DLL involved.
# lld-link rejects dllimport-declared symbols that resolve to static
# defs ("undefined symbol: __declspec(dllimport) wasm_runtime_*").
# Override the macro to empty; consistent with the header's else-branch
# for non-MSVC static builds. Applied globally so vmlib and iwasm
# agree on symbol linkage attributes.
add_compile_definitions (WASM_RUNTIME_API_EXTERN= WASM_API_EXTERN=)

#set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWIN32_LEAN_AND_MEAN")
if (NOT MINGW)
  # /SAFESEH:NO is a link.exe / lld-link option. When cl.exe drives the
  # link it passes through unchanged. When plain clang.exe drives the
  # link (via -fuse-ld=lld-link) it needs -Xlinker to pass raw
  # options through — otherwise clang treats /SAFESEH:NO as a source
  # file and fails with "no such file or directory".
  if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Xlinker /SAFESEH:NO")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Xlinker /SAFESEH:NO")
  else ()
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /SAFESEH:NO")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /SAFESEH:NO")
  endif ()
endif ()

# The following flags are to enhance security, but it may impact performance,
# we disable them by default.
#if (WAMR_BUILD_TARGET MATCHES "X86_.*" OR WAMR_BUILD_TARGET STREQUAL "AMD_64")
#  set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftrapv -D_FORTIFY_SOURCE=2")
#endif ()
#set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong --param ssp-buffer-size=4")
#set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,noexecstack,-z,relro,-z,now")

include (${SHARED_DIR}/utils/uncommon/shared_uncommon.cmake)

# The Clay runtime sources and NativeSymbol tables every embedder
# compiles in (see that file for why the host iwasm needs them).
include (${CMAKE_CURRENT_SOURCE_DIR}/../../../../../Clay/runtime/natives/clay_natives.cmake)

add_executable (iwasm main.c
                ${CLAY_MOCK_NATIVES_C}
                ${CLAY_RT_NATIVES_C}
                ${CLAY_RUNTIME_SOURCES} ${UNCOMMON_SHARED_SOURCE})
target_compile_definitions (iwasm PRIVATE CLAY_MOCK_NATIVES=1)
target_include_directories (iwasm PRIVATE ${CLAY_RUNTIME_DIR})
# vmlib's WAMR_RUNTIME_LIB_SOURCE (build-scripts/runtime_lib.cmake §209)
# already carries PLATFORM_SHARED_SOURCE and UTILS_SHARED_SOURCE, so we
# do NOT relist those — repeating them would feed lld-link two copies
# of every symbol they define.  UNCOMMON_SHARED_SOURCE (bh_read_file_*)
# is the one set that vmlib does not include and main.c references, so
# it has to live in the iwasm exe.  cl.exe's linker silently de-duped
# the prior over-inclusive list, which is why the divergence was
# invisible before the ClangCL switch.

# When using clang-cl, the link step is lld-link which doesn't auto-
# pull clang's compiler-rt builtins (whereas a plain clang link line
# does).  Clay's f16 helpers (clay_render_float16 et al.) need
# `__truncsfhf2` / `__extendhfsf2` from clang_rt.builtins to convert
# between float and _Float16.  Discover the lib's location relative
# to the compiler at configure time so we don't pin a specific LLVM
# version.
if (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND WIN32)
    get_filename_component (CLANG_BIN_DIR ${CMAKE_C_COMPILER} DIRECTORY)
    get_filename_component (CLANG_ROOT ${CLANG_BIN_DIR} DIRECTORY)
    file (GLOB CLANG_RT_BUILTINS
          "${CLANG_ROOT}/lib/clang/*/lib/windows/clang_rt.builtins-x86_64.lib")
    if (CLANG_RT_BUILTINS)
        list (GET CLANG_RT_BUILTINS 0 CLANG_RT_BUILTINS_LIB)
        message (STATUS "Linking clang_rt builtins: ${CLANG_RT_BUILTINS_LIB}")
        target_link_libraries (iwasm "${CLANG_RT_BUILTINS_LIB}")
    else ()
        message (WARNING "clang_rt.builtins-x86_64.lib not found under ${CLANG_ROOT}; "
                         "f16 helpers (__truncsfhf2 / __extendhfsf2) will fail to link")
    endif ()
endif ()

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
  OUTPUT_NAME libiwasm
  PUBLIC_HEADER "${WAMR_PUBLIC_HEADERS}"
  POSITION_INDEPENDENT_CODE ON
)

target_link_libraries (vmlib ${LLVM_AVAILABLE_LIBS} ${UV_A_LIBS})
if (MINGW)
  target_link_libraries (vmlib ws2_32)
endif ()

if (WIN32)
  target_link_libraries(vmlib ntdll)
endif()

install (TARGETS vmlib
  EXPORT iwasmTargets
  DESTINATION lib
  PUBLIC_HEADER DESTINATION include
)

install_iwasm_package ()
