#
# Copyright (c) 2022 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)

set(REMOTE_ZEPHYR_DIR ${CMAKE_CURRENT_BINARY_DIR}/ipc_service_remote-prefix/src/ipc_service_remote-build/zephyr)

if("${BACKEND}" STREQUAL "")
  message(FATAL_ERROR "BACKEND variable must be set for this sample")
endif()

if("${BOARD}" STREQUAL "nrf5340dk_nrf5340_cpuapp")
  set(BOARD_REMOTE "nrf5340dk_nrf5340_cpunet")
else()
  message(FATAL_ERROR "${BOARD} is not supported for this sample")
endif()

set(BACKEND_OVERLAY "backends/${BACKEND}.overlay")
set(BOARD_BACKEND_OVERLAY "boards/${BOARD}_${BACKEND}.overlay")

if(EXISTS ${BACKEND_OVERLAY})
  list(APPEND DTC_OVERLAY_FILE ${BACKEND_OVERLAY})
endif()
if(EXISTS ${BOARD_BACKEND_OVERLAY})
  list(APPEND DTC_OVERLAY_FILE ${BOARD_BACKEND_OVERLAY})
endif()

message("DTC_OVERLAY_FILE: ${DTC_OVERLAY_FILE}")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ipc_service)

target_sources(app PRIVATE src/main.c)

include(ExternalProject)

ExternalProject_Add(
  ipc_service_remote
  SOURCE_DIR ${APPLICATION_SOURCE_DIR}/remote
  INSTALL_COMMAND ""      # This particular build system has no install command
  CMAKE_CACHE_ARGS -DBOARD:STRING=${BOARD_REMOTE} -DBACKEND:STRING=${BACKEND}
  BUILD_BYPRODUCTS "${REMOTE_ZEPHYR_DIR}/${KERNEL_BIN_NAME}"
  # NB: Do we need to pass on more CMake variables?
  BUILD_ALWAYS True
)
