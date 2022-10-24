#
# Copyright (c) 2022 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)

if("${BACKEND}" STREQUAL "")
  message(FATAL_ERROR "BACKEND variable must be set for this sample")
endif()

set(BACKEND_OVERLAY "boards/${BACKEND}.overlay")
set(BOARD_BACKEND_OVERLAY "boards/${BOARD}_${BACKEND}.overlay")

if(EXISTS ${BACKEND_OVERLAY})
  list(APPEND DTC_OVERLAY_FILE ${BACKEND_OVERLAY})
endif()
if(EXISTS ${BOARD_BACKEND_OVERLAY})
  list(APPEND DTC_OVERLAY_FILE ${BOARD_BACKEND_OVERLAY})
endif()

message("DTC_OVERLAY_FILE: ${DTC_OVERLAY_FILE}")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ipc_service_remote)

target_sources(app PRIVATE src/main.c)
