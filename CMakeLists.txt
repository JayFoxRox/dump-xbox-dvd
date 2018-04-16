cmake_minimum_required(VERSION 2.4)

if(WIN32)
  set(ARCH windows)
  set(CMAKE_EXE_LINKER_FLAGS "-static")
elseif(APPLE)
  set(ARCH macosx)
  set(CMAKE_EXE_LINKER_FLAGS "-framework IOKit -framework CoreFoundation")
elseif(UNIX)
  set(ARCH linux)
else()
  message(FATAL_ERROR "Unknown platform")
endif()


find_package(ZLIB REQUIRED)

include_directories(SYSTEM ${ZLIB_INCLUDE_DIRS})

add_executable(dump-xbox-dvd main.c ${ARCH}.c platform.h ss.c ss.h scsi.c scsi.h md5.c md5.h sha1.c sha1.h crc32.c crc32.h)
target_link_libraries(dump-xbox-dvd ${ZLIB_LIBRARIES})
if(WIN32)
  target_link_libraries(dump-xbox-dvd wsock32 ws2_32)
endif()
