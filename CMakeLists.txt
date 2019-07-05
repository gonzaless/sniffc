cmake_minimum_required(VERSION 3.10)
project(sniffc)

set(CMAKE_CXX_STANDARD 17)

#set(CMAKE_PREFIX_PATH ${E8_EXTERNAL_DIR})

add_library(nfc INTERFACE)

find_path(LIBNFC_INCLUDE_DIR nfc/nfc.h)
if (LIBNFC_INCLUDE_DIR)
	message(${LIBNFC_INCLUDE_DIR})
	target_include_directories(nfc INTERFACE ${LIBNFC_INCLUDE_DIR})
else()
	message(Failed to find libnfc headers)
endif()

find_library(LIBNFC_LIBRARY NAMES nfc)
if (LIBNFC_LIBRARY)
	message(${LIBNFC_LIBRARY})
	target_link_libraries(nfc INTERFACE ${LIBNFC_LIBRARY})
else()
	message(Failed to find libnfc library)
endif()


add_executable(sniffc main.cpp)
target_link_libraries(sniffc nfc)
