# resolve prefix relative to this file in ./lib/cmake/zuri.
get_filename_component(_ZURI_PREFIX "${CMAKE_CURRENT_LIST_FILE}" PATH)
get_filename_component(_ZURI_PREFIX "${_ZURI_PREFIX}" PATH)
get_filename_component(_ZURI_PREFIX "${_ZURI_PREFIX}" PATH)
get_filename_component(_ZURI_PREFIX "${_ZURI_PREFIX}" PATH)
if(_ZURI_PREFIX STREQUAL "/")
  set(_ZURI_PREFIX "")
endif()

add_library(zuri STATIC IMPORTED)

set_target_properties(zuri PROPERTIES
  IMPORTED_LOCATION "${_ZURI_PREFIX}/lib/libzuri.a"
  INTERFACE_INCLUDE_DIRECTORIES "${_ZURI_PREFIX}/include"
)

# cleanup prefix
set(_ZURI_PREFIX)
