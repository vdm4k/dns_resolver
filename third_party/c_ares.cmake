set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)

find_package(c-ares 1.18)

if (c-ares_FOUND)
    return()
endif()

include(FetchContent)
FetchContent_Declare(
  c-ares
  GIT_REPOSITORY https://github.com/c-ares/c-ares.git
  GIT_TAG cares-1_19_0
)

FetchContent_MakeAvailable(c-ares)