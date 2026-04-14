# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file LICENSE.rst or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-src")
  file(MAKE_DIRECTORY "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-src")
endif()
file(MAKE_DIRECTORY
  "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-build"
  "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-subbuild/robin_hood-populate-prefix"
  "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-subbuild/robin_hood-populate-prefix/tmp"
  "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-subbuild/robin_hood-populate-prefix/src/robin_hood-populate-stamp"
  "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-subbuild/robin_hood-populate-prefix/src"
  "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-subbuild/robin_hood-populate-prefix/src/robin_hood-populate-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-subbuild/robin_hood-populate-prefix/src/robin_hood-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/Users/yuchen/Documents/Coding/Taihang-Protocols/build/_deps/robin_hood-subbuild/robin_hood-populate-prefix/src/robin_hood-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
