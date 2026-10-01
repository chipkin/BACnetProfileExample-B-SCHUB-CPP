# embed_file.cmake - turns a text file into a C++ header holding it as a
# string, for files served by the hub (web/setup.html -> cert_portal_page.h).
# Run as:  cmake -DINPUT=<file> -DOUTPUT=<header> -DNAME=<variable> -P embed_file.cmake
#
# The file is written as an array of bytes, not a string literal: MSVC limits
# a string literal to about 16 KB, and the page is larger than that.

file(READ "${INPUT}" CONTENT HEX)
string(LENGTH "${CONTENT}" HEX_LENGTH)
math(EXPR BYTE_COUNT "${HEX_LENGTH} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1," BYTES "${CONTENT}")
# Wrap lines every 24 bytes so the generated header stays readable in a diff tool.
string(REGEX REPLACE "((0x[0-9a-f][0-9a-f],){24})" "\\1\n    " BYTES "${BYTES}")
get_filename_component(SOURCE_NAME "${INPUT}" NAME)
file(WRITE "${OUTPUT}"
"// Generated from ${SOURCE_NAME} by cmake/embed_file.cmake - do not edit; edit ${SOURCE_NAME}.
#pragma once
#include <string>
static const unsigned char ${NAME}_BYTES[] = {
    ${BYTES}0x00};
static const std::string ${NAME}(reinterpret_cast<const char*>(${NAME}_BYTES), ${BYTE_COUNT});
")
