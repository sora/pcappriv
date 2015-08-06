cmake_minimum_required(VERSION 2.8)

PROJECT(pcappriv C)
add_definitions("-Wall -O2")

SET(VERSION_MAJOR "0")
SET(VERSION_MINOR "1")

include_directories(/home/sora/wrk/github.com/wikimedia/analytics-libanon/build/include)
link_directories(/home/sora/wrk/github.com/wikimedia/analytics-libanon/build/lib)

add_executable(pcappriv
	src/anon.c
	src/hash.c
	src/pcappriv.c
	src/pcappriv.h
	src/signal.c
)

target_link_libraries(pcappriv anon)
