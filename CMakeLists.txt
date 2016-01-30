cmake_minimum_required(VERSION 2.8)

PROJECT(pcappriv C)
add_definitions("-Wall -O2")

SET(VERSION_MAJOR "0")
SET(VERSION_MINOR "2")

include_directories(/home/sora/wrk/src/github.com/wikimedia/analytics-libanon/build/include)
link_directories(/home/sora/wrk/src/github.com/wikimedia/analytics-libanon/build/lib)

add_executable(pcappriv
	src/anon.c
	src/cache.c
	src/pcappriv.c
	src/pcappriv.h
	src/signal.c
)

target_link_libraries(pcappriv anon)
