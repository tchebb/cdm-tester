CXX := clang++
CXXFLAGS := -std=c++14 -Wall -Wextra -Wno-unused-parameter -g
LDFLAGS := '-Wl,-rpath,$$ORIGIN' -L.
LDLIBS := -lwidevinecdm

OBJS := cdm-tester

all: $(OBJS)
clean:
	rm -f $(OBJS)

.PHONY: all clean
