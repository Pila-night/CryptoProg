.PHONY: all debug release clean

Compiler = g++
RELEASE_FLAGS = -O2 -Wall -DNDEBUG -Iheaders
DEBUG_FLAGS   = -g -O0 -Wall -Iheaders
RELEASE_EXEC  = Hash
SOURCES       = hasher.cpp
LIBARY        = -lcryptopp -lboost_program_options
all: release

release: $(RELEASE_EXEC)

$(RELEASE_EXEC): $(SOURCES)
	$(Compiler) $(RELEASE_FLAGS) $(SOURCES) -o $(RELEASE_EXEC) $(LIBARY)

clean:
	rm -f $(RELEASE_EXEC) $(DEBUG_EXEC)
