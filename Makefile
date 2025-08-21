# Compiler and Linker
CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -pedantic -g -O2 -D_BSD_SOURCE -D_DEFAULT_SOURCE
CPPFLAGS = -I./include
LIBS = -lpcap -lm

# Targets
TARGET = packet_counter
SRC_DIR = src
SRCS = $(SRC_DIR)/main.c $(SRC_DIR)/packet_parser.c
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(SRC_DIR)/%.o)

# Default target
all: $(TARGET)

# Main executable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(OBJS) $(LIBS)

# Compile source files to object files in same directory
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

# Test executable (if you have tests)
TEST_TARGET = test_parser
TEST_SRCS = tests/test_parser.c $(SRC_DIR)/packet_parser.c
TEST_OBJS = tests/test_parser.o $(SRC_DIR)/packet_parser.o

$(TEST_TARGET): $(TEST_OBJS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(TEST_OBJS) $(LIBS)

tests/%.o: tests/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

# Clean build artifacts (only in src/ and tests/)
clean:
	rm -f $(TARGET) $(TEST_TARGET) $(SRC_DIR)/*.o tests/*.o

# Run with example parameters
run: $(TARGET)
	sudo ./$(TARGET) -i eth0

# Run with filter example
run-filtered: $(TARGET)
	sudo ./$(TARGET) -i eth0 -f "tcp port 80"

# Show help
help:
	@echo "Available targets:"
	@echo "  all          - Build the main program (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  run          - Build and run with default interface"
	@echo "  run-filtered - Build and run with HTTP filter"

# Phony targets
.PHONY: all clean run run-filtered help

# Default target with success message
all: $(TARGET)
	@echo "========================================"
	@echo " Packet Counter built successfully!"
	@echo " Executable: $(TARGET)"
	@echo " Run with: sudo ./$(TARGET) -i <interface> [-f <filter>] [-t <seconds>]"
	@echo "========================================"


# Dependencies
$(SRC_DIR)/main.o: $(SRC_DIR)/main.c include/packet_parser.h
$(SRC_DIR)/packet_parser.o: $(SRC_DIR)/packet_parser.c include/packet_parser.h
tests/test_parser.o: tests/test_parser.c include/packet_parser.h
