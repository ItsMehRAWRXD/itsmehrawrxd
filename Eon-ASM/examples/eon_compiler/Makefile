# EON Compiler Makefile
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
INCLUDES = -Iinclude
SRCDIR = src
OBJDIR = obj
BINDIR = bin

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
TARGET = $(BINDIR)/eon

# Default target
all: $(TARGET)

# Create directories
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(BINDIR):
	mkdir -p $(BINDIR)

# Build the compiler
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CC) $(OBJECTS) -o $@

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build artifacts
clean:
	rm -rf $(OBJDIR) $(BINDIR)

# Install the compiler
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Test the compiler
test: $(TARGET)
	@echo "Testing EON compiler..."
	@echo "def main() { let x = 5; ret x; }" > test.eon
	./$(TARGET) test.eon
	@echo "Assembly generated: out.asm"
	@rm -f test.eon

# Run example
example: $(TARGET)
	@echo "Running example..."
	@echo "def main() { let x = 5; let y = 10; let z = x + y; ret z; }" > example.eon
	./$(TARGET) example.eon
	nasm -f elf64 out.asm
	gcc out.o -o example
	./example
	@echo "Result: $$?"
	@rm -f example.eon out.asm out.o example

.PHONY: all clean install test example
