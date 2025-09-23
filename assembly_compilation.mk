# Assembly Compilation Makefile
# Compiles the massive assembly files

AS = nasm
LD = ld
ASFLAGS = -f elf64
LDFLAGS = -m elf_x86_64

# Targets
all: n0mn0m_meta_engine eon_ide_final

# N0MN0M Meta-Engine compilation
n0mn0m_meta_engine: n0mn0m_meta_engine_fixed.asm
	$(AS) $(ASFLAGS) n0mn0m_meta_engine_fixed.asm -o n0mn0m_meta_engine.o
	$(LD) $(LDFLAGS) -o n0mn0m_meta_engine n0mn0m_meta_engine.o -lc
	@echo "✅ N0MN0M Meta-Engine compiled successfully!"

# EON IDE System compilation  
eon_ide_final: eon_ide_final_fixed.asm
	$(AS) $(ASFLAGS) eon_ide_final_fixed.asm -o eon_ide_final.o
	$(LD) $(LDFLAGS) -o eon_ide_final eon_ide_final.o -lc -lxcb
	@echo "✅ EON IDE System compiled successfully!"

# Test compilation without linking
test_syntax: n0mn0m_meta_engine_fixed.asm eon_ide_final_fixed.asm
	$(AS) $(ASFLAGS) n0mn0m_meta_engine_fixed.asm -o n0mn0m_meta_engine_test.o
	$(AS) $(ASFLAGS) eon_ide_final_fixed.asm -o eon_ide_final_test.o
	@echo "✅ Syntax test passed for both files!"

clean:
	rm -f *.o n0mn0m_meta_engine eon_ide_final *_test.o

install: all
	cp n0mn0m_meta_engine /usr/local/bin/
	cp eon_ide_final /usr/local/bin/
	@echo "✅ Quantum systems installed!"

.PHONY: all test_syntax clean install
