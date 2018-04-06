.PHONY: all clean test install
all clean test install:
	$(MAKE) -C liborbis-elf $@
	$(MAKE) -C orbis-elf $@

$(V).SILENT:
