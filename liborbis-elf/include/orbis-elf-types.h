#ifndef _ORBIS_ELF_TYPES_H_
#define _ORBIS_ELF_TYPES_H_

#include <stdint.h>

typedef struct OrbisElf_s *OrbisElfHandle_t;
typedef uint64_t (*OrbisElfReadCallback_t)(uint64_t offset, void *destination, uint64_t size, void *readUserDada);

typedef struct
{
	uint8_t magic[4];
	uint8_t eclass;
	uint8_t data;
	uint8_t eversion;
	uint8_t osabi;
	uint8_t abiver;
	uint8_t pad[7];
	uint16_t type; /* See OrbisElfType_t */
	uint16_t machine;
	uint32_t version;
	uint64_t entry;
	uint64_t phoff;
	uint64_t shoff;
	uint32_t flags;
	uint16_t ehsize;
	uint16_t phentsize;
	uint16_t phnum;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstrndx;
} OrbisElfHeader_t;

typedef struct
{
	uint32_t type; /* see OrbisElfProgramType_t */
	uint32_t flags;
	uint64_t offset;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t filesz;
	uint64_t memsz;
	uint64_t align;
} OrbisElfProgramHeader_t;

typedef struct
{
	uint32_t name;
	uint32_t type; /* see OrbisElfSectionType_t */
	uint64_t flags;
	uint64_t addr;
	uint64_t offset;
	uint64_t size;
	uint32_t link;
	uint32_t info;
	uint64_t addralign;
	uint64_t entsize;
} OrbisElfSectionHeader_t;

typedef struct
{
	uint32_t name;
	uint8_t info;
	uint8_t other;
	uint16_t shndx;
	uint64_t value;
	uint64_t size;
} OrbisElfSymbolHeader_t;

typedef struct
{
	uint64_t offset;
	uint64_t info;
} OrbisElfRel_t;

typedef struct
{
	uint64_t offset;
	uint64_t info;
	int64_t addend;
} OrbisElfRela_t;

typedef struct
{
	int64_t type; /* See OrbisElfDynamicType_t */
	uint64_t value;
} OrbisElfDynamic_t;


typedef struct OrbisElfLibraryInfo_s
{
	uint16_t version;
	uint16_t id;
	const char *name;
	uint32_t attr;
} OrbisElfLibraryInfo_t;

typedef struct OrbisElfModuleInfo_s
{
	uint16_t version;
	uint16_t id;
	const char *name;
	uint64_t attr;
} OrbisElfModuleInfo_t;

typedef struct OrbisElfSymbol_s
{
	OrbisElfSymbolHeader_t header;
	const char *name;
	const OrbisElfModuleInfo_t *module;
	const OrbisElfLibraryInfo_t *library;
	int bind; /* see OrbisElfSymbolBind_t*/
	int type; /* see OrbisElfSymbolType_t */
	uint64_t virtualBaseAddress;
} OrbisElfSymbol_t;

typedef struct OrbisElfRelocation_s
{
	uint64_t offset;
	int64_t addend;
	uint32_t symbolIndex;
	uint32_t relType; /* see OrbisElfRelocationType_t */
} OrbisElfRelocation_t;

typedef struct OrbisElfRebase_s
{
	uint64_t offset;
	uint64_t value;
	uint32_t symbolIndex;
} OrbisElfRebaseRelocation_t;

#endif /* _ORBIS_ELF_TYPES_H_ */
