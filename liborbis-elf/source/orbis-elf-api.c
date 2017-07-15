#include "orbis-elf-types.h"
#include "orbis-elf-enums.h"
#include "orbis-elf-api.h"

#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#define R_X86_64_NONE		0	/* No reloc */
#define R_X86_64_64		1	/* Direct 64 bit  */
#define R_X86_64_PC32		2	/* PC relative 32 bit signed */
#define R_X86_64_GOT32		3	/* 32 bit GOT entry */
#define R_X86_64_PLT32		4	/* 32 bit PLT address */
#define R_X86_64_COPY		5	/* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT	6	/* Create GOT entry */
#define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
#define R_X86_64_RELATIVE	8	/* Adjust by program base */
#define R_X86_64_GOTPCREL	9	/* 32 bit signed PC relative offset to GOT */
#define R_X86_64_32		10	/* Direct 32 bit zero extended */
#define R_X86_64_32S		11	/* Direct 32 bit sign extended */
#define R_X86_64_16		12	/* Direct 16 bit zero extended */
#define R_X86_64_PC16		13	/* 16 bit sign extended pc relative */
#define R_X86_64_8		14	/* Direct 8 bit sign extended  */
#define R_X86_64_PC8		15	/* 8 bit sign extended pc relative */
#define R_X86_64_DTPMOD64	16	/* ID of module containing symbol */
#define R_X86_64_DTPOFF64	17	/* Offset in module's TLS block */
#define R_X86_64_TPOFF64	18	/* Offset in initial TLS block */
#define R_X86_64_TLSGD		19	/* 32 bit signed PC relative offset to two GOT entries for GD symbol */
#define R_X86_64_TLSLD		20	/* 32 bit signed PC relative offset to two GOT entries for LD symbol */
#define R_X86_64_DTPOFF32	21	/* Offset in TLS block */
#define R_X86_64_GOTTPOFF	22	/* 32 bit signed PC relative offset to GOT entry for IE symbol */
#define R_X86_64_TPOFF32	23	/* Offset in initial TLS block */
#define R_X86_64_PC64		24	/* PC relative 64 bit */
#define R_X86_64_GOTOFF64	25	/* 64 bit offset to GOT */
#define R_X86_64_GOTPC32	26	/* 32 bit signed pc relative offset to GOT */
#define R_X86_64_GOT64		27	/* 64-bit GOT entry offset */
#define R_X86_64_GOTPCREL64	28	/* 64-bit PC relative offset to GOT entry */
#define R_X86_64_GOTPC64	29	/* 64-bit PC relative offset to GOT */
#define R_X86_64_GOTPLT64	30 	/* like GOT64, says PLT entry needed */
#define R_X86_64_PLTOFF64	31	/* 64-bit GOT relative offset to PLT entry */
#define R_X86_64_SIZE32		32	/* Size of symbol plus 32-bit addend */
#define R_X86_64_SIZE64		33	/* Size of symbol plus 64-bit addend */
#define R_X86_64_GOTPC32_TLSDESC 34	/* GOT offset for TLS descriptor.  */
#define R_X86_64_TLSDESC_CALL   35	/* Marker for call through TLS descriptor.  */
#define R_X86_64_TLSDESC        36	/* TLS descriptor.  */
#define R_X86_64_IRELATIVE	37	/* Adjust indirectly by program base */
#define R_X86_64_RELATIVE64	38	/* 64-bit adjust by program base */

typedef struct OrbisElfProgram_s
{
	OrbisElfProgramHeader_t header;
	const void *data;
} OrbisElfProgram_t;

typedef struct OrbisElfSection_s
{
	OrbisElfSectionHeader_t header;
	const char *name;
	const void *data;
} OrbisElfSection_t;

typedef struct OrbisElf_s
{
	const void *image;
	OrbisElfHeader_t header;

	OrbisElfProgram_t *programs;
	uint16_t programsCount;

	OrbisElfSection_t *sections;
	uint16_t sectionsCount;

	OrbisElfLibraryInfo_t *importLibraries;
	uint64_t importLibrariesCount;

	OrbisElfLibraryInfo_t *exportLibraries;
	uint64_t exportLibrariesCount;

	OrbisElfModuleInfo_t *importModules;
	uint64_t importModulesCount;

	OrbisElfSymbol_t *symbols;
	uint64_t symbolsCount;

	const OrbisElfSymbolHeader_t *sceSymTab;
	uint64_t sceSymTabSize;
	uint64_t sceSymTabEntrySize;

	const char *sceStrTab;
	uint64_t sceStrTabSize;

	const OrbisElfDynamic_t *dynamics;
	uint64_t dynamicsCount;

	const char *sceDynlibData;
	uint64_t sceDynlibDataSize;

	const char *soName;

	uint64_t pltGotAddress;
	uint64_t tlsIndex;
	uint64_t tlsOffset;
	uint64_t tlsSize;
	uint64_t tlsAlign;
	uint64_t tlsInitSize;
	uint64_t tlsInitAddress;

	uint64_t loadSize;

	OrbisElfDynamicType_t scePltRelType;
	uint64_t scePltRelSize;
	const void *sceJmpRel;

	const OrbisElfRelocationWithAddend_t *sceRela;
	uint64_t sceRelaSize;
	uint64_t sceRelaEntSize;

	uint64_t initAddress;
	uint64_t finiAddress;

	OrbisElfModuleInfo_t moduleInfo;
	uint64_t baseAddress;
} OrbisElf_t;

static OrbisElfErrorCode_t parsePrograms(OrbisElfHandle_t elf)
{
	elf->programs = malloc(sizeof(OrbisElfProgram_t) * elf->header.phnum);

	if (!elf->programs)
	{
		return orbisElfErrorCodeNoMemory;
	}

	elf->programsCount = elf->header.phnum;
	memset(elf->programs, 0, sizeof(OrbisElfProgram_t) * elf->programsCount);

	for (uint16_t i = 0; i < elf->programsCount; ++i)
	{
		elf->programs[i].header = ((const OrbisElfProgramHeader_t *)((const char *)elf->image + elf->header.phoff))[i];
		elf->programs[i].data = (const char *)elf->image + elf->programs[i].header.offset;

		switch (elf->programs[i].header.type)
		{
		case orbisElfProgramTypeLoad:
			if (elf->programs[i].header.vaddr + elf->programs[i].header.memsz > elf->loadSize)
			{
				elf->loadSize = elf->programs[i].header.vaddr + elf->programs[i].header.memsz;
			}
			break;

		case orbisElfProgramTypeDynamic:
			elf->dynamics = elf->programs[i].data;
			elf->dynamicsCount = elf->programs[i].header.filesz / sizeof(OrbisElfDynamic_t);
			break;

		case orbisElfProgramTypeSceDynlibData:
			elf->sceDynlibData = elf->programs[i].data;
			elf->sceDynlibDataSize = elf->programs[i].header.filesz;
			break;

		case orbisElfProgramTypeSceProcParam:
			//TODO
			break;

		case orbisElfProgramTypeTls:
			elf->tlsSize = elf->programs[i].header.memsz;
			elf->tlsAlign = elf->programs[i].header.align;
			elf->tlsInitSize = elf->programs[i].header.filesz;
			elf->tlsInitAddress = elf->programs[i].header.vaddr;
			break;
		}
	}

	return orbisElfErrorCodeOk;
}

static OrbisElfErrorCode_t parseSections(OrbisElfHandle_t elf)
{
	elf->sections = malloc(sizeof(OrbisElfSection_t) * elf->header.shnum);

	if (!elf->sections)
	{
		return orbisElfErrorCodeNoMemory;
	}

	elf->sectionsCount = elf->header.shnum;
	memset(elf->sections, 0, sizeof(OrbisElfSection_t) * elf->sectionsCount);

	const OrbisElfSectionHeader_t *strsection = NULL;

	if (elf->header.shstrndx < elf->sectionsCount)
	{
		strsection = ((const OrbisElfSectionHeader_t *)((const char *)elf->image + elf->header.shoff)) + elf->header.shstrndx;

		if (strsection->type != orbisElfSectionTypeStrTab)
		{
			strsection = NULL;
		}
	}

	for (uint16_t i = 0; i < elf->sectionsCount; ++i)
	{
		elf->sections[i].header = ((const OrbisElfSectionHeader_t *)((const char *)elf->image + elf->header.shoff))[i];
		elf->sections[i].data = (const char *)elf->image + elf->sections[i].header.offset;

		if (strsection)
		{
			elf->sections[i].name = (const char *)elf->image + strsection->offset + elf->sections[i].header.name;
		}
	}

	return orbisElfErrorCodeOk;
}

static OrbisElfErrorCode_t parseDynamicProgram(OrbisElfHandle_t elf)
{
	if (!elf->dynamics/* || !elf->sceDynlibData */)
	{
		return orbisElfErrorCodeOk;
	}

	elf->sceSymTabEntrySize = sizeof(OrbisElfSymbolHeader_t);
	elf->sceRelaEntSize = sizeof(OrbisElfRelocationWithAddend_t);

	for (uint64_t i = 0; i < elf->dynamicsCount && elf->dynamics[i].type != orbisElfDynamicTypeNull; ++i)
	{
		switch (elf->dynamics[i].type)
		{
		case orbisElfDynamicTypeSoName:
			break;

		case orbisElfDynamicTypeSceImportLib:
			elf->importLibrariesCount++;
			break;

		case orbisElfDynamicTypeSceExportLib:
			elf->exportLibrariesCount++;
			break;

		case orbisElfDynamicTypeSceNeededModule:
			elf->importModulesCount++;
			break;

		case orbisElfDynamicTypeSceSymTab:
			elf->sceSymTab = (const OrbisElfSymbolHeader_t *)(elf->sceDynlibData + elf->dynamics[i].value);
			break;

		case orbisElfDynamicTypeSceSymEnt:
			elf->sceSymTabEntrySize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceSymTabSize:
			elf->sceSymTabSize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceStrTab:
			elf->sceStrTab = (const char *)(elf->sceDynlibData + elf->dynamics[i].value);
			break;

		case orbisElfDynamicTypeSceStrSize:
			elf->sceStrTabSize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeScePltGot:
			elf->pltGotAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceModuleInfo:
			elf->moduleInfo.id = elf->dynamics[i].value >> 48;
			elf->moduleInfo.version = (elf->dynamics[i].value >> 32) & 0xffff;
			break;

		case orbisElfDynamicTypeSceModuleAttr:
			elf->moduleInfo.attr = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceJmpRel:
			elf->sceJmpRel = (const void *)(elf->sceDynlibData + elf->dynamics[i].value);
			break;

		case orbisElfDynamicTypeScePltRel:
			elf->scePltRelType = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeScePltRelSize:
			elf->scePltRelSize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceRela:
			elf->sceRela = (const OrbisElfRelocationWithAddend_t *)(elf->sceDynlibData + elf->dynamics[i].value);
			break;

		case orbisElfDynamicTypeSceRelaSize:
			elf->sceRelaSize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceRelaEnt:
			elf->sceRelaEntSize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeInit:
			elf->initAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeFini:
			elf->finiAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeNeeded:
			//TODO
			break;

		case orbisElfDynamicTypeInitArray:
			//TODO
			break;

		case orbisElfDynamicTypeFiniArray:
			//TODO
			break;

		case orbisElfDynamicTypeInitArraySize:
			if (elf->dynamics[i].value)
			{
				printf("orbisElfDynamicTypeInitArraySize with value %I64u\n", elf->dynamics[i].value);
			}
			//TODO
			break;

		case orbisElfDynamicTypeFiniArraySize:
			//TODO
			if (elf->dynamics[i].value)
			{
				printf("orbisElfDynamicTypeFiniArraySize with value %I64u\n", elf->dynamics[i].value);
			}
			break;

		case orbisElfDynamicTypeFlags:
			//TODO
			break;

		case orbisElfDynamicTypePreinitArray:
			//TODO
			break;

		case orbisElfDynamicTypePreinitArraySize:
			//TODO

			if (elf->dynamics[i].value)
			{
				printf("orbisElfDynamicTypePreinitArraySize with value %I64u\n", elf->dynamics[i].value);
			}
			break;

		case orbisElfDynamicTypeDebug:
			//TODO

			if (elf->dynamics[i].value)
			{
				printf("orbisElfDynamicTypeDebug with value %I64u\n", elf->dynamics[i].value);
			}
			break;

		case orbisElfDynamicTypeTextRel:
			//TODO

			if (elf->dynamics[i].value)
			{
				printf("orbisElfDynamicTypeDebug with value %I64u\n", elf->dynamics[i].value);
			}
			break;

		case orbisElfDynamicTypeSceHash:
			//TODO
			break;

		case orbisElfDynamicTypeSceHashSize:
			//TODO
			break;


		case orbisElfDynamicTypeSceExportLibAttr:
		case orbisElfDynamicTypeSceImportLibAttr:
			break;

		case orbisElfDynamicTypeSceFingerprint:
			//TODO
			break;

		case orbisElfDynamicTypeSceOriginalFilename:
			break;

		default:
			printf("Unhandled dynamic type 0x%I64x\n", elf->dynamics[i].type);
			continue;
		}
	}

	if (!elf->sceStrTab)
	{
		return orbisElfErrorCodeOk;
	}

	if (elf->importModulesCount)
	{
		elf->importModules = malloc(sizeof(OrbisElfModuleInfo_t) * elf->importModulesCount);

		if (!elf->importModules)
		{
			return orbisElfErrorCodeNoMemory;
		}

		memset(elf->importModules, 0, sizeof(OrbisElfModuleInfo_t) * elf->importModulesCount);
	}

	if (elf->importLibrariesCount)
	{
		elf->importLibraries = malloc(sizeof(OrbisElfLibraryInfo_t) * elf->importLibrariesCount);

		if (!elf->importLibraries)
		{
			return orbisElfErrorCodeNoMemory;
		}

		memset(elf->importLibraries, 0, sizeof(OrbisElfLibraryInfo_t) * elf->importLibrariesCount);
	}

	if (elf->exportLibrariesCount)
	{
		elf->exportLibraries = malloc(sizeof(OrbisElfLibraryInfo_t) * elf->exportLibrariesCount);

		if (!elf->exportLibraries)
		{
			return orbisElfErrorCodeNoMemory;
		}

		memset(elf->exportLibraries, 0, sizeof(OrbisElfLibraryInfo_t) * elf->exportLibrariesCount);
	}

	for (uint64_t i = 0, moduleIndex = 0, importLibraryIndex = 0, exportLibraryIndex = 0; i < elf->dynamicsCount; ++i)
	{
		switch (elf->dynamics[i].type)
		{
		case orbisElfDynamicTypeSoName:
			elf->soName = elf->sceStrTab + elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceImportLib:
			elf->importLibraries[importLibraryIndex].id = elf->dynamics[i].value >> 48;
			elf->importLibraries[importLibraryIndex].version = (elf->dynamics[i].value >> 32) & 0xffff;
			elf->importLibraries[importLibraryIndex].name = elf->sceStrTab + (elf->dynamics[i].value & 0xffffffff);
			importLibraryIndex++;
			break;

		case orbisElfDynamicTypeSceExportLib:
			elf->exportLibraries[exportLibraryIndex].id = elf->dynamics[i].value >> 48;
			elf->exportLibraries[exportLibraryIndex].version = (elf->dynamics[i].value >> 32) & 0xffff;
			elf->exportLibraries[exportLibraryIndex].name = elf->sceStrTab + (elf->dynamics[i].value & 0xffffffff);
			exportLibraryIndex++;
			break;

		case orbisElfDynamicTypeSceNeededModule:
			elf->importModules[moduleIndex].id = elf->dynamics[i].value >> 48;
			elf->importModules[moduleIndex].version = (elf->dynamics[i].value >> 32) & 0xffff;
			elf->importModules[moduleIndex].name = elf->sceStrTab + (elf->dynamics[i].value & 0xffffffff);
			moduleIndex++;
			break;

		case orbisElfDynamicTypeSceModuleInfo:
			elf->moduleInfo.name = elf->sceStrTab + (elf->dynamics[i].value & 0xffffffff);
			break;

		case orbisElfDynamicTypeSceOriginalFilename:
			printf("orbisElfDynamicTypeSceOriginalFilename value '%s'\n", elf->sceStrTab + (elf->dynamics[i].value & 0xffffffff));
			break;

		default:
			break;
		}
	}

	if (elf->importLibraries || elf->exportLibraries)
	{
		for (uint64_t i = 0; i < elf->dynamicsCount; ++i)
		{
			switch (elf->dynamics[i].type)
			{
			case orbisElfDynamicTypeSceImportLibAttr:
				for (uint64_t libraryIndex = 0; libraryIndex < elf->importLibrariesCount; ++libraryIndex)
				{
					if (elf->importLibraries[libraryIndex].id == (elf->dynamics[i].value >> 32))
					{
						elf->importLibraries[libraryIndex].attr = elf->dynamics[i].value & 0xffffffff;
					}
				}
				break;

			case orbisElfDynamicTypeSceExportLibAttr:
				for (uint64_t libraryIndex = 0; libraryIndex < elf->exportLibrariesCount; ++libraryIndex)
				{
					if (elf->exportLibraries[libraryIndex].id == (elf->dynamics[i].value >> 32))
					{
						elf->exportLibraries[libraryIndex].attr = elf->dynamics[i].value & 0xffffffff;
					}
				}
				break;

			default:
				break;
			}
		}
	}

	return orbisElfErrorCodeOk;
}

static OrbisElfErrorCode_t parseSymbols(OrbisElfHandle_t elf)
{
	if (!elf->sceStrTab || !elf->sceSymTab || !elf->sceStrTabSize || !elf->sceSymTabSize)
	{
		return orbisElfErrorCodeOk;
	}

	if (elf->sceSymTabEntrySize != sizeof(OrbisElfSymbolHeader_t))
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	elf->symbolsCount = elf->sceSymTabSize / elf->sceSymTabEntrySize;

	if (!elf->symbolsCount)
	{
		return orbisElfErrorCodeOk;
	}

	elf->symbols = malloc(sizeof(OrbisElfSymbol_t) * elf->symbolsCount);

	if (!elf->symbols)
	{
		return orbisElfErrorCodeNoMemory;
	}

	memset(elf->symbols, 0, sizeof(OrbisElfSymbol_t) * elf->symbolsCount);

	for (uint32_t i = 0; i < elf->symbolsCount; ++i)
	{
		elf->symbols[i].header = elf->sceSymTab[i];
		elf->symbols[i].bind = elf->symbols[i].header.info >> 4;
		elf->symbols[i].type = elf->symbols[i].header.info & 0xf;

		const char *name = elf->sceStrTab + elf->symbols[i].header.name;

		if (strlen(name) == 15 && name[11] == '#' && name[12] >= 'A' && name[12] <= 'Z' && name[13] == '#' && name[14] >= 'A' && name[14] <= 'Z')
		{
			const OrbisElfModuleInfo_t *module = orbisElfFindModuleById(elf, name[14] - 'A');
			const OrbisElfLibraryInfo_t *library = orbisElfFindLibraryById(elf, name[12] - 'A');

			if (module && library)
			{
				char *allocatedName = malloc(12);
				memcpy(allocatedName, name, 11);
				allocatedName[11] = '\0';

				elf->symbols[i].name = allocatedName;
				elf->symbols[i].module = module;
				elf->symbols[i].library = library;
			}
		}

		if (elf->symbols[i].name == NULL)
		{
			elf->symbols[i].name = name;
		}

		if (elf->symbols[i].header.info == 0 && elf->symbols[i].header.other == 0)
		{
			if (strcmp(elf->symbols[i].name, "module_start") == 0)
			{
				elf->symbols[i].header.value = elf->initAddress;
			}
			else if (strcmp(elf->symbols[i].name, "module_stop") == 0)
			{
				elf->symbols[i].header.value = elf->finiAddress;
			}
		}
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfValidate(const void *image, size_t size, OrbisElfType_t expectedType)
{
	const OrbisElfHeader_t *header = image;

	if (header->magic[0] != 0x7f || header->magic[1] != 'E' || header->magic[2] != 'L' || header->magic[3] != 'F')
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	if (header->eclass != 2 || header->data != 1 || header->version != 1 || header->eversion != 1)
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	if (header->type == orbisElfTypeNone)
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	if (header->phentsize != sizeof(OrbisElfProgramHeader_t) || (header->shentsize && header->shentsize != sizeof(OrbisElfSectionHeader_t)) || header->ehsize != sizeof(OrbisElfHeader_t))
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	if (expectedType != orbisElfTypeNone && header->type != expectedType)
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfParse(const void *image, size_t size, OrbisElfHandle_t *handle)
{
	OrbisElfErrorCode_t errorCode = orbisElfValidate(image, size, orbisElfTypeNone);

	if (errorCode != orbisElfErrorCodeOk)
	{
		return errorCode;
	}

	OrbisElfHandle_t elf = malloc(sizeof(OrbisElf_t));

	if (!elf)
	{
		return orbisElfErrorCodeNoMemory;
	}

	memset(elf, 0, sizeof(OrbisElf_t));
	elf->image = image;
	elf->header = *(const OrbisElfHeader_t *)image;

	int isOk = 1;
	isOk = isOk && (errorCode = parsePrograms(elf)) == orbisElfErrorCodeOk;
	isOk = isOk && (errorCode = parseSections(elf)) == orbisElfErrorCodeOk;
	isOk = isOk && (errorCode = parseDynamicProgram(elf)) == orbisElfErrorCodeOk;
	isOk = isOk && (errorCode = parseSymbols(elf)) == orbisElfErrorCodeOk;

	if (!isOk)
	{
		orbisElfDestroy(elf);
		return errorCode;
	}

	*handle = elf;
	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfLoad(OrbisElfHandle_t elf, void *address)
{
	elf->baseAddress = (uint64_t)address;

	for (uint16_t i = 0; i < elf->programsCount; ++i)
	{
		if (elf->programs[i].header.type == orbisElfProgramTypeLoad)
		{
			memcpy((char *)address + elf->programs[i].header.vaddr, (const char *)elf->image + elf->programs[i].header.offset, elf->programs[i].header.filesz);
		}
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfImportModule(OrbisElfHandle_t elf, OrbisElfHandle_t importElf)
{
	for (uint64_t importSymbolIndex = 0; importSymbolIndex < elf->symbolsCount; ++importSymbolIndex)
	{
		if (!elf->symbols[importSymbolIndex].module || !elf->symbols[importSymbolIndex].library)
		{
			continue;
		}

		if (strcmp(elf->symbols[importSymbolIndex].module->name, importElf->moduleInfo.name) != 0)
		{
			continue;
		}

		for (uint64_t exportSymbolIndex = 0; exportSymbolIndex < importElf->symbolsCount; ++exportSymbolIndex)
		{
			if (!importElf->symbols[exportSymbolIndex].library || !importElf->symbols[exportSymbolIndex].header.value)
			{
				continue;
			}

			if (elf->symbols[importSymbolIndex].type != importElf->symbols[exportSymbolIndex].type)
			{
				continue;
			}

			if (strcmp(elf->symbols[importSymbolIndex].library->name, importElf->symbols[exportSymbolIndex].library->name) != 0)
			{
				continue;
			}

			if (strcmp(elf->symbols[importSymbolIndex].name, importElf->symbols[exportSymbolIndex].name) != 0)
			{
				continue;
			}

			elf->symbols[importSymbolIndex].header.value = importElf->symbols[exportSymbolIndex].header.value;
			elf->symbols[importSymbolIndex].baseAddress = importElf->baseAddress;
			break;
		}
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfImportSymbol(OrbisElfHandle_t elf, const char *moduleName, const char *libraryName, const char *symbolName, uint64_t value)
{
	for (uint64_t importSymbolIndex = 0; importSymbolIndex < elf->symbolsCount; ++importSymbolIndex)
	{
		if (!elf->symbols[importSymbolIndex].module || !elf->symbols[importSymbolIndex].library)
		{
			continue;
		}

		if (strcmp(elf->symbols[importSymbolIndex].module->name, moduleName) != 0)
		{
			continue;
		}

		if (strcmp(elf->symbols[importSymbolIndex].library->name, libraryName) != 0)
		{
			continue;
		}

		if (strcmp(elf->symbols[importSymbolIndex].name, symbolName) != 0)
		{
			continue;
		}

		elf->symbols[importSymbolIndex].header.value = value - 0x10;
		elf->symbols[importSymbolIndex].baseAddress = 0x10;
		return orbisElfErrorCodeOk;
	}

	return orbisElfErrorCodeNotFound;
}

OrbisElfErrorCode_t orbisElfRelocate(OrbisElfHandle_t elf)
{
	if (elf->scePltRelSize)
	{
		switch (elf->scePltRelType)
		{
		case orbisElfDynamicTypeRela:
			for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRelocationWithAddend_t); i < count; ++i)
			{
				const OrbisElfRelocationWithAddend_t *rela = ((OrbisElfRelocationWithAddend_t *)elf->sceJmpRel) + i;

				if ((rela->info & 0xffffffff) != R_X86_64_JUMP_SLOT)
				{
					assert(0);
					continue;
				}

				const OrbisElfSymbol_t *sym = elf->symbols + (rela->info >> 32);

				if (!sym->header.value)
				{
					if (sym->module && sym->library)
					{
						printf("%s: Unresolved symbol '%s::%s::%s'\n", elf->moduleInfo.name, sym->module->name, sym->library->name, sym->name);
					}
					else
					{
						printf("%s: Unresolved symbol '%s'\n", elf->moduleInfo.name, sym->name);
					}

					*(uint64_t *)(elf->baseAddress + rela->offset) = 0xDEADBEEFBADCAFE1;
				}
				else
				{

					uint64_t symbolBaseAddress = sym->baseAddress ? sym->baseAddress : elf->baseAddress;

					*(uint64_t *)(elf->baseAddress + rela->offset) += sym->baseAddress + sym->header.value + rela->addend;
				}
			}
			break;

		case orbisElfDynamicTypeRel:
			for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRelocation_t); i < count; ++i)
			{
				const OrbisElfRelocation_t *rel = ((OrbisElfRelocation_t *)elf->sceJmpRel) + i;

				if ((rel->info & 0xffffffff) != R_X86_64_JUMP_SLOT)
				{
					assert(0);
					continue;
				}

				const OrbisElfSymbol_t *sym = elf->symbols + (rel->info >> 32);

				if (!sym->header.value)
				{
					if (sym->module && sym->library)
					{
						printf("%s: Unresolved symbol '%s::%s::%s'\n", elf->moduleInfo.name, sym->module->name, sym->library->name, sym->name);
					}
					else
					{
						printf("%s: Unresolved symbol '%s'\n", elf->moduleInfo.name, sym->name);
					}
				}

				uint64_t symbolBaseAddress = sym->baseAddress ? sym->baseAddress : elf->baseAddress;

				*(uint64_t *)(elf->baseAddress + rel->offset) += sym->baseAddress + sym->header.value;
			}
			break;

		default:
			assert(0);
		}
	}

	for (uint64_t i = 0, count = elf->sceRelaSize / elf->sceRelaEntSize; i < count; ++i)
	{
		OrbisElfRelocationWithAddend_t rela = elf->sceRela[i];
		uint64_t *where = (uint64_t *)(elf->baseAddress + rela.offset);
		uint32_t *where32 = (uint32_t *)where;
		uint32_t relaType = rela.info & 0xffffffff;

		const OrbisElfSymbol_t *sym = elf->symbols + (rela.info >> 32);
		uint64_t symVal = 0;

		switch (relaType)
		{
		case R_X86_64_64:
		case R_X86_64_PC32:
		case R_X86_64_GLOB_DAT:
			if (!sym->header.value)
			{
				if (sym->module && sym->library)
				{
					printf("%s: Unresolved symbol '%s::%s::%s' rel %u\n", elf->moduleInfo.name, sym->module->name, sym->library->name, sym->name, relaType);
				}
				else
				{
					printf("%s: Unresolved symbol '%s' rel %u\n", elf->moduleInfo.name, sym->name, relaType);
				}
			}
			else
			{
				symVal = (sym->baseAddress ? sym->baseAddress : elf->baseAddress) + sym->header.value;
			}
			break;
		}

		switch (relaType)
		{
		case R_X86_64_NONE:
			break;

		case R_X86_64_64:
			*where = symVal + rela.addend;
			break;

		case R_X86_64_PC32:
			*where32 = (uint32_t)(symVal + rela.addend - (uint64_t)where);
			break;

		case R_X86_64_COPY:
			fprintf(stderr, "%s: Unexpected R_X86_64_COPY relocation in shared library\n", elf->moduleInfo.name);
			break;

		case R_X86_64_GLOB_DAT:
			*where = symVal;
			break;

		case R_X86_64_TPOFF64:
			*where += sym->header.value - elf->tlsOffset + rela.addend;
			fprintf(stderr, "%s: TLS relocation\n", elf->moduleInfo.name);
			break;

		case R_X86_64_TPOFF32:
			*where32 += (uint32_t)(sym->header.value - elf->tlsOffset + rela.addend);
			fprintf(stderr, "%s: TLS32 relocation\n", elf->moduleInfo.name);
			break;

		case R_X86_64_DTPMOD64:
			*where += elf->tlsIndex;
			break;

		case R_X86_64_DTPOFF64:
			*where += sym->header.value + rela.addend;
			break;

		case R_X86_64_DTPOFF32:
			*where32 += (uint32_t)(sym->header.value + rela.addend);
			break;

		case R_X86_64_RELATIVE:
			*where = elf->baseAddress + rela.addend;
			break;

		default:
			fprintf(stderr, "Unsupported relocation type %u in non-PLT relocations\n", relaType);
			break;
		}
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfInitializeTls(OrbisElfHandle_t elf, void *tls)
{
	memcpy(tls, (void *)(elf->baseAddress + elf->tlsInitAddress), elf->tlsInitSize);
	memset((char *)tls + elf->tlsInitSize, 0, elf->tlsSize - elf->tlsInitSize);

	return orbisElfErrorCodeOk;
}

void orbisElfDestroy(OrbisElfHandle_t elf)
{
	free(elf->programs);
	free(elf->sections);
	free(elf->importModules);
	free(elf->importLibraries);
	free(elf->exportLibraries);

	for (uint64_t i = 0; i < elf->symbolsCount; ++i)
	{
		if (elf->symbols[i].library || elf->symbols[i].module)
		{
			free((void *)elf->symbols[i].name);
		}
	}

	free(elf->symbols);
	free(elf);
}

const OrbisElfHeader_t *orbisElfGetHeader(OrbisElfHandle_t elf)
{
	return &elf->header;
}

OrbisElfType_t orbisElfGetType(OrbisElfHandle_t elf)
{
	return elf->header.type;
}

const OrbisElfModuleInfo_t *orbisElfGetModuleInfo(OrbisElfHandle_t elf)
{
	return &elf->moduleInfo;
}

uint64_t orbisElfGetGotPltAddress(OrbisElfHandle_t elf)
{
	return elf->pltGotAddress;
}

uint64_t orbisElfGetTlsSize(OrbisElfHandle_t elf)
{
	return elf->tlsSize;
}

uint64_t orbisElfGetTlsAlign(OrbisElfHandle_t elf)
{
	return elf->tlsAlign;
}

uint64_t orbisElfGetTlsIndex(OrbisElfHandle_t elf)
{
	return elf->tlsIndex;
}

void orbisElfSetTlsIndex(OrbisElfHandle_t elf, uint64_t index)
{
	elf->tlsIndex = index;
}

uint64_t orbisElfGetTlsOffset(OrbisElfHandle_t elf)
{
	return elf->tlsOffset;
}

void orbisElfSetTlsOffset(OrbisElfHandle_t elf, uint64_t offset)
{
	elf->tlsOffset = offset;
}

uint64_t orbisElfGetLoadSize(OrbisElfHandle_t elf)
{
	return elf->loadSize;
}

const char *orbisElfGetSoName(OrbisElfHandle_t elf)
{
	return elf->soName;
}

uint64_t orbisElfGetEntryPoint(OrbisElfHandle_t elf)
{
	return elf->baseAddress + elf->header.entry;
}

uint16_t orbisElfGetProgramsCount(OrbisElfHandle_t elf)
{
	return elf->programsCount;
}

uint16_t orbisElfGetSectionsCount(OrbisElfHandle_t elf)
{
	return elf->sectionsCount;
}

uint64_t orbisElfGetImportModulesCount(OrbisElfHandle_t elf)
{
	return elf->importModulesCount;
}

uint64_t orbisElfGetImportLibrariesCount(OrbisElfHandle_t elf)
{
	return elf->importLibrariesCount;
}

uint64_t orbisElfGetExportLibrariesCount(OrbisElfHandle_t elf)
{
	return elf->exportLibrariesCount;
}

uint64_t orbisElfGetSymbolsCount(OrbisElfHandle_t elf)
{
	return elf->symbolsCount;
}

OrbisElfProgramHandle_t orbisElfGetProgram(OrbisElfHandle_t elf, uint16_t index)
{
	if (index >= elf->programsCount)
	{
		return NULL;
	}

	return elf->programs + index;
}

OrbisElfSectionHandle_t orbisElfGetSection(OrbisElfHandle_t elf, uint16_t index)
{
	if (index >= elf->sectionsCount)
	{
		return NULL;
	}

	return elf->sections + index;
}

const OrbisElfModuleInfo_t *orbisElfGetImportModuleInfo(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->importModulesCount)
	{
		return NULL;
	}

	return elf->importModules + index;
}

const OrbisElfLibraryInfo_t *orbisElfGetImportLibraryInfo(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->importLibrariesCount)
	{
		return NULL;
	}

	return elf->importLibraries + index;
}

const OrbisElfLibraryInfo_t *orbisElfGetExportLibraryInfo(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->exportLibrariesCount)
	{
		return NULL;
	}

	return elf->exportLibraries + index;
}

const OrbisElfSymbol_t *orbisElfGetSymbol(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->symbolsCount)
	{
		return NULL;
	}

	return elf->symbols + index;
}

OrbisElfSectionHandle_t orbisElfFindSectionByName(OrbisElfHandle_t elf, const char *name)
{
	for (uint16_t i = 0; i < elf->sectionsCount; ++i)
	{
		if (strcmp(elf->sections[i].name, name) == 0)
		{
			return elf->sections + i;
		}
	}

	return NULL;
}

const OrbisElfModuleInfo_t *orbisElfFindModuleById(OrbisElfHandle_t elf, uint16_t id)
{
	if (elf->moduleInfo.id == id)
	{
		return &elf->moduleInfo;
	}

	for (uint64_t i = 0; i < elf->importModulesCount; ++i)
	{
		if (elf->importModules[i].id == id)
		{
			return elf->importModules + i;
		}
	}

	return NULL;
}

const OrbisElfLibraryInfo_t *orbisElfFindLibraryById(OrbisElfHandle_t elf, uint16_t id)
{
	for (uint64_t i = 0; i < elf->importLibrariesCount; ++i)
	{
		if (elf->importLibraries[i].id == id)
		{
			return elf->importLibraries + i;
		}
	}

	for (uint64_t i = 0; i < elf->exportLibrariesCount; ++i)
	{
		if (elf->exportLibraries[i].id == id)
		{
			return elf->exportLibraries + i;
		}
	}

	return NULL;
}

const OrbisElfProgramHeader_t *orbisElfProgramGetHeader(OrbisElfProgramHandle_t program)
{
	return program ? &program->header : NULL;
}

const void *orbisElfProgramGetData(OrbisElfProgramHandle_t program, uint64_t *size)
{
	if (size)
	{
		*size = program->header.filesz;
	}

	return program->data;
}

OrbisElfSectionHeader_t *orbisElfSectionGetHeader(OrbisElfSectionHandle_t section)
{
	return section ? &section->header : NULL;
}

const void *orbisElfSectionGetData(OrbisElfSectionHandle_t section, uint64_t *size)
{
	if (size)
	{
		*size = section->header.size;
	}

	return section->data;
}

const char *orbisElfSectionGetName(OrbisElfSectionHandle_t section)
{
	return section->name;
}

