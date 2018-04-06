#include "orbis-elf-enums.h"
#include "orbis-elf-types.h"
#include "orbis-elf-api.h"

#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

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

	uint64_t sceProcParam;
	uint64_t sceProcParamSize;

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

	uint64_t preinitArrayAddress;
	uint64_t preinitArrayCount;

	uint64_t initArrayAddress;
	uint64_t initArrayCount;

	struct OrbisElfRebase_s *rebases;
	uint64_t rebasesCount;

	struct OrbisElfImport_s *imports;
	uint64_t importsCount;

	OrbisElfModuleInfo_t moduleInfo;
	uint64_t virtualBaseAddress;
	void *baseAddress;
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
		case orbisElfProgramTypeSceRelRo:
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
			elf->sceProcParam = elf->programs[i].header.vaddr;
			elf->sceProcParamSize = elf->programs[i].header.filesz;
			break;

		case orbisElfProgramTypeTls:
			elf->tlsOffset = elf->programs[i].header.offset;
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
			if (elf->sceDynlibData)
			{
				elf->sceSymTab = (const OrbisElfSymbolHeader_t *)(elf->sceDynlibData + elf->dynamics[i].value);
			}
			break;

		case orbisElfDynamicTypeSceSymEnt:
			elf->sceSymTabEntrySize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceSymTabSize:
			elf->sceSymTabSize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceStrTab:
			if (elf->sceDynlibData)
			{
				elf->sceStrTab = (const char *)(elf->sceDynlibData + elf->dynamics[i].value);
			}
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
			if (elf->sceDynlibData)
			{
				elf->sceJmpRel = (const void *)(elf->sceDynlibData + elf->dynamics[i].value);
			}
			break;

		case orbisElfDynamicTypeScePltRel:
			elf->scePltRelType = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeScePltRelSize:
			elf->scePltRelSize = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeSceRela:
			if (elf->sceDynlibData)
			{
				elf->sceRela = (const OrbisElfRelocationWithAddend_t *)(elf->sceDynlibData + elf->dynamics[i].value);
			}
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
			elf->initArrayAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeFiniArray:
			//TODO
			break;

		case orbisElfDynamicTypeInitArraySize:
			elf->initArrayCount = elf->dynamics[i].value / 8;
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
			printf("orbisElfDynamicTypePreinitArray with value 0x%I64x\n", elf->dynamics[i].value);
			elf->preinitArrayAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypePreinitArraySize:
			elf->preinitArrayCount = elf->dynamics[i].value / 8;
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
	}

	return orbisElfErrorCodeOk;
}

static OrbisElfErrorCode_t parseRelocations(OrbisElfHandle_t elf)
{
	int rebaseCount = 0;
	int importsCount = 0;

	for (uint64_t i = 0, count = elf->sceRelaSize / elf->sceRelaEntSize; i < count; ++i)
	{
		uint32_t symbolIndex = elf->sceRela[i].info >> 32;
		uint32_t relType = elf->sceRela[i].info & 0xffffffff;

		if (relType == orbisElfRelocationTypeNone)
		{
			continue;
		}

		const OrbisElfSymbol_t *sym = elf->symbols + symbolIndex;

		if (relType == orbisElfRelocationTypeRelative)
		{
			++rebaseCount;
		}
		else
		{
			++importsCount;
		}
	}

	switch (elf->scePltRelType)
	{
	case orbisElfDynamicTypeRela:
	{
		const OrbisElfRelocationWithAddend_t *rela = (OrbisElfRelocationWithAddend_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRelocationWithAddend_t); i < count; ++i)
		{
			if ((rela[i].info & 0xffffffff) != orbisElfRelocationTypeJumpSlot)
			{
				assert(0);
				continue;
			}

			const OrbisElfSymbol_t *sym = elf->symbols + (rela[i].info >> 32);

			if (!sym->header.value)
			{
				++importsCount;
			}
			else
			{
				++rebaseCount;
			}
		}
		break;
	}

	case orbisElfDynamicTypeRel:
	{
		const OrbisElfRelocation_t *rel = (OrbisElfRelocation_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRelocation_t); i < count; ++i)
		{
			if ((rel[i].info & 0xffffffff) != orbisElfRelocationTypeJumpSlot)
			{
				assert(0);
				continue;
			}

			const OrbisElfSymbol_t *sym = elf->symbols + (rel[i].info >> 32);

			if (!sym->header.value)
			{
				++importsCount;
			}
			else
			{
				++rebaseCount;
			}
		}

		elf->rebasesCount = rebaseCount;
		elf->rebases = malloc(sizeof(OrbisElfRebase_t) * elf->rebasesCount);

		elf->importsCount = importsCount;
		elf->imports = malloc(sizeof(OrbisElfImport_t) * elf->importsCount);

		OrbisElfRebase_t *rebaseIt = elf->rebases;
		OrbisElfImport_t *importIt = elf->imports;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRelocation_t); i < count; ++i)
		{
			uint32_t symbolIndex = rel[i].info >> 32;
			const OrbisElfSymbol_t *sym = elf->symbols + symbolIndex;

			if (!sym->header.value)
			{
				importIt->offset = rel[i].offset;
				importIt->symbolIndex = symbolIndex;
				importIt->relType = rel[i].info & 0xffffffff;
				importIt->addend = 0;

				++importIt;
			}
			else
			{
				rebaseIt->offset = rel[i].offset;
				rebaseIt->value = sym->header.value;
				rebaseIt->symbolIndex = symbolIndex;

				++rebaseIt;
			}
		}
		break;
	}

	default:
		assert(0);
	}

	elf->rebasesCount = rebaseCount;
	elf->rebases = malloc(sizeof(OrbisElfRebase_t) * elf->rebasesCount);

	elf->importsCount = importsCount;
	elf->imports = malloc(sizeof(OrbisElfImport_t) * elf->importsCount);

	OrbisElfRebase_t *rebaseIt = elf->rebases;
	OrbisElfImport_t *importIt = elf->imports;

	for (uint64_t i = 0, count = elf->sceRelaSize / elf->sceRelaEntSize; i < count; ++i)
	{
		uint32_t symbolIndex = elf->sceRela[i].info >> 32;
		uint32_t relType = elf->sceRela[i].info & 0xffffffff;

		if (relType == orbisElfRelocationTypeNone)
		{
			continue;
		}

		const OrbisElfSymbol_t *sym = elf->symbols + symbolIndex;

		if (relType == orbisElfRelocationTypeRelative)
		{
			rebaseIt->offset = elf->sceRela[i].offset;
			rebaseIt->value = elf->sceRela[i].addend;
			rebaseIt->symbolIndex = symbolIndex;

			++rebaseIt;
		}
		else
		{
			importIt->offset = elf->sceRela[i].offset;
			importIt->symbolIndex = symbolIndex;
			importIt->relType = relType;
			importIt->addend = elf->sceRela[i].addend;

			++importIt;
		}
	}

	switch (elf->scePltRelType)
	{
	case orbisElfDynamicTypeRela:
	{
		const OrbisElfRelocationWithAddend_t *rela = (OrbisElfRelocationWithAddend_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRelocationWithAddend_t); i < count; ++i)
		{
			uint32_t symbolIndex = rela[i].info >> 32;
			const OrbisElfSymbol_t *sym = elf->symbols + symbolIndex;

			if (!sym->header.value)
			{
				importIt->offset = rela[i].offset;
				importIt->symbolIndex = symbolIndex;
				importIt->relType = rela[i].info & 0xffffffff;
				importIt->addend = rela[i].addend;

				++importIt;
			}
			else
			{
				rebaseIt->offset = rela[i].offset;
				rebaseIt->value = sym->header.value + rela[i].addend;
				rebaseIt->symbolIndex = symbolIndex;

				++rebaseIt;
			}
		}
		break;
	}

	case orbisElfDynamicTypeRel:
	{
		const OrbisElfRelocation_t *rel = (OrbisElfRelocation_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRelocation_t); i < count; ++i)
		{
			uint32_t symbolIndex = rel[i].info >> 32;
			const OrbisElfSymbol_t *sym = elf->symbols + symbolIndex;

			if (!sym->header.value)
			{
				importIt->offset = rel[i].offset;
				importIt->symbolIndex = symbolIndex;
				importIt->relType = rel[i].info & 0xffffffff;
				importIt->addend = 0;

				++importIt;
			}
			else
			{
				rebaseIt->offset = rel[i].offset;
				rebaseIt->value = sym->header.value;
				rebaseIt->symbolIndex = symbolIndex;

				++rebaseIt;
			}
		}
		break;
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
	isOk = isOk && (errorCode = parseRelocations(elf)) == orbisElfErrorCodeOk;

	if (!isOk)
	{
		orbisElfDestroy(elf);
		return errorCode;
	}

	*handle = elf;
	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfLoad(OrbisElfHandle_t elf, void *baseAddress, uint64_t virtualBaseAddress)
{
	elf->virtualBaseAddress = virtualBaseAddress ? virtualBaseAddress : (uint64_t)baseAddress;
	elf->baseAddress = baseAddress;

	for (uint64_t i = 0; i < elf->symbolsCount; ++i)
	{
		elf->symbols[i].baseAddress = elf->baseAddress;
		elf->symbols[i].virtualBaseAddress = elf->virtualBaseAddress;
	}

	for (uint16_t i = 0; i < elf->programsCount; ++i)
	{
		if (elf->programs[i].header.type == orbisElfProgramTypeLoad || elf->programs[i].header.type == orbisElfProgramTypeSceRelRo)
		{
			memcpy((char *)baseAddress + elf->programs[i].header.vaddr, (const char *)elf->image + elf->programs[i].header.offset, elf->programs[i].header.filesz);
		}
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfInitializeTls(OrbisElfHandle_t elf, void *tls)
{
	memcpy(tls, (void *)((char *)elf->baseAddress + elf->tlsInitAddress), elf->tlsInitSize);
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
	free(elf->imports);
	free(elf->rebases);
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

uint64_t orbisElfGetTlsInitAddress(OrbisElfHandle_t elf)
{
	return elf->tlsInitAddress;
}

uint64_t orbisElfGetTlsInitSize(OrbisElfHandle_t elf)
{
	return elf->tlsInitSize;
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

uint64_t orbisElfGetSceProcParam(OrbisElfHandle_t elf, uint64_t *size)
{
	if (size)
	{
		*size = elf->sceProcParam ? elf->sceProcParamSize : 0;
	}

	return elf->sceProcParam ? orbisElfGetVirtualBaseAddress(elf) + elf->sceProcParam : 0;
}

uint64_t orbisElfGetEntryPoint(OrbisElfHandle_t elf)
{
	return elf->header.entry;
}

uint64_t orbisElfGetVirtualBaseAddress(OrbisElfHandle_t elf)
{
	return elf->virtualBaseAddress;
}

void *orbisElfGetBaseAddress(OrbisElfHandle_t elf)
{
	return elf->baseAddress;
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

uint64_t orbisElfGetInitAddress(OrbisElfHandle_t elf)
{
	return elf->initAddress;
}

uint64_t orbisElfGetPreinitArray(OrbisElfHandle_t elf, uint64_t *count)
{
	if (count)
	{
		*count = elf->preinitArrayCount;
	}

	return elf->preinitArrayAddress;
}

uint64_t orbisElfGetInitArray(OrbisElfHandle_t elf, uint64_t *count)
{
	if (count)
	{
		*count = elf->initArrayCount;
	}

	return elf->initArrayAddress;
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

const OrbisElfSymbol_t *orbisElfFindSymbolByName(OrbisElfHandle_t elf, const char *name)
{
	for (uint16_t i = 0; i < elf->symbolsCount; ++i)
	{
		if (strcmp(elf->symbols[i].name, name) == 0)
		{
			return elf->symbols + i;
		}
	}

	return NULL;
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

uint64_t orbisElfGetRebasesCount(OrbisElfHandle_t elf)
{
	return elf->rebasesCount;
}

OrbisElfRebase_t *orbisElfGetRebase(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->rebasesCount)
	{
		return NULL;
	}

	return elf->rebases + index;
}

uint64_t orbisElfGetImportsCount(OrbisElfHandle_t elf)
{
	return elf->importsCount;
}

OrbisElfImport_t *orbisElfGetImport(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->importsCount)
	{
		return NULL;
	}

	return elf->imports + index;
}

uint8_t orbisElfGetImportAddressSize(OrbisElfImport_t *import)
{
	switch (import->relType)
	{
	case orbisElfRelocationTypePc32:
	case orbisElfRelocationTypeTpOff32:
	case orbisElfRelocationTypeDtpOff32:
		return 4;
	
	default:
		return 8;
	}
}

uint64_t orbisElfGetImportValue(OrbisElfImport_t *import, OrbisElfHandle_t elf)
{
	const OrbisElfSymbol_t *sym = elf->symbols + import->symbolIndex;

	switch (import->relType)
	{
	case orbisElfRelocationType64:
		return sym->header.value + import->addend;

	case orbisElfRelocationTypePc32:
		return (uint32_t)(sym->header.value + import->addend - (elf->virtualBaseAddress + import->offset));

	case orbisElfRelocationTypeCopy:
		fprintf(stderr, "%s: Unexpected R_X86_64_COPY relocation in shared library\n", elf->moduleInfo.name);
		return 0;

	case orbisElfRelocationTypeGlobDat:
		return sym->header.value;

	case orbisElfRelocationTypeDtpMod64:
		return elf->tlsIndex;

	case orbisElfRelocationTypeDtpOff64:
		return sym->header.value + import->addend;

	case orbisElfRelocationTypeTpOff64:
		return sym->header.value - elf->tlsOffset + import->addend;

	case orbisElfRelocationTypeDtpOff32:
		return (uint32_t)(sym->header.value + import->addend);

	case orbisElfRelocationTypeTpOff32:
		return (uint32_t)(sym->header.value - elf->tlsOffset + import->addend);

	default:
		fprintf(stderr, "%s: Unsupported relocation type %u in non-PLT relocations\n", elf->moduleInfo.name, import->relType);
		return 0;
	}
}

OrbisElfImportInjectType_t orbisElfGetImportInjectType(OrbisElfImport_t *import)
{
	switch (import->relType)
	{
	case orbisElfRelocationTypeDtpMod64:
	case orbisElfRelocationTypeDtpOff64:
	case orbisElfRelocationTypeTpOff64:
	case orbisElfRelocationTypeDtpOff32:
	case orbisElfRelocationTypeTpOff32:
		return orbisElfImportInjectTypeAdd;

	default:
		return orbisElfImportInjectTypeSet;
	}
}
