#include "orbis-elf-types.h"
#include "orbis-elf-enums.h"
#include "orbis-elf-api.h"

#include <malloc.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

typedef struct OrbisElf_s
{
	OrbisElfReadCallback_t read;
	void *readUserData;
	size_t imageSize;
	
	OrbisElfHeader_t header;

	OrbisElfProgramHeader_t *programs;
	uint16_t programsCount;

	OrbisElfSectionHeader_t *sections;
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
	uint64_t tlsSize;
	uint64_t tlsAlign;
	uint64_t tlsInitSize;
	uint64_t tlsInitAddress;

	uint64_t loadSize;

	OrbisElfDynamicType_t scePltRelType;
	uint64_t scePltRelSize;
	const void *sceJmpRel;

	const OrbisElfRela_t *sceRela;
	uint64_t sceRelaSize;
	uint64_t sceRelaEntSize;

	uint64_t initAddress;
	uint64_t finiAddress;

	uint64_t preinitArrayAddress;
	uint64_t preinitArrayCount;

	uint64_t initArrayAddress;
	uint64_t initArrayCount;

	uint64_t finiArrayAddress;
	uint64_t finiArrayCount;

	const char **needed;
	uint64_t neededCount;

	const char *originalFileName;

	OrbisElfRebaseRelocation_t *rebaseRelocations;
	uint64_t rebaseRelocationsCount;

	OrbisElfRelocation_t *importRelocations;
	uint64_t importRelocationsCount;

	OrbisElfRelocation_t *tlsRelocations;
	uint64_t tlsRelocationsCount;

	OrbisElfModuleInfo_t moduleInfo;
	uint64_t virtualBaseAddress;

	void *baseAddress;
} OrbisElf_t;

static OrbisElfErrorCode_t parsePrograms(OrbisElfHandle_t elf)
{
	if (elf->header.phentsize != sizeof(OrbisElfProgramHeader_t))
	{
		return orbisElfErrorCodeCorruptedImage;
	}
	
	elf->programs = malloc(elf->header.phentsize * elf->header.phnum);

	if (!elf->programs)
	{
		return orbisElfErrorCodeNoMemory;
	}

	elf->programsCount = elf->header.phnum;
	
	if (orbisElfRead(elf, elf->header.phoff, elf->programs, elf->header.phnum * elf->header.phentsize) != elf->header.phnum * elf->header.phentsize)
	{
		return orbisElfErrorCodeIoError;
	}
	
	OrbisElfErrorCode_t error = orbisElfErrorCodeOk;

	for (uint16_t i = 0; i < elf->programsCount; ++i)
	{
		switch (elf->programs[i].type)
		{
		case orbisElfProgramTypeLoad:
		case orbisElfProgramTypeSceRelRo:
			if (elf->programs[i].vaddr + elf->programs[i].memsz > elf->loadSize)
			{
				elf->loadSize = elf->programs[i].vaddr + elf->programs[i].memsz;
			}
			break;

		case orbisElfProgramTypeDynamic:
			if (elf->programs[i].filesz)
			{
				void *allocatedData = malloc(elf->programs[i].filesz);
				elf->dynamics = allocatedData;
				
				if (orbisElfRead(elf, elf->programs[i].offset, allocatedData, elf->programs[i].filesz) != elf->programs[i].filesz)
				{
					error = orbisElfErrorCodeIoError;
				}
				else
				{
					elf->dynamicsCount = elf->programs[i].filesz / sizeof(OrbisElfDynamic_t);
				}
			}
			break;

		case orbisElfProgramTypeSceDynlibData:
			if (elf->programs[i].filesz)
			{
				void *allocatedData = malloc(elf->programs[i].filesz);
				elf->sceDynlibData = allocatedData;
				
				if (orbisElfRead(elf, elf->programs[i].offset, allocatedData, elf->programs[i].filesz) != elf->programs[i].filesz)
				{
					error = orbisElfErrorCodeIoError;
				}
				else
				{
					elf->sceDynlibDataSize = elf->programs[i].filesz;
				}
			}
			break;

		case orbisElfProgramTypeSceProcParam:
			elf->sceProcParam = elf->programs[i].vaddr;
			elf->sceProcParamSize = elf->programs[i].filesz;
			break;

		case orbisElfProgramTypeTls:
			elf->tlsSize = elf->programs[i].memsz;
			elf->tlsAlign = elf->programs[i].align;
			elf->tlsInitSize = elf->programs[i].filesz;
			elf->tlsInitAddress = elf->programs[i].vaddr;
			break;
		}
	}

	return orbisElfErrorCodeOk;
}

static OrbisElfErrorCode_t parseSections(OrbisElfHandle_t elf)
{
	/*
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
	*/
	return orbisElfErrorCodeOk;
}

static OrbisElfErrorCode_t parseDynamicProgram(OrbisElfHandle_t elf)
{
	if (!elf->dynamics/* || !elf->sceDynlibData */)
	{
		return orbisElfErrorCodeOk;
	}

	elf->sceSymTabEntrySize = sizeof(OrbisElfSymbolHeader_t);
	elf->sceRelaEntSize = sizeof(OrbisElfRela_t);

	int neededCount = 0;

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
				elf->sceRela = (const OrbisElfRela_t *)(elf->sceDynlibData + elf->dynamics[i].value);
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
			neededCount++;
			break;

		case orbisElfDynamicTypeInitArray:
			elf->initArrayAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeFiniArray:
			elf->finiArrayAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypeInitArraySize:
			elf->initArrayCount = elf->dynamics[i].value / 8;
			break;

		case orbisElfDynamicTypeFiniArraySize:
			elf->finiArrayCount = elf->dynamics[i].value / 8;
			break;

		case orbisElfDynamicTypeFlags:
			//TODO
			break;

		case orbisElfDynamicTypePreinitArray:
			elf->preinitArrayAddress = elf->dynamics[i].value;
			break;

		case orbisElfDynamicTypePreinitArraySize:
			elf->preinitArrayCount = elf->dynamics[i].value / 8;
			break;

		case orbisElfDynamicTypeDebug:
			//TODO

			if (elf->dynamics[i].value)
			{
				printf("orbisElfDynamicTypeDebug with value %lu\n", elf->dynamics[i].value);
			}
			break;

		case orbisElfDynamicTypeTextRel:
			//TODO

			if (elf->dynamics[i].value)
			{
				printf("orbisElfDynamicTypeDebug with value %lu\n", elf->dynamics[i].value);
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
			printf("Unhandled dynamic type 0x%lx\n", elf->dynamics[i].type);
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

	if (neededCount)
	{
		elf->needed = malloc(sizeof(char *) * neededCount);

		if (!elf->needed)
		{
			return orbisElfErrorCodeNoMemory;
		}

		elf->neededCount = neededCount;
	}

	for (uint64_t i = 0, moduleIndex = 0, importLibraryIndex = 0, exportLibraryIndex = 0, neededIndex = 0; i < elf->dynamicsCount; ++i)
	{
		const char *name = elf->sceStrTab + (elf->dynamics[i].value & 0xffffffff);

		switch (elf->dynamics[i].type)
		{
		case orbisElfDynamicTypeSoName:
			elf->soName = name;
			break;

		case orbisElfDynamicTypeSceImportLib:
			elf->importLibraries[importLibraryIndex].id = elf->dynamics[i].value >> 48;
			elf->importLibraries[importLibraryIndex].version = (elf->dynamics[i].value >> 32) & 0xffff;
			elf->importLibraries[importLibraryIndex].name = name;
			importLibraryIndex++;
			break;

		case orbisElfDynamicTypeSceExportLib:
			elf->exportLibraries[exportLibraryIndex].id = elf->dynamics[i].value >> 48;
			elf->exportLibraries[exportLibraryIndex].version = (elf->dynamics[i].value >> 32) & 0xffff;
			elf->exportLibraries[exportLibraryIndex].name = name;
			exportLibraryIndex++;
			break;

		case orbisElfDynamicTypeSceNeededModule:
			elf->importModules[moduleIndex].id = elf->dynamics[i].value >> 48;
			elf->importModules[moduleIndex].version = (elf->dynamics[i].value >> 32) & 0xffff;
			elf->importModules[moduleIndex].name = elf->sceStrTab + (elf->dynamics[i].value & 0xffffffff);
			moduleIndex++;
			break;

		case orbisElfDynamicTypeSceModuleInfo:
			elf->moduleInfo.name = name;
			break;

		case orbisElfDynamicTypeSceOriginalFilename:
			elf->originalFileName = name;
			break;

		case orbisElfDynamicTypeNeeded:
			elf->needed[neededIndex++] = name;
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
	int tlsCount = 0;

	for (uint64_t i = 0, count = elf->sceRelaSize / elf->sceRelaEntSize; i < count; ++i)
	{
		uint32_t symbolIndex = elf->sceRela[i].info >> 32;
		uint32_t relType = elf->sceRela[i].info & 0xffffffff;

		if (relType == orbisElfRelocationTypeNone)
		{
			continue;
		}

		switch (relType)
		{
		case orbisElfRelocationTypeRelative:
			assert(elf->sceRela[i].addend);
			++rebaseCount;
			break;

		case orbisElfRelocationTypeDtpMod64:
		case orbisElfRelocationTypeTpOff64:
		case orbisElfRelocationTypeTpOff32:
			++tlsCount;
			break;

		case orbisElfRelocationType64:
			if (orbisElfGetSymbol(elf, symbolIndex)->header.value)
			{
				++rebaseCount;
			}
			else
			{
				++importsCount;
			}
			break;

		default:
			assert(orbisElfGetSymbol(elf, symbolIndex)->header.value == 0);
			++importsCount;
			break;
		}
	}

	switch (elf->scePltRelType)
	{
	case orbisElfDynamicTypeRela:
	{
		const OrbisElfRela_t *rela = (OrbisElfRela_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRela_t); i < count; ++i)
		{
			if ((rela[i].info & 0xffffffff) != orbisElfRelocationTypeJumpSlot)
			{
				assert(0);
				continue;
			}

			if (!orbisElfGetSymbol(elf, rela[i].info >> 32)->header.value)
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
		const OrbisElfRel_t *rel = (OrbisElfRel_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRel_t); i < count; ++i)
		{
			if ((rel[i].info & 0xffffffff) != orbisElfRelocationTypeJumpSlot)
			{
				assert(0);
				continue;
			}

			if (!orbisElfGetSymbol(elf, rel[i].info >> 32)->header.value)
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

	default:
		assert(0);
	}

	elf->rebaseRelocationsCount = rebaseCount;
	elf->rebaseRelocations = malloc(sizeof(OrbisElfRebaseRelocation_t) * elf->rebaseRelocationsCount);

	elf->importRelocationsCount = importsCount;
	elf->importRelocations = malloc(sizeof(OrbisElfRelocation_t) * elf->importRelocationsCount);

	elf->tlsRelocationsCount = tlsCount;
	elf->tlsRelocations = malloc(sizeof(OrbisElfRelocation_t) * elf->tlsRelocationsCount);

	OrbisElfRebaseRelocation_t *rebaseIt = elf->rebaseRelocations;
	OrbisElfRelocation_t *importIt = elf->importRelocations;
	OrbisElfRelocation_t *tlsIt = elf->tlsRelocations;

	for (uint64_t i = 0, count = elf->sceRelaSize / elf->sceRelaEntSize; i < count; ++i)
	{
		uint32_t symbolIndex = elf->sceRela[i].info >> 32;
		uint32_t relType = elf->sceRela[i].info & 0xffffffff;

		if (relType == orbisElfRelocationTypeNone)
		{
			continue;
		}

		const OrbisElfSymbol_t *sym = orbisElfGetSymbol(elf, symbolIndex);


		switch (relType)
		{
		case orbisElfRelocationTypeRelative:
			rebaseIt->offset = elf->sceRela[i].offset;
			rebaseIt->value = elf->sceRela[i].addend;
			rebaseIt->symbolIndex = symbolIndex;

			++rebaseIt;
			break;

		case orbisElfRelocationTypeDtpMod64:
		case orbisElfRelocationTypeTpOff64:
		case orbisElfRelocationTypeTpOff32:
			tlsIt->offset = elf->sceRela[i].offset;
			tlsIt->symbolIndex = symbolIndex;
			tlsIt->relType = relType;
			tlsIt->addend = elf->sceRela[i].addend;

			++tlsIt;
			break;

		case orbisElfRelocationType64:
			if (sym->header.value)
			{
				rebaseIt->offset = elf->sceRela[i].offset;
				rebaseIt->value = sym->header.value;
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
			break;

		default:
			importIt->offset = elf->sceRela[i].offset;
			importIt->symbolIndex = symbolIndex;
			importIt->relType = relType;
			importIt->addend = elf->sceRela[i].addend;

			++importIt;
			break;
		}
	}

	switch (elf->scePltRelType)
	{
	case orbisElfDynamicTypeRela:
	{
		const OrbisElfRela_t *rela = (OrbisElfRela_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRela_t); i < count; ++i)
		{
			uint32_t symbolIndex = rela[i].info >> 32;
			const OrbisElfSymbol_t *sym = elf->symbols + symbolIndex;

			if (!orbisElfGetSymbol(elf, symbolIndex)->header.value)
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
		const OrbisElfRel_t *rel = (OrbisElfRel_t *)elf->sceJmpRel;

		for (uint64_t i = 0, count = elf->scePltRelSize / sizeof(OrbisElfRel_t); i < count; ++i)
		{
			uint32_t symbolIndex = rel[i].info >> 32;
			const OrbisElfSymbol_t *sym = elf->symbols + symbolIndex;

			if (!orbisElfGetSymbol(elf, symbolIndex)->header.value)
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
		break;
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfValidate(const void *image, size_t imageSize, OrbisElfType_t expectedType);
OrbisElfErrorCode_t orbisElfParse(OrbisElfHandle_t *handle, OrbisElfReadCallback_t readImageCallback, size_t imageSize, void *readImageUserData);
OrbisElfErrorCode_t orbisElfLoad(OrbisElfHandle_t elf, void *baseAddress, uint64_t virtualBaseAddress);

OrbisElfErrorCode_t orbisElfValidate(const void *image, size_t imageSize, OrbisElfType_t expectedType)
{
	if (imageSize < sizeof(OrbisElfHeader_t))
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	OrbisElfHeader_t *header = (OrbisElfHeader_t *)image;

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

OrbisElfErrorCode_t orbisElfParse(OrbisElfHandle_t *handle, OrbisElfReadCallback_t readImageCallback, size_t imageSize, void *readImageUserData)
{
	OrbisElfErrorCode_t errorCode;

	if (imageSize < sizeof(OrbisElfHeader_t))
	{
		return orbisElfErrorCodeInvalidImageFormat;
	}

	OrbisElfHandle_t elf = malloc(sizeof(OrbisElf_t));
		
	if (!elf)
	{
		return orbisElfErrorCodeNoMemory;
	}
		
	memset(elf, 0, sizeof(OrbisElf_t));
	elf->read = readImageCallback;
	elf->readUserData = readImageUserData;
	elf->imageSize = imageSize;
	
	if (orbisElfRead(elf, 0, &elf->header, sizeof(OrbisElfHeader_t)) != sizeof(OrbisElfHeader_t))
	{
		orbisElfDestroy(elf);
		return orbisElfErrorCodeIoError;
	}
	
	*handle = elf;

	int isOk = 1;
	isOk = isOk && (errorCode = parsePrograms(elf)) == orbisElfErrorCodeOk;
	isOk = isOk && (errorCode = parseSections(elf)) == orbisElfErrorCodeOk;
	isOk = isOk && (errorCode = parseDynamicProgram(elf)) == orbisElfErrorCodeOk;
	isOk = isOk && (errorCode = parseSymbols(elf)) == orbisElfErrorCodeOk;
	isOk = isOk && (errorCode = parseRelocations(elf)) == orbisElfErrorCodeOk;
	
	return isOk ? orbisElfErrorCodeOk : errorCode;
}

OrbisElfErrorCode_t orbisElfLoad(OrbisElfHandle_t elf, void *baseAddress, uint64_t virtualBaseAddress)
{
	elf->virtualBaseAddress = virtualBaseAddress ? virtualBaseAddress : (uint64_t)baseAddress;
	elf->baseAddress = baseAddress;

	for (uint64_t i = 0; i < elf->symbolsCount; ++i)
	{
		elf->symbols[i].virtualBaseAddress = elf->virtualBaseAddress;
	}

	for (uint16_t i = 0; i < elf->programsCount; ++i)
	{
		if (elf->programs[i].type == orbisElfProgramTypeLoad || elf->programs[i].type == orbisElfProgramTypeSceRelRo)
		{
			if (elf->programs[i].offset + elf->programs[i].filesz > elf->imageSize)
			{
				return orbisElfErrorCodeCorruptedImage;
			}
			
			if (orbisElfRead(elf, elf->programs[i].offset, (char *)baseAddress + elf->programs[i].vaddr, elf->programs[i].filesz)
			    != elf->programs[i].filesz)
			{
				return orbisElfErrorCodeIoError;
			}
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

		if (elf->symbols[importSymbolIndex].type == orbisElfSymbolBindLocal)
		{
			continue;
		}

		if (elf->symbols[importSymbolIndex].header.value && elf->symbols[importSymbolIndex].type != orbisElfSymbolBindWeak)
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

			if (importElf->symbols[exportSymbolIndex].type == orbisElfSymbolBindLocal)
			{
				continue;
			}

			if (elf->symbols[importSymbolIndex].header.value && importElf->symbols[exportSymbolIndex].type != orbisElfSymbolBindGlobal)
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
			elf->symbols[importSymbolIndex].header.size = importElf->symbols[exportSymbolIndex].header.size;
			elf->symbols[importSymbolIndex].virtualBaseAddress = importElf->virtualBaseAddress;
			break;
		}
	}

	return orbisElfErrorCodeOk;
}

OrbisElfErrorCode_t orbisElfSetImportSymbol(OrbisElfHandle_t elf, const char *moduleName, const char *libraryName, const char *symbolName, uint64_t virtualBaseAddress, uint64_t value, uint64_t size)
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

		elf->symbols[importSymbolIndex].header.value = value;
		elf->symbols[importSymbolIndex].header.size = size;
		elf->symbols[importSymbolIndex].virtualBaseAddress = virtualBaseAddress;
		return orbisElfErrorCodeOk;
	}

	return orbisElfErrorCodeNotFound;
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

	free((void *)elf->dynamics);
	free(elf->symbols);
	free(elf->importRelocations);
	free(elf->rebaseRelocations);
	free(elf->tlsRelocations);
	free((void *)elf->needed);
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

uint64_t orbisElfGetTlsInitAddress(OrbisElfHandle_t elf)
{
	return elf->tlsInitAddress;
}

uint64_t orbisElfGetTlsInitSize(OrbisElfHandle_t elf)
{
	return elf->tlsInitSize;
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

const OrbisElfProgramHeader_t *orbisElfGetProgram(OrbisElfHandle_t elf, uint16_t index)
{
	if (index >= elf->programsCount)
	{
		return NULL;
	}

	return elf->programs + index;
}

const OrbisElfSectionHeader_t *orbisElfGetSection(OrbisElfHandle_t elf, uint16_t index)
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

const OrbisElfSectionHeader_t *orbisElfFindSectionByName(OrbisElfHandle_t elf, const char *name)
{
	/*
	for (uint16_t i = 0; i < elf->sectionsCount; ++i)
	{
		if (strcmp(elf->sections[i].name, name) == 0)
		{
			return elf->sections + i;
		}
	}
	*/

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

const char *orbisElfSectionGetName(const OrbisElfSectionHeader_t *section)
{
	return NULL;//section->name;
}

uint64_t orbisElfGetRebaseRelocationsCount(OrbisElfHandle_t elf)
{
	return elf->rebaseRelocationsCount;
}

OrbisElfRebaseRelocation_t *orbisElfGetRebaseRelocation(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->rebaseRelocationsCount)
	{
		return NULL;
	}

	return elf->rebaseRelocations + index;
}

uint64_t orbisElfGetImportRelocationsCount(OrbisElfHandle_t elf)
{
	return elf->importRelocationsCount;
}

OrbisElfRelocation_t *orbisElfGetImportRelocation(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->importRelocationsCount)
	{
		return NULL;
	}

	return elf->importRelocations + index;
}

uint64_t orbisElfGetTlsRelocationsCount(OrbisElfHandle_t elf)
{
	return elf->tlsRelocationsCount;
}

OrbisElfRelocation_t *orbisElfGetTlsRelocation(OrbisElfHandle_t elf, uint64_t index)
{
	if (index >= elf->tlsRelocationsCount)
	{
		return NULL;
	}

	return elf->tlsRelocations + index;
}


uint8_t orbisElfGetRelocationAddressSize(OrbisElfRelocation_t *rel)
{
	switch (rel->relType)
	{
	case orbisElfRelocationTypePc32:
	case orbisElfRelocationTypeTpOff32:
	case orbisElfRelocationTypeDtpOff32:
		return 4;
	
	default:
		return 8;
	}
}

uint64_t orbisElfGetImportRelocationValue(OrbisElfHandle_t elf, OrbisElfRelocation_t *rel)
{
	const OrbisElfSymbol_t *sym = orbisElfGetSymbol(elf, rel->symbolIndex);

	switch (rel->relType)
	{
	case orbisElfRelocationTypeJumpSlot:
		if (sym->header.value)
		{
			return sym->virtualBaseAddress + sym->header.value + rel->addend;
		}

		return sym->virtualBaseAddress;

	case orbisElfRelocationType64:
		return sym->virtualBaseAddress + sym->header.value + rel->addend;

	case orbisElfRelocationTypePc32:
		return (uint32_t)(sym->virtualBaseAddress + sym->header.value + rel->addend - (elf->virtualBaseAddress + rel->offset));

	case orbisElfRelocationTypeCopy:
		fprintf(stderr, "%s: Unexpected R_X86_64_COPY relocation in shared library\n", elf->moduleInfo.name);
		return 0;

	case orbisElfRelocationTypeGlobDat:
		return sym->virtualBaseAddress + sym->header.value;

	case orbisElfRelocationTypeDtpOff64:
		return sym->header.value + rel->addend;

	case orbisElfRelocationTypeDtpOff32:
		return (uint32_t)(sym->header.value + rel->addend);

	default:
		fprintf(stderr, "%s: Unsupported relocation type %u in imports relocations\n", elf->moduleInfo.name, rel->relType);
		return 0;
	}
}

uint64_t orbisElfGetTlsRelocationValue(OrbisElfHandle_t elf, OrbisElfRelocation_t *rel, uint64_t tlsIndex, uint64_t tlsOffset)
{
	switch (rel->relType)
	{
	case orbisElfRelocationTypeDtpMod64:
		return tlsIndex;

	case orbisElfRelocationTypeTpOff64:
		return orbisElfGetSymbol(elf, rel->symbolIndex)->header.value - tlsOffset + rel->addend;

	case orbisElfRelocationTypeTpOff32:
		return (uint32_t)(orbisElfGetSymbol(elf, rel->symbolIndex)->header.value - tlsOffset + rel->addend);

	default:
		fprintf(stderr, "%s: Unsupported relocation type %u in TLS relocations\n", elf->moduleInfo.name, rel->relType);
		return 0;
	}
}


uint64_t orbisElfGetRelocationOffset(OrbisElfRelocation_t *rel)
{
	return rel->offset;
}

OrbisElfRelocationInjectType_t orbisElfGetRelocationInjectType(OrbisElfRelocation_t *rel)
{
	switch (rel->relType)
	{
	case orbisElfRelocationTypeDtpMod64:
	case orbisElfRelocationTypeDtpOff64:
	case orbisElfRelocationTypeTpOff64:
	case orbisElfRelocationTypeDtpOff32:
	case orbisElfRelocationTypeTpOff32:
		return orbisElfRelocationInjectTypeAdd;

	default:
		return orbisElfRelocationInjectTypeSet;
	}
}

const OrbisElfDynamic_t *orbisElfGetDynamics(OrbisElfHandle_t elf, uint64_t *count)
{
	if (count)
	{
		*count = elf->dynamicsCount;
	}

	return elf->dynamics;
}

const char **orbisElfGetNeeded(OrbisElfHandle_t elf, uint64_t *count)
{
	if (count)
	{
		*count = elf->neededCount;
	}

	return elf->needed;
}

uint64_t orbisElfRead(OrbisElfHandle_t elf, uint64_t offset, void *destination, uint64_t size)
{
	return elf->read(offset, destination, size, elf->readUserData);
}
