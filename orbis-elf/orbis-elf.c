#include <orbis-elf-api.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <string.h>

#ifdef _WIN32
	#define stat64 _stat64
#endif

const char *orbisElfErrorCodeToString(OrbisElfErrorCode_t error)
{
	switch (error)
	{
	case orbisElfErrorCodeOk: return "Ok";
	case orbisElfErrorCodeNoMemory: return "No memory";
	case orbisElfErrorCodeInvalidImageFormat: return "Invalid image format";
	case orbisElfErrorCodeInvalidValue: return "Invalid value";
	case orbisElfErrorCodeNotFound: return "Not found";

	default:
		break;
	}

	return "<invalid error code>";
}

const char *orbisElfTypeToString(OrbisElfType_t type)
{
	switch (type)
	{
	case orbisElfTypeRel: return "Rel";
	case orbisElfTypeExec: return "Exec";
	case orbisElfTypeDyn: return "Dyn";
	case orbisElfTypeCore: return "Core";
	case orbisElfTypeSceDynExec: return "SCE DynExec";
	case orbisElfTypeSceDynamic: return "SCE Dyn";

	default:
		break;
	}

	return "<unknown type>";
}

const char *orbisElfSymbolTypeToString(OrbisElfSymbolType_t type)
{
	switch (type)
	{
	case orbisElfSymbolTypeNoType: return "No type";

	case orbisElfSymbolTypeObject: return "Object";
	case orbisElfSymbolTypeFunction: return "Function";
	case orbisElfSymbolTypeSection: return "Section";
	case orbisElfSymbolTypeFile: return "File";
	case orbisElfSymbolTypeCommon: return "Common";
	case orbisElfSymbolTypeTls: return "TLS";
	default:
		break;
	}

	return "<unknown>";
}

const char *orbisElfSymbolBindToString(OrbisElfSymbolBind_t bind)
{
	switch (bind)
	{
	case orbisElfSymbolBindLocal: return "Local";
	case orbisElfSymbolBindGlobal: return "Global";
	case orbisElfSymbolBindWeak: return "Weak";

	default:
		break;
	}

	return "<unknown>";
}

const char *orbisElfProgramTypeToString(OrbisElfProgramType_t type)
{
	switch (type)
	{
	case orbisElfProgramTypeNull: return "null";
	case orbisElfProgramTypeLoad: return "load";
	case orbisElfProgramTypeDynamic: return "dynamic";
	case orbisElfProgramTypeInterp: return "interp";
	case orbisElfProgramTypeNote: return "note";
	case orbisElfProgramTypeShlib: return "shlib";
	case orbisElfProgramTypePhdr: return "phdr";
	case orbisElfProgramTypeTls: return "tls";
	case orbisElfProgramTypeSceDynlibData: return "sce_dynlib_data";
	case orbisElfProgramTypeSceProcParam: return "sce_proc_param";
	case orbisElfProgramTypeSceRelRo: return "sce_rel_ro";
	case orbisElfProgramTypeSceComment: return "sce_comment";
	case orbisElfProgramTypeSceVersion: return "sce_version";

	default:
		break;
	}

	return NULL;
}

enum
{
	configDumpHeader = 1 << 0,
	configDumpSections = 1 << 1,
	configDumpPrograms = 1 << 2,
	configDumpImportSymbols = 1 << 3,
	configDumpExportSymbols = 1 << 4,
	configDumpRebases = 1 << 5,
	configDumpSceSymbols = 1 << 6,
	configDumpSceDynamic = 1 << 7,
	configDumpTlsInfo = 1 << 8,
	configDumpImportLibraries = 1 << 9,
	configDumpImportModules = 1 << 10,
};


static int charToConfigKey(char c)
{
	switch (c)
	{
	case 'a': return ~0;
	case 'H': return configDumpHeader;
	case 'S': return configDumpSections;
	case 'p': return configDumpPrograms;
	case 'i': return configDumpImportSymbols;
	case 'e': return configDumpExportSymbols;
	case 'r': return configDumpRebases;
	case 's': return configDumpSceSymbols;
	case 'd': return configDumpSceDynamic;
	case 't': return configDumpTlsInfo;
	case 'l': return configDumpImportLibraries;
	case 'm': return configDumpImportModules;

	default:
		break;
	}

	return 0;
}

static void usage(const char *program)
{
	printf("usage: %s [OPTIONS] <path to elf>\n", program);
	printf("    OPTIONS:\n");
	printf("        -a - Dump all (default)\n");
	printf("        -H - Dump header\n");
	printf("        -S - Dump sections\n");
	printf("        -p - Dump programs\n");
	printf("        -i - Dump import symbols\n");
	printf("        -e - Dump export symbols\n");
	printf("        -r - Dump rebases\n");
	printf("        -s - Dump sce symbols\n");
	printf("        -d - Dump sce dynamic\n");
	printf("        -t - Dump TLS info\n");
	printf("        -l - Dump import libraries\n");
	printf("        -m - Dump import modules\n");
}

int main(int argc, const char *argv[])
{
	if (argc < 2)
	{
		usage(argv[0]);
		return 1;
	}

	const char *pathToElf = NULL;
	int config = 0;

	for (int i = 1; i < argc; ++i)
	{
		if (argv[i][0] == '-')
		{
			for (int j = 1; argv[i][j] != '\0'; ++j)
			{
				if (argv[i][j] == 'h')
				{
					usage(argv[0]);
					return 0;
				}
				int key = charToConfigKey(argv[i][j]);

				if (key == 0)
				{
					usage(argv[0]);
					return 1;
				}

				config |= key;
			}
		}
		else if (pathToElf == NULL)
		{
			pathToElf = argv[i];
		}
		else
		{
			usage(argv[0]);
			return 1;
		}
	}

	if (!config)
	{
		config = ~0;
	}

	if (!pathToElf)
	{
		usage(argv[0]);
		return 1;
	}

	struct stat64 fileStat;
	if (stat64(pathToElf, &fileStat) != 0)
	{
		fprintf(stderr, "File '%s' not found\n", pathToElf);
		return 1;
	}

	FILE *file = fopen(pathToElf, "rb");

	if (!file)
	{
		fprintf(stderr, "File '%s' opening error\n", pathToElf);
		return 1;
	}

	void *elfData = malloc(fileStat.st_size);

	if (fread(elfData, 1, fileStat.st_size, file) != fileStat.st_size)
	{
		fprintf(stderr, "File '%s' reading error\n", pathToElf);
		free(elfData);

		return 1;
	}

	OrbisElfHandle_t elf;
	OrbisElfErrorCode_t errorCode = orbisElfParse(elfData, fileStat.st_size, &elf);

	if (errorCode != orbisElfErrorCodeOk)
	{
		fprintf(stderr, "File '%s' parsing error: %s\n", pathToElf, orbisElfErrorCodeToString(errorCode));
		free(elfData);
		return 0;
	}

	if (config & configDumpHeader)
	{
		const OrbisElfHeader_t *elfHeader = orbisElfGetHeader(elf);

		if (elfHeader)
		{
			printf("Type: 0x%x - %s\n", elfHeader->type, orbisElfTypeToString(elfHeader->type));
			printf("Entry point: 0x%" PRIx64 "\n", elfHeader->entry);
			printf("\n\n");
		}
	}

	if (config & configDumpPrograms)
	{
		uint16_t programsCount = orbisElfGetProgramsCount(elf);
		if (programsCount)
		{
			printf("ELF contains %" PRIu16 " programs\n\n", programsCount);

			if (programsCount)
			{
				printf("#                Type   Flags      Offset             FileSize           VAddr              PAddr               MemSize            Align\n");

				for (uint16_t i = 0; i < programsCount; ++i)
				{
					const OrbisElfProgramHeader_t *programHeader = orbisElfProgramGetHeader(orbisElfGetProgram(elf, i));

					printf("%-3u  ", i);

					if (programHeader)
					{
						int needFreeProgramType = 0;

						char *programType = (char *)orbisElfProgramTypeToString(programHeader->type);

						if (!programType)
						{
							programType = malloc(32);
							snprintf(programType, 64, "0x%-8" PRIx32, programHeader->type);
							needFreeProgramType = 1;
						}

						printf("% 16s   %-8" PRIx32 "   %-16" PRIx64 "   %-16" PRIx64 "   %-16" PRIx64 "   %-16" PRIx64 "    %-16" PRIx64 "   %-16" PRIx64,
							programType,
							programHeader->flags,
							programHeader->offset,
							programHeader->filesz,
							programHeader->vaddr,
							programHeader->paddr,
							programHeader->memsz,
							programHeader->align
						);

						if (needFreeProgramType)
						{
							free(programType);
						}
					}
					else
					{
						printf("<error>");
					}

					printf("\n");
				}

				printf("\n");
			}
		}
	}

	if (config & configDumpSections)
	{
		uint16_t sectionsCount = orbisElfGetSectionsCount(elf);
		if (sectionsCount == orbisElfErrorCodeOk)
		{
			printf("ELF contains %" PRIu16 " sections\n\n", sectionsCount);

			if (sectionsCount)
			{
				for (uint16_t i = 0; i < sectionsCount; ++i)
				{
					OrbisElfSectionHandle_t section = orbisElfGetSection(elf, i);
					printf("%-3u  %s\n", i, orbisElfSectionGetName(section));
				}

				printf("\n");
			}
		}
	}

	if (config & configDumpImportLibraries)
	{
		uint64_t importLibrariesCount = orbisElfGetImportLibrariesCount(elf);
		if (importLibrariesCount)
		{
			for (uint64_t i = 0; i < importLibrariesCount; ++i)
			{
				const OrbisElfLibraryInfo_t *info = orbisElfGetImportLibraryInfo(elf, i);

				printf("Import library '%s' version %" PRIu16 ".%" PRIu16 " attributes 0x%" PRIx32 "\n",
					info->name, info->version >> 8, info->version & 0xff, info->attr);
			}

			printf("\n\n");
		}
	}

	if (config & configDumpImportModules)
	{
		uint64_t importModulesCount = orbisElfGetImportModulesCount(elf);
		if (importModulesCount)
		{
			for (uint64_t i = 0; i < importModulesCount; ++i)
			{
				const OrbisElfModuleInfo_t *info = orbisElfGetImportModuleInfo(elf, i);

				printf("Import module '%s' version %" PRIu16 ".%" PRIu16 " attributes 0x%" PRIx64 "\n",
					info->name, info->version >> 8, info->version & 0xff, info->attr);
			}

			printf("\n\n");
		}
	}

	if (config & configDumpSceSymbols)
	{
		uint64_t symbolsCount = orbisElfGetSymbolsCount(elf);
		if (symbolsCount)
		{
			for (uint64_t i = 0; i < symbolsCount; ++i)
			{
				const OrbisElfSymbol_t *symbol = orbisElfGetSymbol(elf, i);

				printf("Symbol '");

				if (symbol->library && symbol->module)
				{
					printf("%s::%s::%s",
						symbol->module->name,
						symbol->library->name,
						symbol->name
					);
				}
				else
				{
					printf("%s", symbol->name);
				}

				printf("' %s %s at 0x%" PRIx64 " other %u size 0x%" PRIx64 "\n",
					orbisElfSymbolBindToString(symbol->bind),
					orbisElfSymbolTypeToString(symbol->type),
					symbol->header.value, symbol->header.other, symbol->header.size);
			}

			printf("\n\n");
		}
	}

	if (config & configDumpImportSymbols)
	{
		//TODO
	}

	if (config & configDumpExportSymbols)
	{
		//TODO
	}

	if (config & configDumpRebases)
	{
		//TODO
	}

	if (config & configDumpSceDynamic)
	{
		//TODO
	}

	if (config & configDumpTlsInfo)
	{
		printf("TLS offset: 0x%" PRIx64 "\n", orbisElfGetTlsOffset(elf));
		printf("TLS size: 0x%" PRIx64 "\n", orbisElfGetTlsSize(elf));
		printf("TLS align: 0x%" PRIx64 "\n", orbisElfGetTlsAlign(elf));
		printf("TLS init address: 0x%" PRIx64 "\n", orbisElfGetTlsInitAddress(elf));
		printf("TLS init size: 0x%" PRIx64 "\n", orbisElfGetTlsInitSize(elf));
	}

	orbisElfDestroy(elf);
	free(elfData);
	return 0;
}
