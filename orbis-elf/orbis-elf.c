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


void usage(const char *program)
{
	printf("usage: %s <path to elf>\n", program);
}

int main(int argc, const char *argv[])
{
	if (argc < 2)
	{
		usage(argv[0]);
		return 1;
	}

	struct stat64 fileStat;
	if (stat64(argv[1], &fileStat) != 0)
	{
		fprintf(stderr, "File '%s' not found\n", argv[1]);
		return 1;
	}

	FILE *file = fopen(argv[1], "rb");

	if (!file)
	{
		fprintf(stderr, "File '%s' opening error\n", argv[1]);
		return 1;
	}

	void *elfData = malloc(fileStat.st_size);

	if (fread(elfData, 1, fileStat.st_size, file) != fileStat.st_size)
	{
		fprintf(stderr, "File '%s' reading error\n", argv[1]);
		free(elfData);

		return 1;
	}

	OrbisElfHandle_t elf;
	OrbisElfErrorCode_t errorCode = orbisElfParse(elfData, fileStat.st_size, &elf);

	if (errorCode != orbisElfErrorCodeOk)
	{
		fprintf(stderr, "File '%s' parsing error: %s\n", argv[1], orbisElfErrorCodeToString(errorCode));
		free(elfData);
		return 0;
	}

	printf("%s:\n", argv[1]);

	const OrbisElfHeader_t *elfHeader = orbisElfGetHeader(elf);
	if (elfHeader)
	{
		printf("Type: 0x%x - %s\n", elfHeader->type, orbisElfTypeToString(elfHeader->type));
		printf("Entry point: 0x%" PRIx64 "\n", elfHeader->entry);
		printf("\n\n");
	}

	uint16_t programsCount = orbisElfGetProgramsCount(elf);
	if (programsCount)
	{
		printf("ELF contains %" PRIu16 " programs\n\n", programsCount);

		if (programsCount)
		{
			printf("#    type         flags        offset               vaddr                paddr                 memsz                align\n");

			for (uint16_t i = 0; i < programsCount; ++i)
			{
				const OrbisElfProgramHeader_t *programHeader = orbisElfProgramGetHeader(orbisElfGetProgram(elf, i));

				printf("%-3u  ", i);

				if (programHeader)
				{
					printf("0x%08" PRIx32 "   0x%08" PRIx32 "   0x%016" PRIx64 "   0x%016" PRIx64 "   0x%016" PRIx64 "    0x%016" PRIx64 "   0x%016" PRIx64,
						programHeader->type,
						programHeader->flags,
						programHeader->offset,
						programHeader->vaddr,
						programHeader->paddr,
						programHeader->memsz,
						programHeader->align
					);
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

	orbisElfDestroy(elf);
	free(elfData);
	return 0;
}
