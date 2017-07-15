#ifndef _ORBIS_ELF_API_H_
#define _ORBIS_ELF_API_H_

#include "orbis-elf-enums.h"
#include "orbis-elf-types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

OrbisElfErrorCode_t orbisElfValidate(const void *image, size_t size, OrbisElfType_t expectedType);
OrbisElfErrorCode_t orbisElfParse(const void *image, size_t size, OrbisElfHandle_t *handle);
OrbisElfErrorCode_t orbisElfLoad(OrbisElfHandle_t elf, void *address);
OrbisElfErrorCode_t orbisElfImportModule(OrbisElfHandle_t elf, OrbisElfHandle_t importElf);
OrbisElfErrorCode_t orbisElfImportSymbol(OrbisElfHandle_t elf, const char *moduleName, const char *libraryName, const char *symbolName, uint64_t value);
OrbisElfErrorCode_t orbisElfRelocate(OrbisElfHandle_t elf);
OrbisElfErrorCode_t orbisElfInitializeTls(OrbisElfHandle_t elf, void *tls);
void orbisElfDestroy(OrbisElfHandle_t elf);

const OrbisElfHeader_t *orbisElfGetHeader(OrbisElfHandle_t elf);
OrbisElfType_t orbisElfGetType(OrbisElfHandle_t elf);
const OrbisElfModuleInfo_t *orbisElfGetModuleInfo(OrbisElfHandle_t elf);
uint64_t orbisElfGetGotPltAddress(OrbisElfHandle_t elf);
uint64_t orbisElfGetTlsSize(OrbisElfHandle_t elf);
uint64_t orbisElfGetTlsAlign(OrbisElfHandle_t elf);
uint64_t orbisElfGetTlsIndex(OrbisElfHandle_t elf);
void orbisElfSetTlsIndex(OrbisElfHandle_t elf, uint64_t index);
uint64_t orbisElfGetTlsOffset(OrbisElfHandle_t elf);
void orbisElfSetTlsOffset(OrbisElfHandle_t elf, uint64_t offset);
uint64_t orbisElfGetLoadSize(OrbisElfHandle_t elf);
const char *orbisElfGetSoName(OrbisElfHandle_t elf);
uint64_t orbisElfGetEntryPoint(OrbisElfHandle_t elf);

uint16_t orbisElfGetProgramsCount(OrbisElfHandle_t elf);
uint16_t orbisElfGetSectionsCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetImportModulesCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetImportLibrariesCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetExportLibrariesCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetSymbolsCount(OrbisElfHandle_t elf);

OrbisElfProgramHandle_t orbisElfGetProgram(OrbisElfHandle_t elf, uint16_t index);
OrbisElfSectionHandle_t orbisElfGetSection(OrbisElfHandle_t elf, uint16_t index);
const OrbisElfModuleInfo_t *orbisElfGetImportModuleInfo(OrbisElfHandle_t elf, uint64_t index);
const OrbisElfLibraryInfo_t *orbisElfGetImportLibraryInfo(OrbisElfHandle_t elf, uint64_t index);
const OrbisElfLibraryInfo_t *orbisElfGetExportLibraryInfo(OrbisElfHandle_t elf, uint64_t index);
const OrbisElfSymbol_t *orbisElfGetSymbol(OrbisElfHandle_t elf, uint64_t index);

OrbisElfSectionHandle_t orbisElfFindSectionByName(OrbisElfHandle_t elf, const char *name);
const OrbisElfModuleInfo_t *orbisElfFindModuleById(OrbisElfHandle_t elf, uint16_t id);
const OrbisElfLibraryInfo_t *orbisElfFindLibraryById(OrbisElfHandle_t elf, uint16_t id);

const OrbisElfProgramHeader_t *orbisElfProgramGetHeader(OrbisElfProgramHandle_t program);
const void *orbisElfProgramGetData(OrbisElfProgramHandle_t program, uint64_t *size);

OrbisElfSectionHeader_t *orbisElfSectionGetHeader(OrbisElfSectionHandle_t section);
const void *orbisElfSectionGetData(OrbisElfSectionHandle_t section, uint64_t *size);
const char *orbisElfSectionGetName(OrbisElfSectionHandle_t section);

#ifdef __cplusplus
}
#endif

#endif /* _ORBIS_ELF_API_H_ */
