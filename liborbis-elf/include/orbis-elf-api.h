#ifndef _ORBIS_ELF_API_H_
#define _ORBIS_ELF_API_H_

#include "orbis-elf-enums.h"
#include "orbis-elf-types.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

OrbisElfErrorCode_t orbisElfValidate(const void *image, size_t imageSize, OrbisElfType_t expectedType);
OrbisElfErrorCode_t orbisElfParse(OrbisElfHandle_t *handle, OrbisElfReadCallback_t readImageCallback, size_t imageSize, void *readImageUserData);
OrbisElfErrorCode_t orbisElfLoad(OrbisElfHandle_t elf, void *baseAddress, uint64_t virtualBaseAddress);

OrbisElfErrorCode_t orbisElfImportModule(OrbisElfHandle_t elf, OrbisElfHandle_t importElf);
OrbisElfErrorCode_t orbisElfSetImportSymbol(OrbisElfHandle_t elf, const char *moduleName, const char *libraryName, const char *symbolName, uint64_t virtualBaseAddress, uint64_t value, uint64_t size);

void orbisElfDestroy(OrbisElfHandle_t elf);

const OrbisElfHeader_t *orbisElfGetHeader(OrbisElfHandle_t elf);
OrbisElfType_t orbisElfGetType(OrbisElfHandle_t elf);
const OrbisElfModuleInfo_t *orbisElfGetModuleInfo(OrbisElfHandle_t elf);
uint64_t orbisElfGetGotPltAddress(OrbisElfHandle_t elf);
uint64_t orbisElfGetTlsSize(OrbisElfHandle_t elf);
uint64_t orbisElfGetTlsAlign(OrbisElfHandle_t elf);
uint64_t orbisElfGetTlsInitAddress(OrbisElfHandle_t elf);
uint64_t orbisElfGetTlsInitSize(OrbisElfHandle_t elf);
uint64_t orbisElfGetLoadSize(OrbisElfHandle_t elf);
const char *orbisElfGetSoName(OrbisElfHandle_t elf);
uint64_t orbisElfGetSceProcParam(OrbisElfHandle_t elf, uint64_t *size);
uint64_t orbisElfGetEntryPoint(OrbisElfHandle_t elf);
uint64_t orbisElfGetVirtualBaseAddress(OrbisElfHandle_t elf);
void *orbisElfGetBaseAddress(OrbisElfHandle_t elf);

uint16_t orbisElfGetProgramsCount(OrbisElfHandle_t elf);
uint16_t orbisElfGetSectionsCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetImportModulesCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetImportLibrariesCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetExportLibrariesCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetSymbolsCount(OrbisElfHandle_t elf);
uint64_t orbisElfGetInitAddress(OrbisElfHandle_t elf);
uint64_t orbisElfGetPreinitArray(OrbisElfHandle_t elf, uint64_t *count);
uint64_t orbisElfGetInitArray(OrbisElfHandle_t elf, uint64_t *count);

const OrbisElfProgramHeader_t *orbisElfGetProgram(OrbisElfHandle_t elf, uint16_t index);
const OrbisElfSectionHeader_t *orbisElfGetSection(OrbisElfHandle_t elf, uint16_t index);
const OrbisElfModuleInfo_t *orbisElfGetImportModuleInfo(OrbisElfHandle_t elf, uint64_t index);
const OrbisElfLibraryInfo_t *orbisElfGetImportLibraryInfo(OrbisElfHandle_t elf, uint64_t index);
const OrbisElfLibraryInfo_t *orbisElfGetExportLibraryInfo(OrbisElfHandle_t elf, uint64_t index);
const OrbisElfSymbol_t *orbisElfGetSymbol(OrbisElfHandle_t elf, uint64_t index);

const OrbisElfSymbol_t *orbisElfFindSymbolByName(OrbisElfHandle_t elf, const char *name);
const OrbisElfSectionHeader_t *orbisElfFindSectionByName(OrbisElfHandle_t elf, const char *name);
const OrbisElfModuleInfo_t *orbisElfFindModuleById(OrbisElfHandle_t elf, uint16_t id);
const OrbisElfLibraryInfo_t *orbisElfFindLibraryById(OrbisElfHandle_t elf, uint16_t id);

const char *orbisElfSectionGetName(const OrbisElfSectionHeader_t *section);

uint64_t orbisElfGetRebaseRelocationsCount(OrbisElfHandle_t elf);
OrbisElfRebaseRelocation_t *orbisElfGetRebaseRelocation(OrbisElfHandle_t elf, uint64_t index);

uint64_t orbisElfGetImportRelocationsCount(OrbisElfHandle_t elf);
OrbisElfRelocation_t *orbisElfGetImportRelocation(OrbisElfHandle_t elf, uint64_t index);

uint64_t orbisElfGetTlsRelocationsCount(OrbisElfHandle_t elf);
OrbisElfRelocation_t *orbisElfGetTlsRelocation(OrbisElfHandle_t elf, uint64_t index);

uint8_t orbisElfGetRelocationAddressSize(OrbisElfRelocation_t *rel);
uint64_t orbisElfGetImportRelocationValue(OrbisElfHandle_t elf, OrbisElfRelocation_t *rel);
uint64_t orbisElfGetRelocationOffset(OrbisElfRelocation_t *rel);
uint64_t orbisElfGetTlsRelocationValue(OrbisElfHandle_t elf, OrbisElfRelocation_t *rel, uint64_t index, uint64_t offset);
OrbisElfRelocationInjectType_t orbisElfGetRelocationInjectType(OrbisElfRelocation_t *rel);

const OrbisElfDynamic_t *orbisElfGetDynamics(OrbisElfHandle_t elf, uint64_t *count);

uint64_t orbisElfRead(OrbisElfHandle_t elf, uint64_t offset, void *destination, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif /* _ORBIS_ELF_API_H_ */
