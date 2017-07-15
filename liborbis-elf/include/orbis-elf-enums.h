#ifndef _ORBIS_ELF_ENUMS_H_
#define _ORBIS_ELF_ENUMS_H_

typedef enum
{
	orbisElfErrorCodeOk,
	orbisElfErrorCodeNoMemory,
	orbisElfErrorCodeInvalidImageFormat,
	orbisElfErrorCodeInvalidValue,
	orbisElfErrorCodeNotFound,
} OrbisElfErrorCode_t;

typedef enum 
{
	orbisElfTypeNone = 0,
	orbisElfTypeRel = 1,
	orbisElfTypeExec = 2,
	orbisElfTypeDyn = 3,
	orbisElfTypeCore = 4,
	orbisElfTypeNum = 5,
	orbisElfTypeSceDynExec = 0xfe10,
	orbisElfTypeSceDynamic = 0xfe18
} OrbisElfType_t;

typedef enum
{
	orbisElfProgramTypeNull = 0,
	orbisElfProgramTypeLoad = 1,
	orbisElfProgramTypeDynamic = 2,
	orbisElfProgramTypeInterp = 3,
	orbisElfProgramTypeNote = 4,
	orbisElfProgramTypeShlib = 5,
	orbisElfProgramTypePhdr = 6,
	orbisElfProgramTypeTls = 7,
	orbisElfProgramTypeSceDynlibData = 0x61000000,
	orbisElfProgramTypeSceProcParam = 0x61000001,
	orbisElfProgramTypeSceRelRo = 0x61000010,
	orbisElfProgramTypeSceComment = 0x6fffff00,
	orbisElfProgramTypeSceVersion = 0x6fffff01,
} OrbisElfProgramType_t;

typedef enum
{
	orbisElfSectionTypeNull = 0,
	orbisElfSectionTypeProgBits = 1,
	orbisElfSectionTypeSymTab = 2,
	orbisElfSectionTypeStrTab = 3,
	orbisElfSectionTypeRela = 4,
	orbisElfSectionTypeHash = 5,
	orbisElfSectionTypeDynamic = 6,
	orbisElfSectionTypeNote = 7,
	orbisElfSectionTypeNoBits = 8,
	orbisElfSectionTypeRel = 9,
	orbisElfSectionTypeShlib = 10,
	orbisElfSectionTypeDynSym = 11,
} OrbisElfSectionType_t;

typedef enum
{
	orbisElfDynamicTypeNull = 0,
	orbisElfDynamicTypeNeeded = 1,
	orbisElfDynamicTypePltRelSize = 2,
	orbisElfDynamicTypePltGot = 3,
	orbisElfDynamicTypeHash = 4,
	orbisElfDynamicTypeStrTab = 5,
	orbisElfDynamicTypeSymTab = 6,
	orbisElfDynamicTypeRela = 7,
	orbisElfDynamicTypeRelaSize = 8,
	orbisElfDynamicTypeRelaEnt = 9,
	orbisElfDynamicTypeStrSize = 10,
	orbisElfDynamicTypeSymEnt = 11,
	orbisElfDynamicTypeInit = 12,
	orbisElfDynamicTypeFini = 13,
	orbisElfDynamicTypeSoName = 14,
	orbisElfDynamicTypeRpath = 15,
	orbisElfDynamicTypeSymbolic = 16,
	orbisElfDynamicTypeRel = 17,
	orbisElfDynamicTypeRelSize = 18,
	orbisElfDynamicTypeRelEent = 19,
	orbisElfDynamicTypePltRel = 20,
	orbisElfDynamicTypeDebug = 21,
	orbisElfDynamicTypeTextRel = 22,
	orbisElfDynamicTypeJmpRel = 23,
	orbisElfDynamicTypeBindNow = 24,
	orbisElfDynamicTypeInitArray = 25,
	orbisElfDynamicTypeFiniArray = 26,
	orbisElfDynamicTypeInitArraySize = 27,
	orbisElfDynamicTypeFiniArraySize = 28,
	orbisElfDynamicTypeRunPath = 29,
	orbisElfDynamicTypeFlags = 30,
	orbisElfDynamicTypePreinitArray = 32,
	orbisElfDynamicTypePreinitArraySize = 33,
	orbisElfDynamicTypeSceFingerprint = 0x61000007,
	orbisElfDynamicTypeSceOriginalFilename = 0x61000009,
	orbisElfDynamicTypeSceModuleInfo = 0x6100000d,
	orbisElfDynamicTypeSceNeededModule = 0x6100000f,
	orbisElfDynamicTypeSceModuleAttr = 0x61000011,
	orbisElfDynamicTypeSceExportLib = 0x61000013,
	orbisElfDynamicTypeSceImportLib = 0x61000015,
	orbisElfDynamicTypeSceExportLibAttr = 0x61000017,
	orbisElfDynamicTypeSceImportLibAttr = 0x61000019,
	orbisElfDynamicTypeSceHash = 0x61000025,
	orbisElfDynamicTypeScePltGot = 0x61000027,
	orbisElfDynamicTypeSceJmpRel = 0x61000029,
	orbisElfDynamicTypeScePltRel = 0x6100002b,
	orbisElfDynamicTypeScePltRelSize = 0x6100002d,
	orbisElfDynamicTypeSceRela = 0x6100002f,
	orbisElfDynamicTypeSceRelaSize = 0x61000031,
	orbisElfDynamicTypeSceRelaEnt = 0x61000033,
	orbisElfDynamicTypeSceStrTab = 0x61000035,
	orbisElfDynamicTypeSceStrSize = 0x61000037,
	orbisElfDynamicTypeSceSymTab = 0x61000039,
	orbisElfDynamicTypeSceSymEnt = 0x6100003b,
	orbisElfDynamicTypeSceHashSize = 0x6100003d,
	orbisElfDynamicTypeSceSymTabSize = 0x6100003f,
} OrbisElfDynamicType_t;

typedef enum
{
	orbisElfSymbolTypeNoType = 0,
	orbisElfSymbolTypeObject = 1,
	orbisElfSymbolTypeFunction = 2,
	orbisElfSymbolTypeSection = 3,
	orbisElfSymbolTypeFile = 4,
	orbisElfSymbolTypeCommon = 5,
	orbisElfSymbolTypeTls = 6
} OrbisElfSymbolType_t;

typedef enum
{
	orbisElfSymbolBindLocal = 0,
	orbisElfSymbolBindGlobal = 1,
	orbisElfSymbolBindWeak = 2
} OrbisElfSymbolBind_t;

#endif /* _ORBIS_ELF_ENUMS_H_ */
