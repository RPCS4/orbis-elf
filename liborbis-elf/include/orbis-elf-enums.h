#ifndef _ORBIS_ELF_ENUMS_H_
#define _ORBIS_ELF_ENUMS_H_

typedef enum OrbisElfErrorCode_t
{
	orbisElfErrorCodeOk,
	orbisElfErrorCodeNoMemory,
	orbisElfErrorCodeInvalidImageFormat,
	orbisElfErrorCodeInvalidValue,
	orbisElfErrorCodeNotFound,
	orbisElfErrorCodeIoError,
	orbisElfErrorCodeCorruptedImage
} OrbisElfErrorCode_t;

typedef enum OrbisElfType_t
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

typedef enum OrbisElfProgramType_t
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
	orbisElfProgramTypeGnuEhFrame = 0x6474e550,
	orbisElfProgramTypeSceComment = 0x6fffff00,
	orbisElfProgramTypeSceVersion = 0x6fffff01,
} OrbisElfProgramType_t;

typedef enum OrbisElfSectionType_t
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

typedef enum OrbisElfDynamicType_t
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

typedef enum OrbisElfSymbolType_t
{
	orbisElfSymbolTypeNoType = 0,
	orbisElfSymbolTypeObject = 1,
	orbisElfSymbolTypeFunction = 2,
	orbisElfSymbolTypeSection = 3,
	orbisElfSymbolTypeFile = 4,
	orbisElfSymbolTypeCommon = 5,
	orbisElfSymbolTypeTls = 6
} OrbisElfSymbolType_t;

typedef enum OrbisElfSymbolBind_t
{
	orbisElfSymbolBindLocal = 0,
	orbisElfSymbolBindGlobal = 1,
	orbisElfSymbolBindWeak = 2
} OrbisElfSymbolBind_t;

typedef enum OrbisElfRelocationInjectType_t
{
	orbisElfRelocationInjectTypeSet,
	orbisElfRelocationInjectTypeAdd
} OrbisElfRelocationInjectType_t;

typedef enum OrbisElfRelocationType_t
{
	orbisElfRelocationTypeNone,
	orbisElfRelocationType64,
	orbisElfRelocationTypePc32,
	orbisElfRelocationTypeGot32,
	orbisElfRelocationTypePlt32,
	orbisElfRelocationTypeCopy,
	orbisElfRelocationTypeGlobDat,
	orbisElfRelocationTypeJumpSlot,
	orbisElfRelocationTypeRelative,
	orbisElfRelocationTypeGotPcRel,
	orbisElfRelocationType32,
	orbisElfRelocationType32s,
	orbisElfRelocationType16,
	orbisElfRelocationTypePc16,
	orbisElfRelocationType8,
	orbisElfRelocationTypePc8,
	orbisElfRelocationTypeDtpMod64,
	orbisElfRelocationTypeDtpOff64,
	orbisElfRelocationTypeTpOff64,
	orbisElfRelocationTypeTlsGd,
	orbisElfRelocationTypeTlsLd,
	orbisElfRelocationTypeDtpOff32,
	orbisElfRelocationTypeGotTpOff,
	orbisElfRelocationTypeTpOff32,
	orbisElfRelocationTypePc64,
	orbisElfRelocationTypeGotOff64,
	orbisElfRelocationTypeGotPc32,
	orbisElfRelocationTypeGot64,
	orbisElfRelocationTypeGotPcRel64,
	orbisElfRelocationTypeGotPc64,
	orbisElfRelocationTypeGotPlt64,
	orbisElfRelocationTypePltOff64,
	orbisElfRelocationTypeSize32,
	orbisElfRelocationTypeSize64,
	orbisElfRelocationTypeGotPc32TlsDesc,
	orbisElfRelocationTypeTlsDescCall,
	orbisElfRelocationTypeTlsDesc,
	orbisElfRelocationTypeIRelative,
	orbisElfRelocationTypeRelative64
} OrbisElfRelocationType_t;

#endif /* _ORBIS_ELF_ENUMS_H_ */
