/*
 * pml_consts.h — PML v9 constant tables.
 *
 * Operation names, NTSTATUS codes, sub-operation names, and category
 * mappings. Keys use (event_class << 16 | operation) encoding.
 *
 * Header-only; include from a single .cpp to avoid ODR violations.
 */

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>


/* ================================================================
 * Key encoding
 * ================================================================ */

static inline uint32_t lut_key(uint32_t high, uint32_t low) {
    return (high << 16) | low;
}

/* Event class values */
namespace pml {
    constexpr uint32_t EC_PROCESS  = 1;
    constexpr uint32_t EC_REGISTRY = 2;
    constexpr uint32_t EC_FS       = 3;
    constexpr uint32_t EC_PROFILING = 4;
    constexpr uint32_t EC_NETWORK  = 5;
}


/* ================================================================
 * Operation LUT: (event_class << 16 | op) → display name
 * ================================================================ */

static inline std::unordered_map<uint32_t, std::string>
build_operation_lut() {
    std::unordered_map<uint32_t, std::string> lut;

    /* Process operations (space-separated display names) */
    const char *proc_ops[] = {
        "Process Defined", "Process Create", "Process Exit",
        "Thread Create", "Thread Exit", "Load Image",
        "Thread Profile", "Process Start", "Process Statistics",
        "System Statistics",
    };
    for (uint32_t i = 0; i < 10; i++)
        lut[lut_key(pml::EC_PROCESS, i)] = proc_ops[i];

    /* Registry operations */
    const char *reg_ops[] = {
        "RegOpenKey", "RegCreateKey", "RegCloseKey", "RegQueryKey",
        "RegSetValue", "RegQueryValue", "RegEnumValue", "RegEnumKey",
        "RegSetInfoKey", "RegDeleteKey", "RegDeleteValue", "RegFlushKey",
        "RegLoadKey", "RegUnloadKey", "RegRenameKey",
        "RegQueryMultipleValueKey", "RegSetKeySecurity",
        "RegQueryKeySecurity", "Unknown1", "RegRestorekey", "Unknown3",
    };
    for (uint32_t i = 0; i < 21; i++)
        lut[lut_key(pml::EC_REGISTRY, i)] = reg_ops[i];

    /* Filesystem operations */
    const char *fs_ops[] = {
        "VolumeDismount", "VolumeMount",
        "FASTIO_MDL_WRITE_COMPLETE", "WriteFile2",
        "FASTIO_MDL_READ_COMPLETE", "ReadFile2",
        "QueryOpen", "FASTIO_CHECK_IF_POSSIBLE",
        "IRP_MJ_12", "IRP_MJ_11", "IRP_MJ_10", "IRP_MJ_9", "IRP_MJ_8",
        "FASTIO_NOTIFY_STREAM_FO_CREATION",
        "FASTIO_RELEASE_FOR_CC_FLUSH",
        "FASTIO_ACQUIRE_FOR_CC_FLUSH",
        "FASTIO_RELEASE_FOR_MOD_WRITE",
        "FASTIO_ACQUIRE_FOR_MOD_WRITE",
        "FASTIO_RELEASE_FOR_SECTION_SYNCHRONIZATION",
        "CreateFileMapping", "CreateFile", "CreatePipe",
        "IRP_MJ_CLOSE", "ReadFile", "WriteFile",
        "QueryInformationFile", "SetInformationFile",
        "QueryEAFile", "SetEAFile", "FlushBuffersFile",
        "QueryVolumeInformation", "SetVolumeInformation",
        "DirectoryControl", "FileSystemControl",
        "DeviceIoControl", "InternalDeviceIoControl",
        "Shutdown", "LockUnlockFile", "CloseFile", "CreateMailSlot",
        "QuerySecurityFile", "SetSecurityFile",
        "Power", "SystemControl", "DeviceChange",
        "QueryFileQuota", "SetFileQuota", "PlugAndPlay",
    };
    for (uint32_t i = 0; i < 48; i++)
        lut[lut_key(pml::EC_FS, i)] = fs_ops[i];

    /* Profiling operations (space-separated) */
    const char *prof_ops[] = {
        "Thread Profiling", "Process Profiling",
        "Debug Output Profiling",
    };
    for (uint32_t i = 0; i < 3; i++)
        lut[lut_key(pml::EC_PROFILING, i)] = prof_ops[i];

    /* Network operations */
    const char *net_ops[] = {
        "Unknown", "Other", "Send", "Receive", "Accept",
        "Connect", "Disconnect", "Reconnect", "Retransmit", "TCPCopy",
    };
    for (uint32_t i = 0; i < 10; i++)
        lut[lut_key(pml::EC_NETWORK, i)] = net_ops[i];

    return lut;
}


/* ================================================================
 * Sub-operation LUT: (main_op << 16 | sub_op) → display name
 * ================================================================ */

static inline std::unordered_map<uint32_t, std::string>
build_sub_operation_lut() {
    struct Entry { uint32_t val; const char *name; };
    std::unordered_map<uint32_t, std::string> lut;

    /* QueryVolumeInformation (main_op=30) */
    Entry qvol[] = {
        {1,"QueryInformationVolume"},{2,"QueryLabelInformationVolume"},
        {3,"QuerySizeInformationVolume"},{4,"QueryDeviceInformationVolume"},
        {5,"QueryAttributeInformationVolume"},{6,"QueryControlInformationVolume"},
        {7,"QueryFullSizeInformationVolume"},{8,"QueryObjectIdInformationVolume"},
    };
    for (auto &e : qvol) lut[lut_key(30, e.val)] = e.name;

    /* SetVolumeInformation (main_op=31) */
    Entry svol[] = {
        {1,"SetControlInformationVolume"},{2,"SetLabelInformationVolume"},
        {8,"SetObjectIdInformationVolume"},
    };
    for (auto &e : svol) lut[lut_key(31, e.val)] = e.name;

    /* QueryInformationFile (main_op=25) */
    Entry qinfo[] = {
        {0x04,"QueryBasicInformationFile"},{0x05,"QueryStandardInformationFile"},
        {0x06,"QueryFileInternalInformationFile"},{0x07,"QueryEaInformationFile"},
        {0x09,"QueryNameInformationFile"},{0x0e,"QueryPositionInformationFile"},
        {0x12,"QueryAllInformationFile"},{0x14,"QueryEndOfFile"},
        {0x16,"QueryStreamInformationFile"},{0x1c,"QueryCompressionInformationFile"},
        {0x1d,"QueryId"},{0x1f,"QueryMoveClusterInformationFile"},
        {0x22,"QueryNetworkOpenInformationFile"},{0x23,"QueryAttributeTagFile"},
        {0x25,"QueryIdBothDirectory"},{0x27,"QueryValidDataLength"},
        {0x28,"QueryShortNameInformationFile"},{0x2b,"QueryIoPiorityHint"},
        {0x2e,"QueryLinks"},{0x30,"QueryNormalizedNameInformationFile"},
        {0x31,"QueryNetworkPhysicalNameInformationFile"},
        {0x32,"QueryIdGlobalTxDirectoryInformation"},
        {0x33,"QueryIsRemoteDeviceInformation"},
        {0x34,"QueryAttributeCacheInformation"},
        {0x35,"QueryNumaNodeInformation"},
        {0x36,"QueryStandardLinkInformation"},
        {0x37,"QueryRemoteProtocolInformation"},
        {0x38,"QueryRenameInformationBypassAccessCheck"},
        {0x39,"QueryLinkInformationBypassAccessCheck"},
        {0x3a,"QueryVolumeNameInformation"},
        {0x3b,"QueryIdInformation"},
        {0x3c,"QueryIdExtdDirectoryInformation"},
        {0x3e,"QueryHardLinkFullIdInformation"},
        {0x3f,"QueryIdExtdBothDirectoryInformation"},
        {0x43,"QueryDesiredStorageClassInformation"},
        {0x44,"QueryStatInformation"},
        {0x45,"QueryMemoryPartitionInformation"},
        {0x46,"QuerySatLxInformation"},
        {0x47,"QueryCaseSensitiveInformation"},
        {0x48,"QueryLinkInformationEx"},
        {0x49,"QueryLinkInfomraitonBypassAccessCheck"},
        {0x4a,"QueryStorageReservedIdInformation"},
        {0x4b,"QueryCaseSensitiveInformationForceAccessCheck"},
    };
    for (auto &e : qinfo) lut[lut_key(25, e.val)] = e.name;

    /* SetInformationFile (main_op=26) */
    Entry sinfo[] = {
        {0x04,"SetBasicInformationFile"},{0x0a,"SetRenameInformationFile"},
        {0x0b,"SetLinkInformationFile"},{0x0d,"SetDispositionInformationFile"},
        {0x0e,"SetPositionInformationFile"},{0x13,"SetAllocationInformationFile"},
        {0x14,"SetEndOfFileInformationFile"},{0x16,"SetFileStreamInformation"},
        {0x17,"SetPipeInformation"},{0x27,"SetValidDataLengthInformationFile"},
        {0x28,"SetShortNameInformation"},{0x3d,"SetReplaceCompletionInformation"},
        {0x40,"SetDispositionInformationEx"},{0x41,"SetRenameInformationEx"},
        {0x42,"SetRenameInformationExBypassAccessCheck"},
        {0x4a,"SetStorageReservedIdInformation"},
    };
    for (auto &e : sinfo) lut[lut_key(26, e.val)] = e.name;

    /* DirectoryControl (main_op=32) */
    lut[lut_key(32, 1)] = "QueryDirectory";
    lut[lut_key(32, 2)] = "NotifyChangeDirectory";

    /* PlugAndPlay (main_op=47) */
    Entry pnp[] = {
        {0x00,"StartDevice"},{0x01,"QueryRemoveDevice"},
        {0x02,"RemoveDevice"},{0x03,"CancelRemoveDevice"},
        {0x04,"StopDevice"},{0x05,"QueryStopDevice"},
        {0x06,"CancelStopDevice"},{0x07,"QueryDeviceRelations"},
        {0x08,"QueryInterface"},{0x09,"QueryCapabilities"},
        {0x0a,"QueryResources"},{0x0b,"QueryResourceRequirements"},
        {0x0c,"QueryDeviceText"},{0x0d,"FilterResourceRequirements"},
        {0x0f,"ReadConfig"},{0x10,"WriteConfig"},
        {0x11,"Eject"},{0x12,"SetLock"},
        {0x13,"QueryId2"},{0x14,"QueryPnpDeviceState"},
        {0x15,"QueryBusInformation"},{0x16,"DeviceUsageNotification"},
        {0x17,"SurpriseRemoval"},{0x18,"QueryLegacyBusInformation"},
    };
    for (auto &e : pnp) lut[lut_key(47, e.val)] = e.name;

    /* LockUnlockFile (main_op=37) */
    Entry lock[] = {
        {1,"LockFile"},{2,"UnlockFileSingle"},
        {3,"UnlockFileAll"},{4,"UnlockFileByKey"},
    };
    for (auto &e : lock) lut[lut_key(37, e.val)] = e.name;

    return lut;
}


/* ================================================================
 * Error LUT: NTSTATUS code → display name
 * ================================================================ */

static inline std::unordered_map<uint32_t, std::string>
build_error_lut() {
    return {
        {0x00000000, "SUCCESS"},
        {0x00000103, ""},
        {0x00000104, "REPARSE"},
        {0x00000105, "MORE ENTRIES"},
        {0x00000108, "OPLOCK BREAK IN PROGRESS"},
        {0x0000010b, "NOTIFY CLEANUP"},
        {0x0000010c, "NOTIFY ENUM DIR"},
        {0x0000012a, "FILE LOCKED WITH ONLY READERS"},
        {0x0000012b, "FILE LOCKED WITH WRITERS"},
        {0x00000215, "OPLOCK SWITCHED TO NEW HANDLE"},
        {0x00000216, "OPLOCK HANDLE CLOSED"},
        {0x00000367, "WAIT FOR OPLOCK"},
        {0x40000016, "PREDEFINED HANDLE"},
        {0x80000002, "DATATYPE MISALIGNMENT"},
        {0x80000005, "BUFFER OVERFLOW"},
        {0x80000006, "NO MORE FILES"},
        {0x80000015, "INVALID EA FLAG"},
        {0x8000001a, "NO MORE ENTRIES"},
        {0xc0000001, "UNSUCCESSFUL"},
        {0xc0000002, "NOT IMPLEMENTED"},
        {0xc0000003, "INVALID INFO CLASS"},
        {0xc0000004, "INFO LENGTH MISMATCH"},
        {0xc0000005, "ACCESS VIOLATION"},
        {0xc0000006, "IN PAGE ERROR"},
        {0xc0000008, "INVALID HANDLE"},
        {0xc000000d, "INVALID PARAMETER"},
        {0xc000000e, "NO SUCH DEVICE"},
        {0xc000000f, "NO SUCH FILE"},
        {0xc0000010, "INVALID DEVICE REQUEST"},
        {0xc0000011, "END OF FILE"},
        {0xc0000012, "WRONG VOLUME"},
        {0xc0000013, "NO MEDIA"},
        {0xc0000015, "NONEXISTENT SECTOR"},
        {0xc0000017, "NO MEMORY"},
        {0xc0000021, "ALREADY COMMITED"},
        {0xc0000022, "ACCESS DENIED"},
        {0xc0000023, "BUFFER TOO SMALL"},
        {0xc0000024, "OBJECT TYPE MISMATCH"},
        {0xc0000032, "DISK CORRUPT"},
        {0xc0000033, "NAME INVALID"},
        {0xc0000034, "NAME NOT FOUND"},
        {0xc0000035, "NAME COLLISION"},
        {0xc0000039, "OBJECT PATH INVALID"},
        {0xc000003a, "PATH NOT FOUND"},
        {0xc000003b, "PATH SYNTAX BAD"},
        {0xc000003c, "DATA OVERRUN"},
        {0xc000003f, "CRC ERROR"},
        {0xc0000043, "SHARING VIOLATION"},
        {0xc0000044, "QUOTA EXCEEDED"},
        {0xc000004f, "EAS NOT SUPPORTED"},
        {0xc0000050, "EA TOO LARGE"},
        {0xc0000051, "NONEXISTENT EA ENTRY"},
        {0xc0000052, "NO EAS ON FILE"},
        {0xc0000053, "EA CORRUPTED ERROR"},
        {0xc0000054, "FILE LOCK CONFLICT"},
        {0xc0000055, "NOT GRANTED"},
        {0xc0000056, "DELETE PENDING"},
        {0xc0000061, "PRIVILEGE NOT HELD"},
        {0xc000006d, "LOGON FAILURE"},
        {0xc000007e, "RANGE NOT LOCKED"},
        {0xc000007f, "DISK FULL"},
        {0xc0000098, "FILE INVALID"},
        {0xc000009a, "INSUFFICIENT RESOURCES"},
        {0xc000009c, "DEVICE DATA ERROR"},
        {0xc000009d, "DEVICE NOT CONNECTED"},
        {0xc00000a2, "MEDIA WRITE PROTECTED"},
        {0xc00000a5, "BAD IMPERSONATION"},
        {0xc00000ab, "INSTANCE NOT AVAILABLE"},
        {0xc00000ac, "PIPE NOT AVAILABLE"},
        {0xc00000ad, "INVALID PIPE STATE"},
        {0xc00000ae, "PIPE BUSY"},
        {0xc00000b0, "PIPE DISCONNECTED"},
        {0xc00000b1, "PIPE CLOSING"},
        {0xc00000b2, "PIPE CONNECTED"},
        {0xc00000b3, "PIPE LISTENING"},
        {0xc00000b4, "INVALID READ MODE"},
        {0xc00000b5, "IO TIMEOUT"},
        {0xc00000ba, "IS DIRECTORY"},
        {0xc00000bb, "NOT SUPPORTED"},
        {0xc00000bd, "DUPLICATE NAME"},
        {0xc00000be, "BAD NETWORK PATH"},
        {0xc00000c1, "BAD NETWORK PATH"},
        {0xc00000c3, "INVALID NETWORK RESPONSE"},
        {0xc00000c4, "NETWORK ERROR"},
        {0xc00000cc, "BAD NETWORK NAME"},
        {0xc00000d4, "BAD NETWORK NAME"},
        {0xc00000d8, "CANT WAIT"},
        {0xc00000d9, "PIPE EMPTY"},
        {0xc00000db, "CSC OBJECT PATH NOT FOUND"},
        {0xc00000e2, "OPLOCK NOT GRANTED"},
        {0xc00000ef, "INVALID PARAMETER 1"},
        {0xc00000f0, "INVALID PARAMETER 2"},
        {0xc00000f1, "INVALID PARAMETER 3"},
        {0xc00000f2, "INVALID PARAMETER 4"},
        {0xc00000fb, "REDIRECTOR NOT STARTED"},
        {0xc0000101, "NOT EMPTY"},
        {0xc0000102, "FILE CORRUPT"},
        {0xc0000103, "NOT A DIRECTORY"},
        {0xc0000107, "FILES OPEN"},
        {0xc000010d, "CANNOT IMPERSONATE"},
        {0xc0000120, "CANCELLED"},
        {0xc0000121, "CANNOT DELETE"},
        {0xc0000123, "FILE DELETED"},
        {0xc0000128, "FILE CLOSED"},
        {0xc000012a, "THREAD NOT IN PROCESS"},
        {0xc0000148, "INVALID LEVEL"},
        {0xc000014b, "PIPE BROKEN"},
        {0xc000014c, "REGISTRY CORRUPT"},
        {0xc000014d, "IO FAILED"},
        {0xc000017c, "KEY DELETED"},
        {0xc0000181, "CHILD MUST BE VOLATILE"},
        {0xc0000184, "INVALID DEVICE STATE"},
        {0xc0000185, "IO DEVICE ERROR"},
        {0xc0000188, "LOG FILE FULL"},
        {0xc000019c, "FS DRIVER REQUIRED"},
        {0xc0000205, "INSUFFICIENT SERVER RESOURCES"},
        {0xc0000207, "INVALID ADDRESS COMPONENT"},
        {0xc000020c, "DISCONNECTED"},
        {0xc0000225, "NOT FOUND"},
        {0xc0000243, "USER MAPPED FILE"},
        {0xc0000248, "LOGIN WKSTA RESTRICTION"},
        {0xc0000257, "PATH NOT COVERED"},
        {0xc000026d, "DFS UNAVAILABLE"},
        {0xc0000273, "NO MORE MATCHES"},
        {0xc0000275, "NOT REPARSE POINT"},
        {0xc00002ea, "CANNOT MAKE"},
        {0xc00002f0, "OBJECTID NOT FOUND"},
        {0xc0000388, "DOWNGRADE DETECTED"},
        {0xc0000425, "HIVE UNLOADED"},
        {0xc0000427, "FILE SYSTEM LIMITATION"},
        {0xc0000463, "DEVICE FEATURE NOT SUPPORTED"},
        {0xc000046d, "OBJECT NOT EXTERNALLY BACKED"},
        {0xc0000909, "CANNOT BREAK OPLOCK"},
        {0xc0190001, "TRANSACTIONAL CONFLICT"},
        {0xc0190002, "INVALID TRANSACTION"},
        {0xc0190003, "TRANSACTION_NOT_ACTIVE"},
        {0xc019003e, "EFS NOT ALLOWED IN TRANSACTION"},
        {0xc019003f, "TRANSACTIONAL OPEN NOT ALLOWED"},
        {0xc0190040, "TRANSACTED MAPPING UNSUPPORTED REMOTE"},
        {0xc0190044, "CANNOT EXECUTE FILE IN TRANSACTION"},
        {0xc0190049, "SPARSE NOT ALLOWED IN TRANSACTION"},
        {0xc000a2a1, "STATUS_OFFLOAD_READ_FLT_NOT_SUPPORTED"},
        {0xc000a2a2, "STATUS_OFFLOAD_WRITE_FLT_NOT_SUPPORTED"},
        {0xc000a2a3, "OFFLOAD READ FILE NOT SUPPORTED"},
        {0xc000a2a4, "OFFLOAD READ FILE NOT SUPPORTED"},
        {0xc01c0004, "FAST IO DISALLOWED"},
    };
}


/* ================================================================
 * Category LUT: (event_class << 16 | op) → category string
 * ================================================================ */

static inline std::unordered_map<uint32_t, std::string>
build_category_lut() {
    std::unordered_map<uint32_t, std::string> lut;

    /* Registry: Read */
    for (uint32_t op : {0u,1u,3u,5u,6u,7u,15u})
        lut[lut_key(pml::EC_REGISTRY, op)] = "Read";
    /* Registry: Write */
    for (uint32_t op : {4u,9u,10u,14u})
        lut[lut_key(pml::EC_REGISTRY, op)] = "Write";
    /* Registry: Write Metadata */
    lut[lut_key(pml::EC_REGISTRY, 8)]  = "Write Metadata";
    lut[lut_key(pml::EC_REGISTRY, 16)] = "Write Metadata";
    /* Registry: Read Metadata */
    lut[lut_key(pml::EC_REGISTRY, 17)] = "Read Metadata";

    /* Filesystem: Read / Write */
    lut[lut_key(pml::EC_FS, 23)] = "Read";   /* ReadFile */
    lut[lut_key(pml::EC_FS, 24)] = "Write";  /* WriteFile */
    /* Filesystem: Read Metadata */
    for (uint32_t op : {25u,40u,27u})
        lut[lut_key(pml::EC_FS, op)] = "Read Metadata";
    /* Filesystem: Write Metadata */
    for (uint32_t op : {26u,41u,28u})
        lut[lut_key(pml::EC_FS, op)] = "Write Metadata";

    return lut;
}
