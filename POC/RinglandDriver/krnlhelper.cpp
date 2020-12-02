#include "krnlhelper.h"
#include "log.h"

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;
PSYSTEM_SERVICE_DESCRIPTOR_TABLE g_SSDT = NULL;

DYNAMIC_DATA dynData;

NTSTATUS GetBuildNO(OUT PULONG pBuildNo)
{
    ASSERT(pBuildNo != NULL);
    if (pBuildNo == NULL)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING strRegKey = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");
    UNICODE_STRING strRegValue = RTL_CONSTANT_STRING(L"BuildLabEx");
    UNICODE_STRING strRegValue10 = RTL_CONSTANT_STRING(L"UBR");
    UNICODE_STRING strVerVal = { 0 };
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES keyAttr = { 0 };

    InitializeObjectAttributes(&keyAttr, &strRegKey, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_READ, &keyAttr);
    if (NT_SUCCESS(status))
    {
        PKEY_VALUE_FULL_INFORMATION pValueInfo = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, PAGE_SIZE, BB_POOL_TAG);
        ULONG bytes = 0;

        if (pValueInfo)
        {
            // Try query UBR value
            status = ZwQueryValueKey(hKey, &strRegValue10, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status))
            {
                *pBuildNo = *(PULONG)((PUCHAR)pValueInfo + pValueInfo->DataOffset);
                goto skip1;
            }

            status = ZwQueryValueKey(hKey, &strRegValue, KeyValueFullInformation, pValueInfo, PAGE_SIZE, &bytes);
            if (NT_SUCCESS(status))
            {
                PWCHAR pData = (PWCHAR)((PUCHAR)pValueInfo->Name + pValueInfo->NameLength);
                for (ULONG i = 0; i < pValueInfo->DataLength; i++)
                {
                    if (pData[i] == L'.')
                    {
                        for (ULONG j = i + 1; j < pValueInfo->DataLength; j++)
                        {
                            if (pData[j] == L'.')
                            {
                                strVerVal.Buffer = &pData[i] + 1;
                                strVerVal.Length = strVerVal.MaximumLength = (USHORT)((j - i) * sizeof(WCHAR));
                                status = RtlUnicodeStringToInteger(&strVerVal, 10, pBuildNo);

                                goto skip1;
                            }
                        }
                    }
                }

            skip1:;
            }

            ExFreePoolWithTag(pValueInfo, BB_POOL_TAG);
        }
        else
            status = STATUS_NO_MEMORY;

        ZwClose(hKey);
    }
    else
        log("ZwOpenKey failed.");

    return status;

}

NTSTATUS InitDynamicData(IN OUT PDYNAMIC_DATA pData)
{
    NTSTATUS status = STATUS_SUCCESS;
    RTL_OSVERSIONINFOEXW verInfo = { 0 };

    if (pData == NULL)
        return STATUS_INVALID_ADDRESS;

    RtlZeroMemory(pData, sizeof(DYNAMIC_DATA));
    pData->DYN_PDE_BASE = PDE_BASE;
    pData->DYN_PTE_BASE = PTE_BASE;

    verInfo.dwOSVersionInfoSize = sizeof(verInfo);
    status = RtlGetVersion((PRTL_OSVERSIONINFOW)&verInfo);

    if (status == STATUS_SUCCESS)
    {
        ULONG ver_short = (verInfo.dwMajorVersion << 8) | (verInfo.dwMinorVersion << 4) | verInfo.wServicePackMajor;
        pData->ver = (WinVer)ver_short;

        // Get kernel build number
        status = GetBuildNO(&pData->buildNo);

        // Validate current driver version
        pData->correctBuild = TRUE;
#if defined(_WIN7_)
        if (ver_short != WINVER_7 && ver_short != WINVER_7_SP1)
            return STATUS_NOT_SUPPORTED;
#elif defined(_WIN8_)
        if (ver_short != WINVER_8)
            return STATUS_NOT_SUPPORTED;
#elif defined (_WIN81_)
        if (ver_short != WINVER_81)
            return STATUS_NOT_SUPPORTED;
#elif defined (_WIN10_)
        if (ver_short < WINVER_10 || WINVER_10_RS7 < ver_short)
            return STATUS_NOT_SUPPORTED;
#endif

        log(
            "OS version %d.%d.%d.%d.%d - 0x%x",
            verInfo.dwMajorVersion,
            verInfo.dwMinorVersion,
            verInfo.dwBuildNumber,
            verInfo.wServicePackMajor,
            pData->buildNo,
            ver_short
        );

        switch (ver_short)
        {
            // Windows 10, build 16299/15063/14393/10586
        case WINVER_10:
            if (verInfo.dwBuildNumber == 10586)
            {
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6B2;
                pData->EProcessFlags2 = 0x300;
                pData->ObjTable = 0x418;
                pData->VadRoot = 0x610;
                pData->NtCreateThdIndex = 0xB4;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x6E0;
                pData->MiAllocPage = 0;
                break;
            }
            else if (verInfo.dwBuildNumber == 14393)
            {
                pData->ver = WINVER_10_RS1;
                pData->KExecOpt = 0x1BF;
                pData->Protection = pData->buildNo >= 447 ? 0x6CA : 0x6C2;
                pData->EProcessFlags2 = 0x300;
                pData->ObjTable = 0x418;
                pData->VadRoot = 0x620;
                pData->NtCreateThdIndex = 0xB6;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x6F0;
                pData->MiAllocPage = 0;
                break;
            }
            else if (verInfo.dwBuildNumber == 15063)
            {
                pData->ver = WINVER_10_RS2;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x300;
                pData->ObjTable = 0x418;
                pData->VadRoot = 0x628;
                pData->NtCreateThdIndex = 0xB9;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x6F8;
                pData->MiAllocPage = 0;
                break;
            }
            else if (verInfo.dwBuildNumber == 16299)
            {
                pData->ver = WINVER_10_RS3;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x828;    // MitigationFlags offset
                pData->ObjTable = 0x418;
                pData->VadRoot = 0x628;
                pData->NtCreateThdIndex = 0xBA;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x700;
                pData->MiAllocPage = 0;
                break;
            }
            else if (verInfo.dwBuildNumber == 17134)
            {
                pData->ver = WINVER_10_RS4;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x828;    // MitigationFlags offset
                pData->ObjTable = 0x418;
                pData->VadRoot = 0x628;
                pData->NtCreateThdIndex = 0xBB;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x700;
                pData->MiAllocPage = 0;
                break;
            }
            else if (verInfo.dwBuildNumber == 17763)
            {
                pData->ver = WINVER_10_RS5;
                pData->KExecOpt = 0x1BF;
                pData->Protection = 0x6CA;
                pData->EProcessFlags2 = 0x820;    // MitigationFlags offset
                pData->ObjTable = 0x418;
                pData->VadRoot = 0x628;
                pData->NtCreateThdIndex = 0xBC;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x700;
                pData->MiAllocPage = 0;
                break;
            }
            else if (verInfo.dwBuildNumber == 18362 || verInfo.dwBuildNumber == 18363)
            {
                pData->ver = verInfo.dwBuildNumber == 18362 ? WINVER_10_RS6 : WINVER_10_RS7;
                pData->KExecOpt = 0x1C3;
                pData->Protection = 0x6FA;
                pData->EProcessFlags2 = 0x850;    // MitigationFlags offset
                pData->ObjTable = 0x418;
                pData->VadRoot = 0x658;
                pData->NtCreateThdIndex = 0xBD;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x710;
                pData->MiAllocPage = 0;
                break;
            }
            else
            {
                pData->KExecOpt = 0x283;
                pData->Protection = 0x87A;
                pData->EProcessFlags2 = 0x9D4;
                pData->ObjTable = 0x570;
                pData->VadRoot = 0x7D8;
                pData->NtCreateThdIndex = 0xC1;
                pData->NtTermThdIndex = 0x53;
                pData->PrevMode = 0x232;
                pData->ExitStatus = 0x6E0;
                pData->MiAllocPage = 0;
                break;
            }
        default:
            break;
        }
    }

    return status;
}

NTSTATUS UtilSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
    NT_ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
    if (ppFound == NULL || pattern == NULL || base == NULL)
        return STATUS_INVALID_PARAMETER;

    __try
    {
        for (ULONG_PTR i = 0; i < size - len; i++)
        {
            BOOLEAN found = TRUE;
            for (ULONG_PTR j = 0; j < len; j++)
            {
                if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
                {
                    found = FALSE;
                    break;
                }
            }

            if (found != FALSE)
            {
                *ppFound = (PUCHAR)base + i;
                return STATUS_SUCCESS;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_UNHANDLED_EXCEPTION;
    }

    return STATUS_NOT_FOUND;
}

PVOID UtilKernelBase(OUT PULONG pSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytes = 0;
    PRTL_PROCESS_MODULES pMods = NULL;
    PVOID checkPtr = NULL;
    UNICODE_STRING routineName;

    // Already found
    if (g_KernelBase != NULL)
    {
        if (pSize)
            *pSize = g_KernelSize;
        return g_KernelBase;
    }

    RtlInitUnicodeString(&routineName, L"NtOpenFile");

    checkPtr = MmGetSystemRoutineAddress(&routineName);
    if (checkPtr == NULL)
        return NULL;

    // Protect from UserMode AV
    __try
    {
        status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
        if (bytes == 0)
        {
            log("Error: Invalid SystemModuleInformation size");
            return NULL;
        }

        pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPoolNx, bytes, HB_POOL_TAG);
        RtlZeroMemory(pMods, bytes);

        status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

        if (NT_SUCCESS(status))
        {
            PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

            for (ULONG i = 0; i < pMods->NumberOfModules; i++)
            {
                // System routine is inside module
                if (checkPtr >= pMod[i].ImageBase &&
                    checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
                {
                    g_KernelBase = pMod[i].ImageBase;
                    g_KernelSize = pMod[i].ImageSize;
                    if (pSize)
                        *pSize = g_KernelSize;
                    break;
                }
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        log("Exception");
    }

    if (pMods)
        ExFreePoolWithTag(pMods, HB_POOL_TAG);

    return g_KernelBase;
}

PSYSTEM_SERVICE_DESCRIPTOR_TABLE UtilSSDTBase()
{
    PUCHAR ntosBase = (PUCHAR)UtilKernelBase(NULL);

    // Already found
    if (g_SSDT != NULL)
        return g_SSDT;

    if (!ntosBase)
        return NULL;

    PIMAGE_NT_HEADERS pHdr = RtlImageNtHeader(ntosBase);
    PIMAGE_SECTION_HEADER pFirstSec = (PIMAGE_SECTION_HEADER)(pHdr + 1);
    for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + pHdr->FileHeader.NumberOfSections; pSec++)
    {
        if (pSec->Characteristics & IMAGE_SCN_MEM_NOT_PAGED &&
            pSec->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
            !(pSec->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
            (*(PULONG)pSec->Name != 'TINI') &&
            (*(PULONG)pSec->Name != 'EGAP'))
        {
            PVOID pFound = NULL;

            // KiSystemServiceRepeat pattern
            UCHAR pattern[] = "\x4c\x8d\x15\xcc\xcc\xcc\xcc\x4c\x8d\x1d\xcc\xcc\xcc\xcc\xf7";
            NTSTATUS status = UtilSearchPattern(pattern, 0xCC, sizeof(pattern) - 1, ntosBase + pSec->VirtualAddress, pSec->Misc.VirtualSize, &pFound);
            if (NT_SUCCESS(status))
            {
                g_SSDT = (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)((PUCHAR)pFound + *(PULONG)((PUCHAR)pFound + 3) + 7);
                return g_SSDT;
            }
            else
                log("Pattern scan for KiSystemServiceRepeat failed!");
        }
    }

    return NULL;
}

PVOID GetSSDTEntry(IN ULONG index)
{
    ULONG size = 0;
    PSYSTEM_SERVICE_DESCRIPTOR_TABLE pSSDT = UtilSSDTBase();
    PVOID pBase = UtilKernelBase(&size);

    if (pSSDT && pBase)
    {
        // Index range check
        if (index > pSSDT->NumberOfServices)
            return NULL;

        return (PUCHAR)pSSDT->ServiceTableBase + (((PLONG)pSSDT->ServiceTableBase)[index] >> 4);
    }

    return NULL;
}

NTSTATUS
NTAPI
ZwCreateThreadEx(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList
)
{
    NTSTATUS status = STATUS_SUCCESS;

    fnNtCreateThreadEx NtCreateThreadEx = (fnNtCreateThreadEx)(ULONG_PTR)GetSSDTEntry(dynData.NtCreateThdIndex);
    if (NtCreateThreadEx)
    {

        status = NtCreateThreadEx(
            hThread, DesiredAccess, ObjectAttributes,
            ProcessHandle, lpStartAddress, lpParameter,
            Flags, StackZeroBits, SizeOfStackCommit,
            SizeOfStackReserve, AttributeList
        );
    }
    else
        status = STATUS_NOT_FOUND;

    return status;
}

//NTSTATUS NTAPI ZwTerminateThread(
//    IN HANDLE ThreadHandle,
//    IN NTSTATUS ExitStatus
//)
//{
//    NTSTATUS status = STATUS_SUCCESS;
//
//    fnNtTerminateThread NtTerminateThread = (fnNtTerminateThread)(ULONG_PTR)GetSSDTEntry(dynData.NtTermThdIndex);
//    if (NtTerminateThread)
//    {
//        status = NtTerminateThread(ThreadHandle, ExitStatus);
//    }
//    else
//        status = STATUS_NOT_FOUND;
//
//    return status;
//}
