#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <winnt.h>

#define Main_Title()                                                    \
    printf("######################################################\n"); \
    printf("##             PE_Analyzer_Tools_v0.2               ##\n"); \
    printf("##                                                  ##\n"); \
    printf("##                            Developed by nam3z1p  ##\n"); \
    printf("##                                         2020.04  ##\n"); \
    printf("######################################################\n");

#define Menu()                                              \
    printf("\n[+] Usage : %s -S[-M] filename \n", argv[0]); \
    printf("\nex) %s -S[-M] test.exe \n", argv[0]);         \
    printf("\n[-S, -M] \n");                                \
    printf("  -S              File Offset Mode\n");         \
    printf("  -M              Memory Image Mode\n");        \
    printf("\n[filename]        Analyzer File Name\n");

typedef struct _PE_Format
{
    DWORD pBaseAddr;
    DWORD dwP_idata_RAW;
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINH;
    PIMAGE_FILE_HEADER pIFH;
    PIMAGE_OPTIONAL_HEADER pIOH;
    PIMAGE_SECTION_HEADER pISH;
    PIMAGE_IMPORT_DESCRIPTOR pIDT;
} PE_Format, *PPE_Format;

PE_Format PF;

#define SAFE_FREE(a) \
    if (a)           \
    {                \
        free(a);     \
        a = NULL;    \
    }

LPTSTR IMAGE_DATA_DIRECTORY_str[] = {
    "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG", "COPYRIGHT", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR"};

void Print_Row_Data(const unsigned char *pstr, DWORD dwRange)
{
    printf("[mAddr]\t\t[Raw Data]\t\t\t[Description]");
    for (int i = 0, j = 0; i < dwRange; i++)
    {
        if (i % 8 == 0)
        {
            printf("\t");
            for (; j < i; j++)
            {
                if (*(pstr + j) == 0x20)
                    printf(" ");
                else if (*(pstr + j) == 0x0A)
                    printf("\\n");
                else if (*(pstr + j) == 0x0D)
                    printf("\\r");
                else if (*(pstr + j) == 0x09)
                    printf("\\t");
                else
                    printf("%c ", *(pstr + j));
            }
            printf("\n0x%X\t", pstr + i);
            j = i;
        }
        printf("%02X ", (int)*(pstr + i));
    }
    printf("\n");
}

void Print_IMAGE_DOS_HEADER(PIMAGE_DOS_HEADER pIDH)
{
    unsigned char str[100] = {0};
    printf("====================IMAGE_DOS_HEADER====================\n");
    memcpy(&str, &pIDH->e_magic, sizeof((*pIDH).e_magic));
    printf("[mAddr]\t\t[pAddr]\t[Data]\t[Description]\n");
    printf("0x%X\t0x%02X\t%04X\te_magic - %s\n", pIDH, (DWORD)pIDH - PF.pBaseAddr, pIDH->e_magic, str);
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIDH->e_lfanew, (DWORD)(&pIDH->e_lfanew) - PF.pBaseAddr, pIDH->e_lfanew, "e_lfanew");
}

void Print_DOS_Stub_Program(PIMAGE_DOS_HEADER pIDH, PIMAGE_NT_HEADERS pINH)
{
    printf("\n====================MS-DOS_Stub_Program====================\n");
    DWORD ms_Stub_Range = (DWORD)(PF.pINH) - (DWORD)(&PF.pIDH->e_lfanew + 1);
    LPTSTR pM_Base = (LPTSTR)(PF.pBaseAddr + sizeof(IMAGE_DOS_HEADER));
    Print_Row_Data(pM_Base, ms_Stub_Range);
}

void Print_IMAGE_NT_HEADER(PIMAGE_NT_HEADERS pINH)
{
    unsigned char str[100] = {0};

    printf("\n===================IMAGE_NT_HEADER===================\n");
    memcpy(&str, &pINH->Signature, sizeof((*pINH).Signature));
    printf("[mAddr]\t\t[pAddr]\t[Data]\t[Description]\n");
    printf("0x%X\t0x%02X\t%04X\tSignature - %s\n", pINH, (DWORD)pINH - PF.pBaseAddr, pINH->Signature, str);
}

void Print_IMAGE_FILE_HEADER(PIMAGE_FILE_HEADER pIFH)
{
    printf("\n===================IMAGE_FILE_HEADER===================\n");
    printf("[mAddr]\t\t[pAddr]\t[Data]\t[Description]\n");
    printf("0x%X\t0x%02X\t%04X\t%s\n", pIFH, (DWORD)pIFH - PF.pBaseAddr, pIFH->Machine, "Machine");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIFH->NumberOfSections, (DWORD)(&pIFH->NumberOfSections) - PF.pBaseAddr, pIFH->NumberOfSections, "Number of Section");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIFH->SizeOfOptionalHeader, (DWORD)(&pIFH->SizeOfOptionalHeader) - PF.pBaseAddr, pIFH->SizeOfOptionalHeader, "Size of Optional Header");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIFH->Characteristics, (DWORD)(&pIFH->Characteristics) - PF.pBaseAddr, pIFH->Characteristics, "Characteristics");
}

void Print_IMAGE_OPTIONAL_HEADER(PIMAGE_OPTIONAL_HEADER pIOH)
{
    printf("\n===================IMAGE_OPTIONAL_HEADER===================\n");

    printf("[mAddr]\t\t[pAddr]\t[Data]\t[Description]\n");
    printf("0x%X\t0x%02X\t%04X\t%s\n", pIOH, (DWORD)pIOH - PF.pBaseAddr, pIOH->Magic, "Magic");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIOH->AddressOfEntryPoint, (DWORD)(&pIOH->AddressOfEntryPoint) - PF.pBaseAddr, pIOH->AddressOfEntryPoint, "Address of Entry Point");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIOH->BaseOfCode, (DWORD)(&pIOH->BaseOfCode) - PF.pBaseAddr, pIOH->BaseOfCode, "Base of Code");
    printf("0x%X\t0x%02X\t%06X\t%s\n", &pIOH->ImageBase, (DWORD)(&pIOH->ImageBase) - PF.pBaseAddr, pIOH->ImageBase, "Image Base");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIOH->SectionAlignment, (DWORD)(&pIOH->SectionAlignment) - PF.pBaseAddr, pIOH->SectionAlignment, "Section Alignment");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIOH->FileAlignment, (DWORD)(&pIOH->FileAlignment) - PF.pBaseAddr, pIOH->FileAlignment, "File Alignemnt");
    printf("0x%X\t0x%02X\t%06X\t%s\n", &pIOH->SizeOfImage, (DWORD)(&pIOH->SizeOfImage) - PF.pBaseAddr, pIOH->SizeOfImage, "Size of Image");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIOH->SizeOfHeaders, (DWORD)(&pIOH->SizeOfHeaders) - PF.pBaseAddr, pIOH->SizeOfHeaders, "Size Of Header");
    printf("0x%X\t0x%02X\t%04X\t%s\n", &pIOH->Subsystem, (DWORD)(&pIOH->Subsystem) - PF.pBaseAddr, pIOH->Subsystem, "Subsystem");

    printf("\n[IMAGE_DATA_DIRECTORY]\n");
    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
    {
        printf("0x%X\t0x%02X\t%04X\t[%d %s] - VirtualAddress\n", &pIOH->DataDirectory[i].VirtualAddress, (DWORD)(&pIOH->DataDirectory[i].VirtualAddress) - PF.pBaseAddr, pIOH->DataDirectory[i].VirtualAddress, i, IMAGE_DATA_DIRECTORY_str[i]);
    }
}

void Print_IMAGE_DIRECTORY_ENTRY_IMPORT(PIMAGE_IMPORT_DESCRIPTOR pIDT)
{
    PIMAGE_THUNK_DATA pIAT;
    PIMAGE_IMPORT_BY_NAME pIIBN;

    printf("\n===================IMAGE_DIRECTORY_ENTRY_IMPORT===================\n");

    printf("[mAddr]\t\t[pAddr]\t[Data]\t[Description]\n");
    for (; pIDT->Name; pIDT++)
    {
        printf("[IMPORT_DLL]\n");
        printf("0x%X\t0x%02X\t%06X\t%s\n", pIDT, (DWORD)pIDT - PF.pBaseAddr, PF.pBaseAddr + pIDT->Name + PF.dwP_idata_RAW, PF.pBaseAddr + pIDT->Name + PF.dwP_idata_RAW);

        pIAT = (PIMAGE_THUNK_DATA)(PF.pBaseAddr + pIDT->FirstThunk + PF.dwP_idata_RAW);

        printf("[IMPORT_FUNCTION]\n");
        for (; pIAT->u1.Function; pIAT++)
        {
            pIIBN = (PIMAGE_IMPORT_BY_NAME)(PF.pBaseAddr + pIAT->u1.AddressOfData + PF.dwP_idata_RAW);

            printf("0x%X\t0x%02X\t%06X\t%s\n", pIIBN, (DWORD)pIIBN - PF.pBaseAddr, PF.pBaseAddr + pIIBN->Name, pIIBN->Name, pIIBN->Name);
        }
        printf("\n");
    }
}

void Print_IMAGE_SECTION(PIMAGE_SECTION_HEADER pISH)
{

    printf("\n===================IMAGE_SECTION===================\n");

    printf("[Section - %s, SizeOfRawData - %06X]\n", pISH->Name, pISH->SizeOfRawData);

    LPTSTR pM_Base;
    DWORD dwSection_Range = pISH->SizeOfRawData;
    dwSection_Range = 80;

    if (PF.dwP_idata_RAW == 0x00)
        pM_Base = (LPTSTR)(PF.pBaseAddr + pISH->VirtualAddress);
    else
        pM_Base = (LPTSTR)(PF.pBaseAddr + pISH->PointerToRawData);

    Print_Row_Data(pM_Base, dwSection_Range);
}

void Print_IMAGE_SECTION_HEADER(PIMAGE_SECTION_HEADER pISH, PIMAGE_FILE_HEADER pIFH)
{
    printf("\n===================IMAGE_SECTION_HEADER===================\n");

    printf("[mAddr]\t\t[pAddr]\t[Data]\t[Description]\n");
    for (int i = 0; i < 3; i++)
    {
        printf("0x%X\t0x%04X\t%04X\t%s\n", pISH + i, (DWORD)(pISH + i) - PF.pBaseAddr, *(pISH + i)->Name, (pISH + i)->Name);
        printf("0x%X\t0x%04X\t%04X\t%s\n", &(pISH + i)->Misc.VirtualSize, (DWORD)(&(pISH + i)->Misc.VirtualSize) - PF.pBaseAddr, (pISH + i)->Misc.VirtualSize, "VirtualSize");
        printf("0x%X\t0x%04X\t%04X\t%s\n", &(pISH + i)->VirtualAddress, (DWORD)(&(pISH + i)->VirtualAddress) - PF.pBaseAddr, (pISH + i)->VirtualAddress, "VirtualAddress");
        printf("0x%X\t0x%04X\t%04X\t%s\n", &(pISH + i)->SizeOfRawData, (DWORD)(&(pISH + i)->SizeOfRawData) - PF.pBaseAddr, (pISH + i)->SizeOfRawData, "SizeOfRawData");
        printf("0x%X\t0x%04X\t%04X\t%s\n", &(pISH + i)->PointerToRawData, (DWORD)(&(pISH + i)->PointerToRawData) - PF.pBaseAddr, (pISH + i)->PointerToRawData, "PointerToRawData");
        printf("0x%X\t0x%04X\t%04X %s\n", &(pISH + i)->Characteristics, (DWORD)(&(pISH + i)->Characteristics) - PF.pBaseAddr, (pISH + i)->Characteristics, "Characteristics");
    }
    Print_IMAGE_SECTION(pISH);
}

BOOL Get_PE_File_Format(LPCTSTR lpTempMemory)
{
    PF.pBaseAddr = (DWORD)lpTempMemory;
    PF.pIDH = (PIMAGE_DOS_HEADER)PF.pBaseAddr;
    PF.pINH = (PIMAGE_NT_HEADERS)(PF.pBaseAddr + PF.pIDH->e_lfanew);
    PF.pIFH = &PF.pINH->FileHeader;
    PF.pIOH = &PF.pINH->OptionalHeader;
    PF.pISH = (PIMAGE_SECTION_HEADER)(PF.pBaseAddr + PF.pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    for (int i = 0; i < PF.pIFH->NumberOfSections; i++)
    {
        if (!strcmp((PF.pISH + i)->Name, ".idata"))
        {
            PF.dwP_idata_RAW = -(PF.pISH + i)->VirtualAddress + (PF.pISH + i)->PointerToRawData;
        }
    }

    PF.pIDT = (PIMAGE_IMPORT_DESCRIPTOR)(PF.pBaseAddr + PF.pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + PF.dwP_idata_RAW);

    if (PF.pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("It's not PE File format.\n");
        return 0;
    }

    printf("\npBaseAddr %X\n", PF.pBaseAddr);
    printf("pIDH %X\n", PF.pIDH);
    printf("pINH %X\n", PF.pINH);
    printf("pIDT %X\n\n", PF.pIDT);

    Print_IMAGE_DOS_HEADER(PF.pIDH);
    Print_DOS_Stub_Program(PF.pIDH, PF.pINH);
    Print_IMAGE_NT_HEADER(PF.pINH);
    Print_IMAGE_FILE_HEADER(PF.pIFH);
    Print_IMAGE_OPTIONAL_HEADER(PF.pIOH);
    Print_IMAGE_SECTION_HEADER(PF.pISH, PF.pIFH);
    Print_IMAGE_DIRECTORY_ENTRY_IMPORT(PF.pIDT);

    return TRUE;
}

BOOL Init_PE_Static(LPCTSTR szFilePath)
{
    FILE *pFile = NULL;
    unsigned char *pTempMemory = NULL;
    DWORD dwFSize = 0;
    pFile = fopen(szFilePath, "rb");
    if (!pFile)
        return FALSE;
    fseek(pFile, 0, SEEK_END);
    dwFSize = ftell(pFile);
    rewind(pFile);

    pTempMemory = (char *)calloc(dwFSize, sizeof(char));
    if (pTempMemory == 0)
        return FALSE;
    if (fread(pTempMemory, dwFSize, 1, pFile) == dwFSize)
        return FALSE;
    fclose(pFile);
    if (!Get_PE_File_Format(pTempMemory))
        return FALSE;

    SAFE_FREE(pTempMemory);

    return TRUE;
}

BOOL Get_PE_Memory_Format(LPCTSTR szFilePath)
{
    HMODULE hModule = NULL;

    if ((hModule = LoadLibrary(szFilePath)) == NULL)
        printf("[!] GetModuleHandle failed (%d)\n", GetLastError());

    PF.pBaseAddr = (DWORD)hModule;
    PF.pIDH = (PIMAGE_DOS_HEADER)PF.pBaseAddr;
    PF.pINH = (PIMAGE_NT_HEADERS)(PF.pBaseAddr + PF.pIDH->e_lfanew);
    PF.pIFH = &PF.pINH->FileHeader;
    PF.pIOH = &PF.pINH->OptionalHeader;
    PF.pISH = (PIMAGE_SECTION_HEADER)(PF.pBaseAddr + PF.pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    PF.pIDT = (PIMAGE_IMPORT_DESCRIPTOR)(PF.pBaseAddr + PF.pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    PF.dwP_idata_RAW = 0x00;

    if (PF.pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("It's not PE File format.\n");
        return 0;
    }

    printf("\npBaseAddr %X\n", PF.pBaseAddr);
    printf("pIDH %X\n", PF.pIDH);
    printf("pINH %X\n", PF.pINH);
    printf("pIDT %X\n\n", PF.pIDT);

    Print_IMAGE_DOS_HEADER(PF.pIDH);
    Print_DOS_Stub_Program(PF.pIDH, PF.pINH);
    Print_IMAGE_NT_HEADER(PF.pINH);
    Print_IMAGE_FILE_HEADER(PF.pIFH);
    Print_IMAGE_OPTIONAL_HEADER(PF.pIOH);
    Print_IMAGE_SECTION_HEADER(PF.pISH, PF.pIFH);
    Print_IMAGE_DIRECTORY_ENTRY_IMPORT(PF.pIDT);

    FreeLibrary(hModule);
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        Menu();
        return 0;
    }
    else
        Main_Title();

    LPTSTR szFilePath = (LPTSTR)calloc(20, sizeof(LPTSTR));
    snprintf(szFilePath, strlen(argv[2]) + 1, argv[2]);

    if (!strcmp(argv[1], "-M"))
    {
        printf("[+] Analyzer [%s]\n", argv[2]);
        if (Get_PE_Memory_Format(szFilePath) == 0)
            return 0;
    }
    else if (!strcmp(argv[1], "-S"))
    {
        printf("[+] Analyzer [%s]\n", argv[2]);
        if (Init_PE_Static(szFilePath) == 0)
            return 0;
    }
    else
    {
        Menu();
        return 0;
    }

    free(szFilePath);
    printf("[+] Done\n");
    return 0;
}
