// dllmain.cpp : Define o ponto de entrada para o aplicativo DLL.
#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <SubAuth.h> //UNICODE_STRING


//Liberar e limpar memrias alocadas comentario esta na funcão LdrLoadDll em baixo 

typedef NTSTATUS(NTAPI* PLdrLoadDll)(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

typedef struct _LDRSTRUCT { // copiado
    PLdrLoadDll LdrLoadDll;
    PUNICODE_STRING ModuleFileName;
    HANDLE ModuleHandle;
} LDRSTRUCT, * PLDRSTRUCT;

LPVOID WriteData(HANDLE hProcess, LPVOID Pointer, SIZE_T size, DWORD flProtect)
{
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, flProtect);
    SIZE_T lpNumberOfBytesWritten;
    WriteProcessMemory(hProcess, lpBaseAddress, Pointer, size, &lpNumberOfBytesWritten);
    return lpBaseAddress;
}

bool ReleaseData(HANDLE hProcess, LPVOID lpAddresses[], size_t length)
{
    bool release = true;

    for (int i = 0; i < length; i++)
    {
        if (lpAddresses[i]) {
            if (!VirtualFreeEx(hProcess, lpAddresses[i], 0, MEM_RELEASE))
                release = false;
        }
    }

    return release;
}

LPCWSTR GetPathNameW(LPCWSTR wPath)
{
    LPCWSTR name = wcsrchr(wPath, L'\\');
    return name ? name + 1 : nullptr;
}

HMODULE GetRemoteModule(const HANDLE hProcess, LPCWSTR modulePath)
{
    DWORD pid = GetProcessId(hProcess);
    LPCWSTR moduleName = GetPathNameW(modulePath);

    if (pid == 0 || !moduleName) return nullptr;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return nullptr;

    HMODULE module = nullptr;

    MODULEENTRY32W mod;
    mod.dwSize = sizeof(mod);

    if (Module32FirstW(hSnapshot, &mod)) {
        do {
            if (_wcsicmp(mod.szModule, moduleName) == 0) {
                module = mod.hModule;
                break;
            }
        } while (Module32NextW(hSnapshot, &mod));
    }

    CloseHandle(hSnapshot);
    return module;
}

HMODULE WINAPI CreateRemote_LdrLoadDll(PLDRSTRUCT ldrStruct) // copiado
{
    ldrStruct->ModuleHandle = NULL;
    ldrStruct->LdrLoadDll(nullptr, 0, ldrStruct->ModuleFileName, &ldrStruct->ModuleHandle);
    return (HMODULE)ldrStruct->ModuleHandle;
}
constexpr DWORD TAM_CREATE_REMOTE_LDRLOAD_DLL = 0x23; // (35 bytes) Tamanho tem que ser pego em release no cheatengine

constexpr DWORD ERROR_REMOTE_PROCESS_WRITE_PATHDLL_FAILED = 0xA; //Erro ao escrever pathDll  no processo
constexpr DWORD ERROR_REMOTE_PROCESS_WRITE_UNICODE_STRING_FAILED = 0xB;
constexpr DWORD ERROR_REMOTE_PROCESS_WRITE_LDRSTRUCT_FAILED = 0xC;
constexpr DWORD ERROR_REMOTE_PROCESS_WRITE_REMOTE_LDRLOADDLL_FAILED = 0xD;
constexpr DWORD ERROR_FUNCTION_ADDRESS_NOT_FOUND = 0xE; // Erro ao encontrar endereço da função
constexpr DWORD ERROR_REMOTE_THREAD_CREATE_FAILED = 0xF; // Erro ao criar Thread remota
constexpr DWORD ERROR_MEMORY_RELEASE_FAILED = 0x10;
constexpr DWORD ERROR_GET_EXIT_CODE_FAILED = 0x11;
constexpr DWORD ERROR_LOADLIBRARY_FAILED = 0x12;
constexpr DWORD ERROR_REMOTE_MODULE_NOT_FOUND = 0x13;

extern "C" __declspec(dllexport)
HMODULE __stdcall LdrLoadDll(HANDLE hProcess, const wchar_t* pathDll, DWORD* errorCode)
{

    //Fechar handle hProcess logo depois de LdrLoadDll no main mesmo, sem ser aqui
    if (!errorCode) return NULL;

    if (!hProcess) {
        *errorCode = ERROR_INVALID_HANDLE;
        return NULL;
    }
    if (!pathDll) {
        *errorCode = ERROR_INVALID_PARAMETER;
        return NULL;
    }

    PWSTR pPathDll = nullptr;
    PUNICODE_STRING pModuleFileName = nullptr;
    PLDRSTRUCT pLdrStruct = nullptr;
    LPTHREAD_START_ROUTINE remoteLdrLoadDll = nullptr;

    *errorCode = 0;
    DWORD exitCode = 0;
    HANDLE hThread = nullptr;
    HMODULE module = nullptr;

    UNICODE_STRING unicodeString;
    unicodeString.Length = wcslen(pathDll) * sizeof(WCHAR);
    unicodeString.MaximumLength = unicodeString.Length + sizeof(WCHAR);
    pPathDll = (PWSTR)WriteData(hProcess, (LPVOID)pathDll, unicodeString.MaximumLength, PAGE_READWRITE);

    if (!pPathDll) { *errorCode = ERROR_REMOTE_PROCESS_WRITE_PATHDLL_FAILED; goto release; }

    unicodeString.Buffer = pPathDll;

    LDRSTRUCT ldrStruct;
    pModuleFileName = (PUNICODE_STRING)WriteData(hProcess, &unicodeString, sizeof(unicodeString), PAGE_READWRITE);

    if (!pModuleFileName) { *errorCode = ERROR_REMOTE_PROCESS_WRITE_UNICODE_STRING_FAILED; goto release; }

    ldrStruct.ModuleFileName = pModuleFileName;
    ldrStruct.LdrLoadDll = (PLdrLoadDll)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");

    if (!ldrStruct.LdrLoadDll) { *errorCode = ERROR_FUNCTION_ADDRESS_NOT_FOUND; goto release; }

    ldrStruct.ModuleHandle = 0;

    pLdrStruct = (PLDRSTRUCT)WriteData(hProcess, &ldrStruct, sizeof(ldrStruct), PAGE_READWRITE);

    if (!pLdrStruct) { *errorCode = ERROR_REMOTE_PROCESS_WRITE_LDRSTRUCT_FAILED; goto release; }

    remoteLdrLoadDll = (LPTHREAD_START_ROUTINE)WriteData(hProcess, &CreateRemote_LdrLoadDll, TAM_CREATE_REMOTE_LDRLOAD_DLL, PAGE_EXECUTE_READWRITE);

    if (!remoteLdrLoadDll) { *errorCode = ERROR_REMOTE_PROCESS_WRITE_REMOTE_LDRLOADDLL_FAILED; goto release; }

    hThread = CreateRemoteThread(hProcess, nullptr, 0, remoteLdrLoadDll, pLdrStruct, 0, nullptr);

    if (!hThread) { *errorCode = ERROR_REMOTE_THREAD_CREATE_FAILED; goto release; }

    WaitForSingleObject(hThread, INFINITE);

    if (!GetExitCodeThread(hThread, &exitCode)) { *errorCode = ERROR_GET_EXIT_CODE_FAILED; goto release; }

    if (exitCode == 0) { *errorCode = ERROR_LOADLIBRARY_FAILED; goto release; }

    module = GetRemoteModule(hProcess, pathDll);
    if (!module) *errorCode = ERROR_REMOTE_MODULE_NOT_FOUND;

release:
    LPVOID lpAddresses[4]{ pPathDll, pModuleFileName, pLdrStruct, remoteLdrLoadDll };

    if (!ReleaseData(hProcess, lpAddresses, 4) && *errorCode == 0) *errorCode = ERROR_MEMORY_RELEASE_FAILED;

    if (hThread) CloseHandle(hThread);

    //Liberar e limpar memorias de ponteiros alocados no processo, porem para isto voce precisa guardar todas as variaveis de ponteiros alocados
    return module;
}

//Liberar e limpar memrias alocadas comentario esta na funcão LdrLoadDll em baixo 


BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// ---------------------------------------------
