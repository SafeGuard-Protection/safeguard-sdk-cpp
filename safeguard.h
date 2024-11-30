/*
 * Copyright (c) 2024 SafeGuard Software Protection. All rights reserved.
 *
 * This code is proprietary and confidential. Unauthorized copying, use,
 * distribution, or modification of this code, via any medium, is strictly prohibited.
 * Violators will be prosecuted to the fullest extent of the law.
*/

#ifndef SAFEGUARD_H
#define SAFEGUARD_H

#include <windows.h>
#include <iostream>
#include <unordered_map>

// Define a structure to hold function RVAs
struct FunctionRVA {
    const char* name;        // Function name
    uintptr_t rva;           // Relative Virtual Address
};

// Array of all function RVAs
static const FunctionRVA g_FunctionRVAs[] = {
    {"initialize", 0xe0ae40},
    {"authenticateUser", 0x3880},
    {"registerUser", 0x46b0},
    {"downloadFile", 0x1a090},
    {"injectFile", 0xe0de50},
    {"retrieveVariable", 0xe0ff70},
    {"getKeyLevel", 0xe22760},
    {"getKeyExpiry", 0xe22770},
    {"getFileContent", 0xe22740},
    {"getLastError", 0xe22720},
};

namespace SafeGuard {

    class Loader {
    public:
        Loader(const char* dllName) : hModule(nullptr) {
            hModule = LoadLibraryA(dllName);
            if (!hModule) {
            }
            else {
                baseAddress = reinterpret_cast<uintptr_t>(hModule);
                ResolveAllFunctions();
            }
        }

        ~Loader() {
            if (hModule) {
                FreeLibrary(hModule);
            }
        }

        // Function pointer types
        typedef void (*InitializeFunction)(const char* sdkKey1);
        typedef bool (*AuthenticateUserFunction)(const char* username);
        typedef bool (*RegisterUserFunction)(const char* username, const char* license);
        typedef bool (*DownloadFileFunction)(const char* file);
        typedef bool (*InjectFileFunction)(const char* file, const char* program);
        typedef const char* (*RetrieveVariableFunction)(const char* name);
        typedef int (*GetKeyLevelFunction)();
        typedef const char* (*GetKeyExpiryFunction)();
        typedef uint8_t* (*GetFileContentFunction)(int* length);
        typedef const char* (*GetLastErrorFunction)();

        // Function pointers
        InitializeFunction initialize;
        AuthenticateUserFunction authenticateUser;
        RegisterUserFunction registerUser;
        DownloadFileFunction downloadFile;
        InjectFileFunction injectFile;
        RetrieveVariableFunction retrieveVariable;
        GetKeyLevelFunction getKeyLevel;
        GetKeyExpiryFunction getKeyExpiry;
        GetFileContentFunction getFileContent;
        GetLastErrorFunction getLastError;

    private:
        HMODULE hModule;
        uintptr_t baseAddress;

        void* GetFunctionAddress(uintptr_t rva) {
            return reinterpret_cast<void*>(baseAddress + rva);
        }

        void ResolveAllFunctions() {
            for (const auto& func : g_FunctionRVAs) {
                void* addr = GetFunctionAddress(func.rva);
                if (!addr) {
                    continue;
                }

                // Assign to the appropriate function pointer
                if (strcmp(func.name, "initialize") == 0) {
                    initialize = reinterpret_cast<InitializeFunction>(addr);
                }
                else if (strcmp(func.name, "authenticateUser") == 0) {
                    authenticateUser = reinterpret_cast<AuthenticateUserFunction>(addr);
                }
                else if (strcmp(func.name, "registerUser") == 0) {
                    registerUser = reinterpret_cast<RegisterUserFunction>(addr);
                }
                else if (strcmp(func.name, "downloadFile") == 0) {
                    downloadFile = reinterpret_cast<DownloadFileFunction>(addr);
                }
                else if (strcmp(func.name, "injectFile") == 0) {
                    injectFile = reinterpret_cast<InjectFileFunction>(addr);
                }
                else if (strcmp(func.name, "retrieveVariable") == 0) {
                    retrieveVariable = reinterpret_cast<RetrieveVariableFunction>(addr);
                }
                else if (strcmp(func.name, "getKeyLevel") == 0) {
                    getKeyLevel = reinterpret_cast<GetKeyLevelFunction>(addr);
                }
                else if (strcmp(func.name, "getKeyExpiry") == 0) {
                    getKeyExpiry = reinterpret_cast<GetKeyExpiryFunction>(addr);
                }
                else if (strcmp(func.name, "getFileContent") == 0) {
                    getFileContent = reinterpret_cast<GetFileContentFunction>(addr);
                }
                else if (strcmp(func.name, "getLastError") == 0) {
                    getLastError = reinterpret_cast<GetLastErrorFunction>(addr);
                }
            }
        }
    };

} // namespace SafeGuard

#endif // SAFEGUARD_H