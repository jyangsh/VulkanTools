/*
 * Copyright (c) 2016 Valve Corporation
 * Copyright (c) 2016 LunarG, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Author: Mark Young <marky@lunarg.com>
 */

#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <time.h>
#include <inttypes.h>

#define VALIDATOR_MAJOR_VERSION 1
#define VALIDATOR_MINOR_VERSION 0

#ifdef _WIN32
#pragma warning(disable : 4996)
#else
#include <stdlib.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <unistd.h>
#endif

#include <json/json.h>

#include <vulkan/vulkan.h>

enum ElementAlign { ALIGN_LEFT = 0, ALIGN_CENTER, ALIGN_RIGHT };

struct PhysicalDeviceInfo {
    VkPhysicalDevice vulkan_phys_dev;
    std::vector<VkQueueFamilyProperties> queue_fam_props;
};

struct GlobalItems {
    std::ofstream html_file_stream;
    bool sdk_found;
    std::string sdk_path;
    VkInstance instance;
    std::vector<PhysicalDeviceInfo> phys_devices;
    std::vector<VkDevice> log_devices;

#ifdef _WIN32
    bool is_wow64;
#endif
};

GlobalItems global_items = {};

void StartOutput(std::string title);
void EndOutput();
void PrintSystemInfo(void);
void PrintVulkanInfo(void);
void PrintDriverInfo(void);
void PrintRunTimeInfo(void);
void PrintSDKInfo(void);
void PrintExplicitLayerJsonInfo(const char *layer_json_filename, Json::Value root,
                                uint32_t num_cols);
void PrintImplicitLayerJsonInfo(const char *layer_json_filename, Json::Value root);
void PrintLayerInfo(void);
void PrintLayerSettingsFileInfo(void);
void PrintTestResults(void);
std::string TrimWhitespace(const std::string &str,
                           const std::string &whitespace = " \t\n\r");

int main(int argc, char **argv) {
    int err_val = 0;
    try {
        time_t time_raw_format;
        struct tm *ptr_time;
        char html_file_name[256];
        char full_file[512];
        bool generate_unique_file = false;

        if (argc > 1) {
            for (int iii = 1; iii < argc; iii++) {
                if (0 == strcmp("--unique_output", argv[iii])) {
                    generate_unique_file = true;
                } else {
                    std::cout << "Usage of vkvalidator.exe:" << std::endl
                              << "    vkvalidator.exe [--unique_output]"
                              << std::endl
                              << "          [--unique_output] Optional "
                                 "parameter to generate a unique html"
                              << std::endl
                              << "                            output file"
                                 "in the form of "
                                 "\'vkvalidator_YYYY_MM_DD_HH_MM.html\'"
                              << std::endl;
                    throw -1;
                }
            }
        }

        if (generate_unique_file) {
            time(&time_raw_format);
            ptr_time = localtime(&time_raw_format);
            if (strftime(html_file_name, 256, "vkvalidator_%Y_%m_%d_%H_%M.html",
                         ptr_time) == 0) {
                std::cerr << "Couldn't prepare formatted string" << std::endl;
                throw -1;
            }
        } else {
            strcpy(html_file_name, "vkvalidator.html");
        }

        global_items.html_file_stream.open(html_file_name);
        if (global_items.html_file_stream.fail()) {
// Try again in home folder
#ifdef _WIN32
            char home_drive[32];
            char home_path[256];
            if (0 != GetEnvironmentVariableA("HOMEDRIVE", home_drive, 31) ||
                0 != GetEnvironmentVariableA("HOMEPATH", home_path, 255)) {
                std::cerr << "Error failed to get either HOMEDRIVE or HOMEPATH "
                             "from environment settings!"
                          << std::endl;
                throw -1;
            }
            sprintf(full_file, "%s%s\\%s", home_drive, home_path,
                    html_file_name);
#else
            sprintf(full_file, "~/%s", html_file_name);
#endif
            global_items.html_file_stream.open(full_file);
            if (global_items.html_file_stream.fail()) {
                std::cerr << "Error failed opening html file stream to "
                             "either current"
                             " folder as "
                          << html_file_name << " or home folder as "
                          << full_file << std::endl;
                throw -1;
            }
        }

        StartOutput("LunarG Vulkan Validator");

        PrintSystemInfo();
        PrintVulkanInfo();
        PrintTestResults();
        EndOutput();
    } catch (int e) {
        std::cout << "ERROR: Failures occurred during validation" << std::endl;
        err_val = e;
    }
    global_items.html_file_stream.close();

    if (err_val == 0) {
        std::cout << "SUCCESS: Validation completed properly" << std::endl;
    }
    return err_val;
}

// Output helper functions:
//=============================
void StartOutput(std::string output) {
    global_items.html_file_stream << "<!DOCTYPE html>" << std::endl;
    global_items.html_file_stream << "<HTML lang=\"en\" xml:lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\">" << std::endl;
    global_items.html_file_stream << std::endl
                                    << "<HEAD>" << std::endl
                                    << "    <TITLE>" << output << "</TITLE>"
                                    << std::endl;

    global_items.html_file_stream
        << "    <META charset=\"UTF-8\">" << std::endl
        << "    <style class=\"cp-pen-styles\">" << std::endl
        << "        table {" << std::endl
        << "            width: 750px;" << std::endl
        << "            border-collapse: collapse;" << std::endl
        << "        }" << std::endl
        << "        th {" << std::endl
        << "            background: #3498db;" << std::endl
        << "            color: white;" << std::endl
        << "            font-weight: bold;" << std::endl
        << "        }" << std::endl
        << "        td, th {" << std::endl
        << "            padding: 10px;" << std::endl
        << "            border: 1px solid #ccc;" << std::endl
        << "            font-size: 18px;" << std::endl
        << "        }" << std::endl
        << "    </style>" << std::endl
        << "    <script src=\"https://ajax.googleapis.com/ajax/libs/jquery/"
        << "2.2.4/jquery.min.js\"></script>" << std::endl
        << "    <script type=\"text/javascript\">" << std::endl
        << "        $( document ).ready(function() {" << std::endl
        << "            $('table tr:not(.header)').hide();" << std::endl
        << "            $('.header').click(function() {" << std::endl
        << "                "
            "$(this).nextUntil('tr.header').slideToggle(300);"
        << std::endl
        << "            });" << std::endl
        << "        });" << std::endl
        << "    </script>" << std::endl
        << "</HEAD>" << std::endl
        << std::endl
        << "<BODY background=\"star_field.png\">" << std::endl
        << "    <H1 style=\"font-size:300%;text-align:center;\"><font "
            "color=\"blue\">"
        << output << std::endl
        << "</font></H1>" << std::endl
        << std::endl
        << "    <br />" << std::endl;
}

void EndOutput() {
    global_items.html_file_stream << "</BODY>" << std::endl
                                    << std::endl
                                    << "</HTML>" << std::endl;
}

void BeginSection(std::string section) {
    global_items.html_file_stream << "    <H1><font color=\"white\">" << section << "</font></H1>"
                                    << std::endl
                                    << "    <HR/>" << std::endl;
}

void EndSection() {
    global_items.html_file_stream << "    <BR/>" << std::endl;
}

void BeginSubSection(std::string section) {
    global_items.html_file_stream << "    <H2>" << section << "</H2>"
                                    << std::endl;
}

void PrintError(std::string error) {
    global_items.html_file_stream << std::endl
                                    << "    <b><font color=\"red\">" << error
                                    << "</font></b>" << std::endl;
}

void PrintBeginCollapsableInfo(std::string summary) {
    global_items.html_file_stream << "    <DETAILS>" << std::endl
                                    << "        <SUMMARY>" << summary
                                    << "</SUMMARY>" << std::endl;
}

void PrintEndCollapsableInfo() {
    global_items.html_file_stream << "    </DETAILS>" << std::endl;
}

void PrintBeginTable(const char *color, const char *table_name,
                     uint32_t num_cols) {
    global_items.html_file_stream
        << "    <table align=\"center\">" << std::endl
        << "        <tr class=\"header\" bgcolor=\"" << color << "\">"
        << std::endl
        << "            <td colspan=\"" << num_cols << "\" >" << table_name
        << "</td>" << std::endl
        << "         </tr>" << std::endl;
}

void PrintBeginTableRow() {
    global_items.html_file_stream << "        <tr bgcolor=\"CornSilk\">" << std::endl;
}

void PrintTableElement(std::string element, ElementAlign align = ALIGN_LEFT) {
    if (align == ALIGN_RIGHT) {
        global_items.html_file_stream << "            <td align=\"right\">"
                                        << element << "</td>" << std::endl;
    } else {
        global_items.html_file_stream << "            <td>" << element
                                        << "</td>" << std::endl;
    }
}

void PrintEndTableRow() {
    global_items.html_file_stream << "        </tr>" << std::endl;
}

void PrintEndTable() {
    global_items.html_file_stream << "    </table>" << std::endl;
}

bool GenerateLibraryPath(const char *json_location, const char *library_info,
                         const uint32_t max_length, char *library_location) {
    bool success = false;
    char final_path[512];
    char *working_string_ptr;
    uint32_t len = (max_length > 512) ? 512 : max_length;

    if (NULL == json_location || NULL == library_info ||
        NULL == library_location) {
        goto out;
    }

    // Remove json file from json location
    strncpy(final_path, json_location, len);
    working_string_ptr = strrchr(final_path, '\\');
    if (working_string_ptr == NULL) {
        working_string_ptr = strrchr(final_path, '/');
    }
    if (working_string_ptr != NULL) {
        working_string_ptr++;
        *working_string_ptr = '\0';
    }

    // Determine if the library is relative or absolute
    if (library_info[0] == '\\' || library_info[0] == '/' ||
        library_info[1] == ':') {
        // Absolute path
        strncpy(library_location, library_info, len);
        success = true;
    } else {
        uint32_t i = 0;
        // Relative path
        while (library_info[i] == '.' && library_info[i + 1] == '.' &&
               (library_info[i + 2] == '\\' || library_info[i + 2] == '/')) {
            i += 3;
            // Go up a folder in the json path
            working_string_ptr = strrchr(final_path, '\\');
            if (working_string_ptr == NULL) {
                working_string_ptr = strrchr(final_path, '/');
            }
            if (working_string_ptr != NULL) {
                working_string_ptr++;
                *working_string_ptr = '\0';
            }
        }
        while (library_info[i] == '.' &&
               (library_info[i + 1] == '\\' || library_info[i + 1] == '/')) {
            i += 2;
        }
        strcpy(library_location, final_path);
        strncat(library_location, &library_info[i], len);
        success = true;
    }

out:
    return success;
}

#ifdef _WIN32

const char g_uninstall_reg_path[] =
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

bool ReadRegKeyString(HKEY regFolder, const char *keyPath,
                      const char *valueName, const int maxLength,
                      char *retString) {
    bool retVal = false;
    DWORD bufLen = maxLength;
    DWORD keyFlags = KEY_READ;
    HKEY hKey;
    LONG lret;

    if (global_items.is_wow64) {
        keyFlags |= KEY_WOW64_64KEY;
    }

    *retString = '\0';
    lret = RegOpenKeyExA(regFolder, keyPath, 0, keyFlags, &hKey);
    if (lret == ERROR_SUCCESS) {
        lret = RegQueryValueExA(hKey, valueName, NULL, NULL, (BYTE *)retString,
                                &bufLen);
        if (lret == ERROR_SUCCESS) {
            retVal = true;
        }
        RegCloseKey(hKey);
    }

    return retVal;
}

bool WriteRegKeyString(HKEY regFolder, const char *keyPath, char *valueName,
                       char *valueValue) {
    bool retVal = false;
    DWORD keyFlags = KEY_WRITE;
    HKEY hKey;
    LONG lret;

    if (global_items.is_wow64) {
        keyFlags |= KEY_WOW64_64KEY;
    }

    lret = RegOpenKeyExA(regFolder, keyPath, 0, keyFlags, &hKey);
    if (lret == ERROR_SUCCESS) {
        lret = RegSetKeyValueA(hKey, NULL, valueName, REG_SZ,
                               (BYTE *)valueValue, (DWORD)(strlen(valueValue)));
        if (lret == ERROR_SUCCESS) {
            retVal = true;
        }
        RegCloseKey(hKey);
    }

    return retVal;
}

bool DeleteRegKeyString(HKEY regFolder, const char *keyPath, char *valueName) {
    bool retVal = false;
    DWORD keyFlags = KEY_WRITE;
    HKEY hKey;
    LONG lret;

    if (global_items.is_wow64) {
        keyFlags |= KEY_WOW64_64KEY;
    }

    lret = RegOpenKeyExA(regFolder, keyPath, 0, keyFlags, &hKey);
    if (lret == ERROR_SUCCESS) {
        lret = RegDeleteKeyValueA(hKey, NULL, valueName);
        if (lret == ERROR_SUCCESS) {
            retVal = true;
        }
        RegCloseKey(hKey);
    }

    return retVal;
}

bool ReadRegKeyDword(HKEY regFolder, const char *keyPath, const char *valueName,
                     unsigned int *returnInt) {
    bool retVal = false;
    DWORD bufLen = sizeof(DWORD);
    DWORD keyFlags = KEY_READ;
    HKEY hKey;
    LONG lret;

    if (global_items.is_wow64) {
        keyFlags |= KEY_WOW64_64KEY;
    }

    *returnInt = 0;
    lret = RegOpenKeyExA(regFolder, keyPath, 0, keyFlags, &hKey);
    if (lret == ERROR_SUCCESS) {
        lret = RegQueryValueExA(hKey, valueName, NULL, NULL, (BYTE *)returnInt,
                                &bufLen);
        if (lret == ERROR_SUCCESS) {
            retVal = true;
        }
        RegCloseKey(hKey);
    }

    return retVal;
}

bool FindNextRegKey(HKEY regFolder, const char *keyPath, const char *keySearch,
                    const int itemIndex, const int maxLength, char *retString) {
    bool retVal = false;
    DWORD bufLen = MAX_PATH;
    DWORD keyFlags = KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE;
    HKEY hKey;
    LONG lret;
    int itemCount = 0;

    if (global_items.is_wow64) {
        keyFlags |= KEY_WOW64_64KEY;
    }

    *retString = '\0';
    lret = RegOpenKeyExA(regFolder, keyPath, 0, keyFlags, &hKey);
    if (lret == ERROR_SUCCESS) {
        DWORD index = 0;
        char keyName[MAX_PATH];

        do {
            lret = RegEnumKeyExA(hKey, index, keyName, &bufLen, NULL, NULL,
                                 NULL, NULL);
            if (ERROR_SUCCESS != lret) {
                break;
            }
            if (strlen(keySearch) == 0 || NULL != strstr(keyName, keySearch)) {
                if (itemIndex == itemCount) {
                    strncpy_s(retString, maxLength, keyName, bufLen);
                    retVal = true;
                    break;
                } else {
                    itemCount++;
                }
            }
            bufLen = MAX_PATH;
            ++index;
        } while (true);
    }

    return retVal;
}

bool FindNextRegValue(HKEY regFolder, const char *keyPath,
                      const char *valueSearch, const int startIndex,
                      const int maxLength, char *retString) {
    bool retVal = false;
    DWORD bufLen = MAX_PATH;
    DWORD keyFlags = KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE;
    HKEY hKey;
    LONG lret;

    if (global_items.is_wow64) {
        keyFlags |= KEY_WOW64_64KEY;
    }

    *retString = '\0';
    lret = RegOpenKeyExA(regFolder, keyPath, 0, keyFlags, &hKey);
    if (lret == ERROR_SUCCESS) {
        DWORD index = startIndex;
        char valueName[MAX_PATH];

        do {
            lret = RegEnumValueA(hKey, index, valueName, &bufLen, NULL, NULL,
                                 NULL, NULL);
            if (ERROR_SUCCESS != lret) {
                break;
            }
            if (strlen(valueSearch) == 0 ||
                NULL != strstr(valueName, valueSearch)) {
                strncpy_s(retString, maxLength, valueName, bufLen);
                retVal = true;
                break;
            }
            bufLen = MAX_PATH;
            ++index;
        } while (true);
    }

    return retVal;
}

// Registry prototypes for Windows
bool ReadRegKeyDword(HKEY regFolder, const char *keyPath, const char *valueName,
                     unsigned int *returnInt);
bool ReadRegKeyString(HKEY regFolder, const char *keyPath,
                      const char *valueName, const int maxLength,
                      char *retString);
bool FindNextRegKey(HKEY regFolder, const char *keyPath, const char *keySearch,
                    const int startIndex, const int maxLength, char *retString);
bool FindNextRegValue(HKEY regFolder, const char *keyPath,
                      const char *valueSearch, const int startIndex,
                      const int maxLength, char *retString);
bool WriteRegKeyString(HKEY regFolder, const char *keyPath, char *valueName,
                       char *valueValue);
bool DeleteRegKeyString(HKEY regFolder, const char *keyPath, char *valueName);

// Functionality to determine if this 32-bit process is running on Windows 64.
//
void IsWow64() {
    typedef BOOL(WINAPI * LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);

    // IsWow64Process is not available on all supported versions of Windows.
    // Use GetModuleHandle to get a handle to the DLL that contains the function
    // and GetProcAddress to get a pointer to the function if available.

    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
        GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (NULL != fnIsWow64Process) {
        BOOL isWOW = FALSE;
        if (!fnIsWow64Process(GetCurrentProcess(), &isWOW)) {
            printf("Error : Failed to determine properly if on Win64!");
        }

        if (isWOW == TRUE) {
            global_items.is_wow64 = true;
        }
    }
}

int RunTestInDirectory(std::string path, std::string test) {
    int err_code = -1;
    char orig_dir[1024];
    orig_dir[0] = '\0';
    if (0 != GetCurrentDirectoryA(1023, orig_dir) &&
        TRUE == SetCurrentDirectoryA(path.c_str())) {
        if (0 == system(test.c_str())) {
            err_code = 0;
        }
        SetCurrentDirectoryA(orig_dir);
    }
    return err_code;
}

void PrintSystemInfo(void) {
    OSVERSIONINFOEX os_info;
    SYSTEM_INFO sys_info;
    MEMORYSTATUSEX mem_stat;
    DWORD ser_ver = 0;
    DWORD sect_per_cluster = 0;
    DWORD bytes_per_sect = 0;
    DWORD num_free_cluster = 0;
    DWORD total_num_cluster = 0;
    char generic_string[1024];
    char output_string[256];
    char system_root_dir[256];
    char os_size[32];

    // Determine if this 32-bit process is on Win64.
    IsWow64();

#if _WIN64
    strcpy(os_size, " 64-bit");
#else
    if (global_items.is_wow64) {
        strcpy(os_size, " 32-bit");
    } else {
        strcpy(os_size, " 64-bit");
    }
#endif

    BeginSection("System Info");

    ZeroMemory(&sys_info, sizeof(SYSTEM_INFO));
    GetSystemInfo(&sys_info);

    ZeroMemory(&os_info, sizeof(OSVERSIONINFOEX));
    os_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    ZeroMemory(&mem_stat, sizeof(MEMORYSTATUSEX));
    mem_stat.dwLength = sizeof(MEMORYSTATUSEX);

    PrintBeginTable("DodgerBlue", "OS", 3);
    if (TRUE == GetVersionEx((LPOSVERSIONINFO)(&os_info))) {
        switch (os_info.dwMajorVersion) {
        case 10:
            if (os_info.wProductType == VER_NT_WORKSTATION) {
                if (ReadRegKeyString(
                        HKEY_LOCAL_MACHINE,
                        "Software\\Microsoft\\Windows NT\\CurrentVersion",
                        "ProductName", 256, generic_string)) {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement(generic_string);
                    PrintTableElement(os_size);
                    PrintEndTableRow();

                    if (ReadRegKeyString(
                            HKEY_LOCAL_MACHINE,
                            "Software\\Microsoft\\Windows NT\\CurrentVersion",
                            "CurrentBuild", 256, output_string)) {
                        PrintBeginTableRow();
                        PrintTableElement("");
                        PrintTableElement("Build");
                        PrintTableElement(output_string);
                        PrintEndTableRow();
                        if (ReadRegKeyString(
                                HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windo"
                                                    "ws NT\\CurrentVersion",
                                "BuildBranch", 256, output_string)) {
                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("Branch");
                            PrintTableElement(output_string);
                            PrintEndTableRow();
                        }
                    }
                } else {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement("Windows 10 (or newer)");
                    PrintTableElement(os_size);
                    PrintEndTableRow();
                }
            } else {
                PrintBeginTableRow();
                PrintTableElement("Windows");
                PrintTableElement("Windows Server 2016 (or newer)");
                PrintTableElement(os_size);
                PrintEndTableRow();
            }
            break;
        case 6:
            switch (os_info.dwMinorVersion) {
            case 3:
                if (os_info.wProductType == VER_NT_WORKSTATION) {
                    if (ReadRegKeyString(
                            HKEY_LOCAL_MACHINE,
                            "Software\\Microsoft\\Windows NT\\CurrentVersion",
                            "ProductName", 256, generic_string)) {
                        PrintBeginTableRow();
                        PrintTableElement("Windows");
                        PrintTableElement(generic_string);
                        PrintTableElement(os_size);
                        PrintEndTableRow();

                        if (ReadRegKeyString(
                                HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windo"
                                                    "ws NT\\CurrentVersion",
                                "CurrentBuild", 256, output_string)) {
                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("Build");
                            PrintTableElement(output_string);
                            PrintEndTableRow();

                            if (ReadRegKeyString(HKEY_LOCAL_MACHINE,
                                                 "Software\\Microsoft\\Windo"
                                                 "ws NT\\CurrentVersion",
                                                 "BuildBranch", 256,
                                                 output_string)) {
                                PrintBeginTableRow();
                                PrintTableElement("");
                                PrintTableElement("Branch");
                                PrintTableElement(output_string);
                                PrintEndTableRow();
                            }
                        }
                    }
                } else {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement("Windows Server 2012 R2 (or newer)");
                    PrintTableElement(os_size);
                    PrintEndTableRow();
                }
                break;
            case 2:
                if (os_info.wProductType == VER_NT_WORKSTATION) {
                    if (ReadRegKeyString(
                            HKEY_LOCAL_MACHINE,
                            "Software\\Microsoft\\Windows NT\\CurrentVersion",
                            "ProductName", 256, generic_string)) {
                        PrintBeginTableRow();
                        PrintTableElement("Windows");
                        PrintTableElement(generic_string);
                        PrintTableElement(os_size);
                        PrintEndTableRow();

                        if (ReadRegKeyString(
                                HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windo"
                                                    "ws NT\\CurrentVersion",
                                "CurrentBuild", 256, output_string)) {
                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("Build");
                            PrintTableElement(output_string);
                            PrintEndTableRow();
                            if (ReadRegKeyString(HKEY_LOCAL_MACHINE,
                                                 "Software\\Microsoft\\Windo"
                                                 "ws NT\\CurrentVersion",
                                                 "BuildBranch", 256,
                                                 output_string)) {
                                PrintBeginTableRow();
                                PrintTableElement("");
                                PrintTableElement("Branch");
                                PrintTableElement(output_string);
                                PrintEndTableRow();
                            }
                        }
                    }
                } else {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement("Windows Server 2012 (or newer)");
                    PrintTableElement(os_size);
                    PrintEndTableRow();
                }
                break;
            case 1:
                if (os_info.wProductType == VER_NT_WORKSTATION) {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement("Windows 7 (or newer)");
                    PrintTableElement(os_size);
                    PrintEndTableRow();
                } else {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement("Windows Server 2008 R2 (or newer)");
                    PrintTableElement(os_size);
                    PrintEndTableRow();
                }
                break;
            default:
                if (os_info.wProductType == VER_NT_WORKSTATION) {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement("Windows Vista (or newer)");
                    PrintTableElement(os_size);
                    PrintEndTableRow();
                } else {
                    PrintBeginTableRow();
                    PrintTableElement("Windows");
                    PrintTableElement("Windows Server 2008 (or newer)");
                    PrintTableElement(os_size);
                    PrintEndTableRow();
                }
                break;
            }
            break;
        case 5:
            ser_ver = GetSystemMetrics(SM_SERVERR2);
            switch (os_info.dwMinorVersion) {
            case 2:
                if ((os_info.wProductType == VER_NT_WORKSTATION) &&
                    (sys_info.wProcessorArchitecture ==
                     PROCESSOR_ARCHITECTURE_AMD64)) {
                    sprintf(generic_string, "Windows XP Professional x64");
                } else if (os_info.wSuiteMask & VER_SUITE_WH_SERVER) {
                    sprintf(generic_string, "Windows Home Server");
                } else if (ser_ver != 0) {
                    sprintf(generic_string, "Windows Server 2003 R2");
                } else {
                    sprintf(generic_string, "Windows Server 2003");
                }
                PrintBeginTableRow();
                PrintTableElement("Windows");
                PrintTableElement(generic_string);
                PrintTableElement(os_size);
                PrintEndTableRow();
                break;
            case 1:
                PrintBeginTableRow();
                PrintTableElement("Windows");
                PrintTableElement("Windows XP");
                PrintTableElement(os_size);
                PrintEndTableRow();
                break;
            case 0:
                PrintBeginTableRow();
                PrintTableElement("Windows");
                PrintTableElement("Windows 2000");
                PrintTableElement(os_size);
                PrintEndTableRow();
                break;
            default:
                PrintBeginTableRow();
                PrintTableElement("Windows");
                PrintTableElement("Unknown Windows OS");
                PrintTableElement(os_size);
                PrintEndTableRow();
                break;
            }
            break;
        }
    } else {
        PrintError("Error attempting to retrieve Windows Version info");
        throw -1;
    }

    if (0 != GetEnvironmentVariableA("SYSTEMROOT", system_root_dir, 255)) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("System Root");
        PrintTableElement(system_root_dir);
        PrintEndTableRow();
    }
    if (0 != GetEnvironmentVariableA("PROGRAMDATA", generic_string, 1023)) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Program Data");
        PrintTableElement(generic_string);
        PrintEndTableRow();
    }
    if (0 != GetEnvironmentVariableA("PROGRAMFILES", generic_string, 1023)) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Program Files");
        PrintTableElement(generic_string);
        PrintEndTableRow();
    }
    if (0 != GetEnvironmentVariableA("PROGRAMFILES(X86)", generic_string, 1023)) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Program Files (x86)");
        PrintTableElement(generic_string);
        PrintEndTableRow();
    }
    if (0 != GetEnvironmentVariableA("TEMP", generic_string, 1023)) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("TEMP");
        PrintTableElement(generic_string);
        PrintEndTableRow();
    }
    if (0 != GetEnvironmentVariableA("TMP", generic_string, 1023)) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("TMP");
        PrintTableElement(generic_string);
        PrintEndTableRow();
    }

    PrintEndTable();

    PrintBeginTable("LimeGreen", "Hardware", 3);

    sprintf(generic_string, "%u", sys_info.dwNumberOfProcessors);
    PrintBeginTableRow();
    PrintTableElement("CPUs");
    PrintTableElement("Number of Logical Cores");
    PrintTableElement(generic_string);
    PrintEndTableRow();

    switch (sys_info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Type");
        PrintTableElement("x86_64");
        PrintEndTableRow();
        break;
    case PROCESSOR_ARCHITECTURE_ARM:
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Type");
        PrintTableElement("ARM");
        PrintEndTableRow();
        break;
    case PROCESSOR_ARCHITECTURE_IA64:
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Type");
        PrintTableElement("IA64");
        PrintEndTableRow();
        break;
    case PROCESSOR_ARCHITECTURE_INTEL:
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Type");
        PrintTableElement("x86");
        PrintEndTableRow();
        break;
    default:
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Type");
        PrintTableElement("Unknown");
        PrintEndTableRow();
        break;
    }

    if (TRUE == GlobalMemoryStatusEx(&mem_stat)) {
        if ((mem_stat.ullTotalPhys >> 40) > 0x0ULL) {
            sprintf(generic_string, "%u TB",
                    static_cast<uint32_t>(mem_stat.ullTotalPhys >> 40));
            PrintBeginTableRow();
            PrintTableElement("Memory");
            PrintTableElement("Physical");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((mem_stat.ullTotalPhys >> 30) > 0x0ULL) {
            sprintf(generic_string, "%u GB",
                    static_cast<uint32_t>(mem_stat.ullTotalPhys >> 30));
            PrintBeginTableRow();
            PrintTableElement("Memory");
            PrintTableElement("Physical");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((mem_stat.ullTotalPhys >> 20) > 0x0ULL) {
            sprintf(generic_string, "%u MB",
                    static_cast<uint32_t>(mem_stat.ullTotalPhys >> 20));
            PrintBeginTableRow();
            PrintTableElement("Memory");
            PrintTableElement("Physical");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((mem_stat.ullTotalPhys >> 10) > 0x0ULL) {
            sprintf(generic_string, "%u KB",
                    static_cast<uint32_t>(mem_stat.ullTotalPhys >> 10));
            PrintBeginTableRow();
            PrintTableElement("Memory");
            PrintTableElement("Physical");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else {
            sprintf(generic_string, "%u bytes",
                    static_cast<uint32_t>(mem_stat.ullTotalPhys));
            PrintBeginTableRow();
            PrintTableElement("Memory");
            PrintTableElement("Physical");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        }
    }

    if (TRUE == GetDiskFreeSpaceA(NULL, &sect_per_cluster, &bytes_per_sect,
                                  &num_free_cluster, &total_num_cluster)) {
        uint64_t bytes_free = (uint64_t)bytes_per_sect *
                              (uint64_t)sect_per_cluster *
                              (uint64_t)num_free_cluster;
        uint64_t bytes_total = (uint64_t)bytes_per_sect *
                               (uint64_t)sect_per_cluster *
                               (uint64_t)total_num_cluster;
        double perc_free = (double)bytes_free / (double)bytes_total;
        if ((bytes_total >> 40) > 0x0ULL) {
            sprintf(generic_string, "%u TB",
                    static_cast<uint32_t>(bytes_total >> 40));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Total");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((bytes_total >> 30) > 0x0ULL) {
            sprintf(generic_string, "%u GB",
                    static_cast<uint32_t>(bytes_total >> 30));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Total");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((bytes_total >> 20) > 0x0ULL) {
            sprintf(generic_string, "%u MB",
                    static_cast<uint32_t>(bytes_total >> 20));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Total");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((bytes_total >> 10) > 0x0ULL) {
            sprintf(generic_string, "%u KB",
                    static_cast<uint32_t>(bytes_total >> 10));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Total");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        }
        sprintf(output_string, "%4.2f%%",
                (static_cast<float>(perc_free) * 100.f));
        if ((bytes_free >> 40) > 0x0ULL) {
            sprintf(generic_string, "%u TB",
                    static_cast<uint32_t>(bytes_free >> 40));
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free Perc");
            PrintTableElement(output_string);
            PrintEndTableRow();
        } else if ((bytes_free >> 30) > 0x0ULL) {
            sprintf(generic_string, "%u GB",
                    static_cast<uint32_t>(bytes_free >> 30));
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free Perc");
            PrintTableElement(output_string);
            PrintEndTableRow();
        } else if ((bytes_free >> 20) > 0x0ULL) {
            sprintf(generic_string, "%u MB",
                    static_cast<uint32_t>(bytes_free >> 20));
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free Perc");
            PrintTableElement(output_string);
            PrintEndTableRow();
        } else if ((bytes_free >> 10) > 0x0ULL) {
            sprintf(generic_string, "%u KB",
                    static_cast<uint32_t>(bytes_free >> 10));
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Free Perc");
            PrintTableElement(output_string);
            PrintEndTableRow();
        }
    }

    PrintEndTable();

    PrintBeginTable("Peru", "Executable", 2);

    if (0 != GetCurrentDirectoryA(1023, generic_string)) {
        PrintBeginTableRow();
        PrintTableElement("Current Directory");
        PrintTableElement(generic_string);
        PrintEndTableRow();
    }

    sprintf(generic_string, "%d.%d", VALIDATOR_MAJOR_VERSION, VALIDATOR_MINOR_VERSION);
    PrintBeginTableRow();
    PrintTableElement("App Version");
    PrintTableElement(generic_string);
    PrintEndTableRow();

    uint32_t major = VK_VERSION_MAJOR(VK_API_VERSION_1_0);
    uint32_t minor = VK_VERSION_MINOR(VK_API_VERSION_1_0);
    uint32_t patch = VK_VERSION_PATCH(VK_HEADER_VERSION);

    PrintBeginTableRow();
    PrintTableElement("Vulkan API Version");
    PrintTableElement(generic_string);
    PrintEndTableRow();

    PrintBeginTableRow();
    PrintTableElement("Executable Format");
#if _WIN64 || __x86_64__ || __ppc64__
    PrintTableElement("64-bit");
#else
    PrintTableElement("32-bit");
#endif
    PrintEndTableRow();

    PrintEndTable();

    PrintDriverInfo();
    PrintRunTimeInfo();
    PrintSDKInfo();
    PrintLayerInfo();
    PrintLayerSettingsFileInfo();
    EndSection();
}

bool GetFileVersion(const char *filename, const uint32_t max_len,
                    char *version_string) {
    DWORD ver_handle;
    UINT size = 0;
    LPBYTE buffer = NULL;
    DWORD ver_size = GetFileVersionInfoSize(filename, &ver_handle);
    bool success = false;

    if (ver_size > 0) {
        LPSTR ver_data = (LPSTR)malloc(sizeof(char) * ver_size);

        if (GetFileVersionInfo(filename, ver_handle, ver_size, ver_data)) {
            if (VerQueryValue(ver_data, "\\", (VOID FAR * FAR *)&buffer,
                              &size)) {
                if (size) {
                    VS_FIXEDFILEINFO *ver_info = (VS_FIXEDFILEINFO *)buffer;
                    if (ver_info->dwSignature == 0xfeef04bd) {
                        DWORD max_size =
                            ver_size > max_len ? max_len : ver_size;
                        snprintf(version_string, max_len, "%d.%d.%d.%d",
                                 (ver_info->dwFileVersionMS >> 16) & 0xffff,
                                 (ver_info->dwFileVersionMS >> 0) & 0xffff,
                                 (ver_info->dwFileVersionLS >> 16) & 0xffff,
                                 (ver_info->dwFileVersionLS >> 0) & 0xffff);
                        success = true;
                    }
                }
            }
        }
        free(ver_data);
    }

    return success;
}

void PrintDriverInfo(void) {
    bool failed = false;
    const char vulkan_reg_base[] = "SOFTWARE\\Khronos\\Vulkan";
    const char vulkan_reg_base_wow64[] =
        "SOFTWARE\\WOW6432Node\\Khronos\\Vulkan";
    char vulkan_driver_reg_key[512];
    char cur_vulkan_driver_json[512];
    char generic_string[512];
    char full_driver_path[512];
    uint32_t i = 0;
    uint32_t j = 0;
    std::ifstream *stream = NULL;

#if _WIN64 || __x86_64__ || __ppc64__
    sprintf(vulkan_driver_reg_key, "%s\\Drivers", vulkan_reg_base);
#else
    if (global_items.is_wow64) {
        sprintf(vulkan_driver_reg_key, "%s\\Drivers", vulkan_reg_base_wow64);
    } else {
        sprintf(vulkan_driver_reg_key, "%s\\Drivers", vulkan_reg_base);
    }
#endif

    PrintBeginTable("Tomato", "Vulkan Driver Info", 3);
    PrintBeginTableRow();
    PrintTableElement("Registry Location");
    PrintTableElement(vulkan_driver_reg_key);
    PrintTableElement("");
    PrintEndTableRow();

    while (FindNextRegValue(HKEY_LOCAL_MACHINE, vulkan_driver_reg_key, "", i,
                            512, cur_vulkan_driver_json)) {

        sprintf(generic_string, "Driver %d", i++);

        PrintBeginTableRow();
        PrintTableElement(generic_string, ALIGN_RIGHT);
        PrintTableElement(cur_vulkan_driver_json);
        PrintTableElement("");
        PrintEndTableRow();

        std::ifstream *stream = NULL;
        stream = new std::ifstream(cur_vulkan_driver_json, std::ifstream::in);
        if (nullptr == stream || stream->fail()) {
            sprintf(generic_string, "Error reading file %s!\n",
                    cur_vulkan_driver_json);
            PrintError(generic_string);
            failed = true;
            continue;
        } else {
            Json::Value root = Json::nullValue;
            Json::Reader reader;
            if (!reader.parse(*stream, root, false) || root.isNull()) {
                PrintError(reader.getFormattedErrorMessages());
                failed = true;
                stream->close();
                delete stream;
                continue;
            } else {
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("JSON File Version");
                if (!root["file_format_version"].isNull()) {
                    PrintTableElement(root["file_format_version"].asString());
                } else {
                    PrintTableElement("MISSING!");
                }
                PrintEndTableRow();

                if (!root["ICD"].isNull()) {
                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("API Version");
                    if (!root["ICD"]["api_version"].isNull()) {
                        PrintTableElement(
                            root["ICD"]["api_version"].asString());
                    } else {
                        PrintTableElement("MISSING!");
                    }
                    PrintEndTableRow();

                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("Library Path");
                    if (!root["ICD"]["library_path"].isNull()) {
                        PrintTableElement(
                            root["ICD"]["library_path"].asString());
                        PrintEndTableRow();

                        if (GenerateLibraryPath(
                                cur_vulkan_driver_json,
                                root["ICD"]["library_path"].asString().c_str(),
                                512, full_driver_path) &&
                            GetFileVersion(full_driver_path, 256,
                                           generic_string)) {

                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("Library File Version");
                            PrintTableElement(generic_string);
                            PrintEndTableRow();
                        }
                    } else {
                        PrintTableElement("MISSING!");
                        PrintEndTableRow();
                    }

                    char count_str[256];
                    j = 0;
                    Json::Value dev_exts = root["ICD"]["device_extensions"];
                    if (!dev_exts.isNull() && dev_exts.isArray()) {
                        sprintf(count_str, "%d", dev_exts.size());
                        PrintBeginTableRow();
                        PrintTableElement("");
                        PrintTableElement("Device Extensions");
                        PrintTableElement(count_str);
                        PrintEndTableRow();

                        for (Json::ValueIterator dev_ext_it = dev_exts.begin();
                             dev_ext_it != dev_exts.end(); dev_ext_it++) {
                            Json::Value dev_ext = (*dev_ext_it);
                            Json::Value dev_ext_name = dev_ext["name"];
                            if (!dev_ext_name.isNull()) {
                                sprintf(generic_string, "[%d]", j);

                                PrintBeginTableRow();
                                PrintTableElement("");
                                PrintTableElement(generic_string, ALIGN_RIGHT);
                                PrintTableElement(dev_ext_name.asString());
                                PrintEndTableRow();
                            }
                        }
                    }
                    Json::Value inst_exts = root["ICD"]["instance_extensions"];
                    j = 0;
                    if (!inst_exts.isNull() && inst_exts.isArray()) {
                        sprintf(count_str, "%d", inst_exts.size());
                        PrintBeginTableRow();
                        PrintTableElement("");
                        PrintTableElement("Instance Extensions");
                        PrintTableElement(count_str);
                        PrintEndTableRow();

                        for (Json::ValueIterator inst_ext_it =
                                 inst_exts.begin();
                             inst_ext_it != inst_exts.end(); inst_ext_it++) {
                            Json::Value inst_ext = (*inst_ext_it);
                            Json::Value inst_ext_name = inst_ext["name"];
                            if (!inst_ext_name.isNull()) {
                                sprintf(generic_string, "[%d]", j);

                                PrintBeginTableRow();
                                PrintTableElement("");
                                PrintTableElement(generic_string, ALIGN_RIGHT);
                                PrintTableElement(inst_ext_name.asString());
                                PrintEndTableRow();
                            }
                        }
                    }
                } else {
                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("ICD Section");
                    PrintTableElement("MISSING!");
                    PrintEndTableRow();
                }
            }

            stream->close();
            delete stream;
            stream = NULL;
        }
    }

    PrintEndTable();

    if (failed) {
        throw -1;
    }
}

void PrintRunTimeInfo(void) {
    char system_root_dir[256];
    char vulkan_dll_used[256];
    char key_name[256];
    char reg_key_path[256];
    char installed_string[256];
    char version_string[256];
    char output_string[256];
    uint32_t i = 0;
    uint32_t install_count = 0;
    FILE *fp = NULL;

    PrintBeginTable("Gold", "Vulkan Runtimes", 3);

    GetEnvironmentVariableA("SYSTEMROOT", system_root_dir, 255);

    PrintBeginTableRow();
    PrintTableElement("Runtimes In Registry");
    PrintTableElement(g_uninstall_reg_path);
    PrintTableElement("");
    PrintEndTableRow();
    while (FindNextRegKey(HKEY_LOCAL_MACHINE, g_uninstall_reg_path, "VulkanRT",
                          i, 256, key_name)) {
        sprintf(installed_string, "[%d]", i++);

        sprintf(reg_key_path, "%s\\%s", g_uninstall_reg_path, key_name);
        if (ReadRegKeyString(HKEY_LOCAL_MACHINE, reg_key_path, "DisplayVersion",
                             256, version_string)) {
        } else {
            strcpy(version_string, key_name);
        }

        if (ReadRegKeyDword(HKEY_LOCAL_MACHINE, reg_key_path, "InstallCount",
                            &install_count)) {
            sprintf(output_string, "%s  [Install Count = %d]", version_string,
                    install_count);
        } else {
            sprintf(output_string, "%s", version_string);
        }
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement(installed_string, ALIGN_RIGHT);
        PrintTableElement(output_string);
        PrintEndTableRow();
    }

    i = 0;
    char dll_search[512];
    char dll_prefix[512];
#if _WIN64 || __x86_64__ || __ppc64__
    sprintf(dll_prefix, "%s\\system32\\", system_root_dir);
#else
    if (global_items.is_wow64) {
        sprintf(dll_prefix, "%s\\sysWOW64\\", system_root_dir);
    } else {
        sprintf(dll_prefix, "%s\\system32\\", system_root_dir);
    }
#endif

    PrintBeginTableRow();
    PrintTableElement("Runtimes in System Folder");
    PrintTableElement(dll_prefix);
    PrintTableElement("");
    PrintEndTableRow();

    strncpy(dll_search, dll_prefix, 512);
    strncat(dll_search, "Vulkan-*.dll", 512);

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(dll_search, &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (0 == (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                sprintf(installed_string, "DLL %d", i++);

                PrintBeginTableRow();
                PrintTableElement(installed_string, ALIGN_RIGHT);
                PrintTableElement(ffd.cFileName);

                sprintf(vulkan_dll_used, "%s\\%s", dll_prefix, ffd.cFileName);
                if (GetFileVersion(vulkan_dll_used, 256, version_string)) {
                    sprintf(installed_string, "Version %s", version_string);
                    PrintTableElement(installed_string);
                } else {
                    PrintTableElement("");
                }
                PrintEndTableRow();
            }
        } while (FindNextFileA(hFind, &ffd) != 0);
        FindClose(hFind);
    }

    PrintBeginTableRow();
    PrintTableElement("Runtime Used by App");
    if (!system("where vulkan-1.dll > where_vulkan")) {
        fp = fopen("where_vulkan", "rt");
        if (NULL != fp) {
            if (NULL != fgets(vulkan_dll_used, 256, fp)) {
                int i = (int)strlen(vulkan_dll_used) - 1;
                while (
                    vulkan_dll_used[i] == '\n' || vulkan_dll_used[i] == '\r' ||
                    vulkan_dll_used[i] == '\t' || vulkan_dll_used[i] == ' ') {
                    vulkan_dll_used[i] = '\0';
                    i--;
                }

                if (GetFileVersion(vulkan_dll_used, 256, version_string)) {
                    PrintTableElement(vulkan_dll_used);
                    PrintTableElement(version_string);
                } else {
                    PrintTableElement(vulkan_dll_used);
                    PrintTableElement("");
                }
            }
            fclose(fp);
        }
    } else {
        PrintTableElement("Unknown");
        PrintTableElement("Unknown");
    }
    PrintEndTableRow();

    PrintEndTable();
}

void PrintSDKInfo(void) {
    const char vulkan_reg_base[] = "SOFTWARE\\Khronos\\Vulkan";
    const char vulkan_reg_base_wow64[] =
        "SOFTWARE\\WOW6432Node\\Khronos\\Vulkan";
    char key_name[256];
    char reg_key_path[256];
    char installed_string[256];
    char location_string[256];
    char vulkan_expl_layer_reg_key[512];
    char cur_vulkan_layer_json[512];
    char generic_string[512];
    uint32_t i = 0;
    uint32_t j = 0;
    FILE *fp = NULL;
    char sdk_env_dir[256];
    bool found = false;
    bool failed = false;

    PrintBeginTable("DarkKhaki", "LunarG Vulkan SDKs", 3);
    PrintBeginTableRow();
    PrintTableElement("SDKs Found In Registry");
    PrintTableElement(g_uninstall_reg_path);
    PrintTableElement("");
    PrintEndTableRow();

    while (FindNextRegKey(HKEY_LOCAL_MACHINE, g_uninstall_reg_path, "VulkanSDK",
                          i, 256, key_name)) {
        found = true;
        sprintf(installed_string, "[%d]", i++);
        sprintf(reg_key_path, "%s\\%s", g_uninstall_reg_path, key_name);
        if (ReadRegKeyString(HKEY_LOCAL_MACHINE, reg_key_path, "InstallDir",
                             256, location_string)) {
        } else {
            strcpy(location_string, key_name);
        }

        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement(installed_string, ALIGN_RIGHT);
        PrintTableElement(location_string);
        PrintEndTableRow();
    }
    if (!found) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("NONE FOUND", ALIGN_RIGHT);
        PrintTableElement("");
        PrintEndTableRow();
    }

    PrintBeginTableRow();
    PrintTableElement("VK_SDK_PATH");
    if (0 != GetEnvironmentVariableA("VK_SDK_PATH", sdk_env_dir, 255)) {
        global_items.sdk_found = true;
        global_items.sdk_path = sdk_env_dir;
        PrintTableElement(sdk_env_dir);
    } else {
        PrintTableElement("No installed SDK");
    }
    PrintTableElement("");
    PrintEndTableRow();

#if _WIN64 || __x86_64__ || __ppc64__
    sprintf(vulkan_expl_layer_reg_key, "%s\\ExplicitLayers", vulkan_reg_base);
#else
    if (global_items.is_wow64) {
        sprintf(vulkan_expl_layer_reg_key, "%s\\ExplicitLayers",
                vulkan_reg_base_wow64);
    } else {
        sprintf(vulkan_expl_layer_reg_key, "%s\\ExplicitLayers",
                vulkan_reg_base);
    }
#endif

    PrintBeginTableRow();
    PrintTableElement("SDK Explicit Layers");
    PrintTableElement(vulkan_expl_layer_reg_key);
    PrintTableElement("");
    PrintEndTableRow();

    found = false;
    i = 0;
    while (FindNextRegValue(HKEY_LOCAL_MACHINE, vulkan_expl_layer_reg_key, "",
                            i, 512, cur_vulkan_layer_json)) {
        found = true;

        // Create a short json file name so we don't use up too much space
        sprintf(location_string, ".%s", &cur_vulkan_layer_json[strlen(sdk_env_dir)]);

        sprintf(generic_string, "[%d]", i++);
        PrintBeginTableRow();
        PrintTableElement(generic_string, ALIGN_RIGHT);
        PrintTableElement(location_string);
        PrintTableElement("");
        PrintEndTableRow();

        std::ifstream *stream = NULL;
        stream = new std::ifstream(cur_vulkan_layer_json, std::ifstream::in);
        if (nullptr == stream || stream->fail()) {
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("ERROR reading JSON file!");
            PrintTableElement("");
            PrintEndTableRow();
            failed = true;
        } else {
            Json::Value root = Json::nullValue;
            Json::Reader reader;
            if (!reader.parse(*stream, root, false) || root.isNull()) {
                // report to the user the failure and their locations in the
                // document.
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("ERROR parsing JSON file!");
                PrintTableElement(reader.getFormattedErrorMessages());
                PrintEndTableRow();
                failed = true;
            } else {
                PrintExplicitLayerJsonInfo(cur_vulkan_layer_json, root, 3);
            }

            stream->close();
            delete stream;
            stream = NULL;
        }
    }
    if (!found) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("NONE FOUND", ALIGN_RIGHT);
        PrintTableElement("");
        PrintEndTableRow();
    }

    PrintEndTable();

    if (failed) {
        throw -1;
    }
}

void PrintLayerInfo(void) {
    const char vulkan_reg_base[] = "SOFTWARE\\Khronos\\Vulkan";
    const char vulkan_reg_base_wow64[] =
        "SOFTWARE\\WOW6432Node\\Khronos\\Vulkan";
    char vulkan_impl_layer_reg_key[512];
    char cur_vulkan_layer_json[512];
    char generic_string[512];
    char full_layer_path[512];
    char env_value[256];
    char *cur_string_ptr = NULL;
    uint32_t i = 0;
    uint32_t j = 0;
    FILE *fp = NULL;
    bool in_layer_section = false;
    bool in_enable_section = false;
    bool in_disable_section = false;
    bool failed = false;

#if _WIN64 || __x86_64__ || __ppc64__
    sprintf(vulkan_impl_layer_reg_key, "%s\\ImplicitLayers", vulkan_reg_base);
#else
    if (global_items.is_wow64) {
        sprintf(vulkan_impl_layer_reg_key, "%s\\ImplicitLayers",
                vulkan_reg_base_wow64);
    } else {
        sprintf(vulkan_impl_layer_reg_key, "%s\\ImplicitLayers",
                vulkan_reg_base);
    }
#endif

    PrintBeginTable("Orange", "Implicit Layers", 4);
    PrintBeginTableRow();
    PrintTableElement("Registry");
    PrintTableElement(vulkan_impl_layer_reg_key);
    PrintTableElement("");
    PrintTableElement("");
    PrintEndTableRow();

    while (FindNextRegValue(HKEY_LOCAL_MACHINE, vulkan_impl_layer_reg_key, "",
                            i, 512, cur_vulkan_layer_json)) {

        sprintf(generic_string, "[%d]", i++);

        PrintBeginTableRow();
        PrintTableElement(generic_string, ALIGN_RIGHT);
        PrintTableElement(cur_vulkan_layer_json);
        PrintTableElement("");
        PrintTableElement("");
        PrintEndTableRow();

        std::ifstream *stream = NULL;
        stream = new std::ifstream(cur_vulkan_layer_json, std::ifstream::in);
        if (nullptr == stream || stream->fail()) {
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("ERROR reading JSON file!");
            PrintTableElement("");
            PrintEndTableRow();
            failed = true;
        } else {
            Json::Value root = Json::nullValue;
            Json::Reader reader;
            if (!reader.parse(*stream, root, false) || root.isNull()) {
                // report to the user the failure and their locations in the
                // document.
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("ERROR parsing JSON file!");
                PrintTableElement(reader.getFormattedErrorMessages());
                PrintEndTableRow();
                failed = true;
            } else {
                PrintImplicitLayerJsonInfo(cur_vulkan_layer_json, root);
            }

            stream->close();
            delete stream;
            stream = NULL;
        }
    }
    PrintEndTable();

    if (0 != GetEnvironmentVariableA("VK_LAYER_PATH", env_value, 255)) {
        WIN32_FIND_DATAA ffd;
        HANDLE hFind;

        PrintBeginTable("Sienna", "VK_LAYER_PATH Explicit Layers", 3);
        PrintBeginTableRow();
        PrintTableElement("VK_LAYER_PATH");
        PrintTableElement(env_value);
        PrintTableElement("");
        PrintEndTableRow();

        sprintf(full_layer_path, "%s\\*.json", env_value);
        i = 0;
        hFind = FindFirstFileA(full_layer_path, &ffd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (0 == (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    sprintf(generic_string, "[%d]", i++);
                    sprintf(cur_vulkan_layer_json, "%s\\%s", env_value,
                            ffd.cFileName);

                    PrintBeginTableRow();
                    PrintTableElement(generic_string, ALIGN_RIGHT);
                    PrintTableElement(ffd.cFileName);
                    PrintTableElement("");
                    PrintEndTableRow();

                    std::ifstream *stream = NULL;
                    stream = new std::ifstream(cur_vulkan_layer_json,
                                               std::ifstream::in);
                    if (nullptr == stream || stream->fail()) {
                        PrintBeginTableRow();
                        PrintTableElement("");
                        PrintTableElement("ERROR reading JSON file!");
                        PrintTableElement("");
                        PrintEndTableRow();
                        failed = true;
                    } else {
                        Json::Value root = Json::nullValue;
                        Json::Reader reader;
                        if (!reader.parse(*stream, root, false) ||
                            root.isNull()) {
                            // report to the user the failure and their
                            // locations in the document.
                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("ERROR parsing JSON file!");
                            PrintTableElement(
                                reader.getFormattedErrorMessages());
                            PrintEndTableRow();
                            failed = true;
                        } else {
                            PrintExplicitLayerJsonInfo(cur_vulkan_layer_json,
                                                       root, 3);
                        }

                        stream->close();
                        delete stream;
                        stream = NULL;
                    }
                }
            } while (FindNextFileA(hFind, &ffd) != 0);

            FindClose(hFind);
        }

        PrintEndTable();
    }

    if (failed) {
        throw -1;
    }
}

#elif __GNUC__

void PrintSystemInfo(void) {
    FILE *fp;
    char path[1035];
    char generic_string[256];
    utsname buffer;
    struct statvfs fs_stats;
    int num_cpus;
    uint64_t memory;
    bool failed = false;

    BeginSection("System Info");

    PrintBeginTable("DodgerBlue", "OS", 3);

    fp = popen("cat /etc/os-release", "r");
    if (fp == NULL) {
        PrintBeginTableRow();
        PrintTableElement("ERROR");
        PrintTableElement("Failed to cat /etc/os-release");
        PrintTableElement("");
        PrintEndTableRow();
        failed = true;
    } else {
        // Read the output a line at a time - output it.
        while (fgets(path, sizeof(path) - 1, fp) != NULL) {
            if (NULL != strstr(path, "PRETTY_NAME")) {
                uint32_t index;
                index = strlen(path) - 1;
                while (path[index] == ' ' || path[index] == '\t' ||
                       path[index] == '\r' || path[index] == '\n' ||
                       path[index] == '\"') {
                    path[index] = '\0';
                    index = strlen(path) - 1;
                }
                index = 13;
                while (path[index] == ' ' || path[index] == '\t' ||
                       path[index] == '\"') {
                    index++;
                }
                PrintBeginTableRow();
                PrintTableElement("Linux");
                PrintTableElement("");
                PrintTableElement("");
                PrintEndTableRow();
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("Distro");
                PrintTableElement(&path[index]);
                PrintEndTableRow();
                break;
            }
        }
        pclose(fp);
    }

    errno = 0;
    if (uname(&buffer) != 0) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("ERROR");
        PrintTableElement("Failed to query uname");
        PrintEndTableRow();
        failed = true;
    } else {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Kernel Build");
        PrintTableElement(buffer.release);
        PrintEndTableRow();
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Machine Target");
        PrintTableElement(buffer.machine);
        PrintEndTableRow();
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Version");
        PrintTableElement(buffer.version);
        PrintEndTableRow();
    }

    PrintEndTable();
    PrintBeginTable("LimeGreen", "Hardware", 3);

    num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    sprintf(generic_string, "%d", num_cpus);

    PrintBeginTableRow();
    PrintTableElement("CPUs");
    PrintTableElement(generic_string);
    PrintTableElement("");
    PrintEndTableRow();

    memory = (sysconf(_SC_PHYS_PAGES) * sysconf(_SC_PAGE_SIZE)) >> 10;
    if ((memory >> 10) > 0) {
        memory >>= 10;
        if ((memory >> 20) > 0) {
            sprintf(generic_string, "%u TB",
                    static_cast<uint32_t>(memory >> 20));
        } else if ((memory >> 10) > 0) {
            sprintf(generic_string, "%u GB",
                    static_cast<uint32_t>(memory >> 10));
        } else {
            sprintf(generic_string, "%u MB", static_cast<uint32_t>(memory));
        }
    } else {
        sprintf(generic_string, "%u KB", static_cast<uint32_t>(memory));
    }
    PrintBeginTableRow();
    PrintTableElement("Memory");
    PrintTableElement("Physical");
    PrintTableElement(generic_string);
    PrintEndTableRow();

    if (0 == statvfs("/etc/os-release", &fs_stats)) {
        uint64_t bytes_total =
            (uint64_t)fs_stats.f_bsize * (uint64_t)fs_stats.f_bavail;
        if ((bytes_total >> 40) > 0x0ULL) {
            sprintf(generic_string, "%u TB",
                    static_cast<uint32_t>(bytes_total >> 40));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((bytes_total >> 30) > 0x0ULL) {
            sprintf(generic_string, "%u GB",
                    static_cast<uint32_t>(bytes_total >> 30));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
        } else if ((bytes_total >> 20) > 0x0ULL) {
            sprintf(generic_string, "%u MB",
                    static_cast<uint32_t>(bytes_total >> 20));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else if ((bytes_total >> 10) > 0x0ULL) {
            sprintf(generic_string, "%u KB",
                    static_cast<uint32_t>(bytes_total >> 10));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        } else {
            sprintf(generic_string, "%u bytes",
                    static_cast<uint32_t>(bytes_total));
            PrintBeginTableRow();
            PrintTableElement("Disk Space");
            PrintTableElement("Free");
            PrintTableElement(generic_string);
            PrintEndTableRow();
        }
    }

    PrintEndTable();

    PrintBeginTable("Peru", "Executable", 2);

    if (getcwd(generic_string, 1023) != NULL) {
        PrintBeginTableRow();
        PrintTableElement("Current Directory");
        PrintTableElement(generic_string);
        PrintEndTableRow();
    }

    sprintf(generic_string, "%d.%d", VALIDATOR_MAJOR_VERSION, VALIDATOR_MINOR_VERSION);
    PrintBeginTableRow();
    PrintTableElement("App Version");
    PrintTableElement(generic_string);
    PrintEndTableRow();

    uint32_t major = VK_VERSION_MAJOR(VK_API_VERSION_1_0);
    uint32_t minor = VK_VERSION_MINOR(VK_API_VERSION_1_0);
    uint32_t patch = VK_VERSION_PATCH(VK_HEADER_VERSION);

    PrintBeginTableRow();
    PrintTableElement("Vulkan API Version");
    PrintTableElement(generic_string);
    PrintEndTableRow();

    PrintBeginTableRow();
    PrintTableElement("Executable Format");
#if _WIN64 || __x86_64__ || __ppc64__
    PrintTableElement("64-bit");
#else
    PrintTableElement("32-bit");
#endif
    PrintEndTableRow();

    PrintEndTable();

    PrintDriverInfo();
    PrintRunTimeInfo();
    PrintSDKInfo();
    PrintLayerInfo();
    PrintLayerSettingsFileInfo();
    EndSection();

    if (failed) {
        throw -1;
    }
}

void PrintDriverInfo(void) {
    bool failed = false;
    char generic_string[256];
    uint32_t i = 0;
    uint32_t j = 0;

    PrintBeginTable("Tomato", "Vulkan Driver Info", 3);

    // There are two folders ICD JSONs could be.  So, both.
    for (uint32_t dir = 0; dir < 3; dir++) {
        std::string cur_driver_path;
        std::string cur_driver_json;
        switch (dir) {
        case 0:
            cur_driver_path = "/etc/vulkan/icd.d";
            break;
        case 1:
            cur_driver_path = "/usr/share/vulkan/icd.d";
            break;
        case 2:
            {
                char *env_value = getenv("VK_DRIVERS_PATH");
                if (NULL == env_value) {
                    continue;
                }
                cur_driver_path = env_value;
                break;
            }
        default:
            failed = true;
            continue;
        }

        PrintBeginTableRow();
        PrintTableElement(cur_driver_path.c_str());
        PrintTableElement("");
        PrintTableElement("");
        PrintEndTableRow();

        DIR *layer_dir = opendir(cur_driver_path.c_str());
        if (NULL == layer_dir) {
            continue;
        }
        dirent *cur_ent;
        i = 0;
        while ((cur_ent = readdir(layer_dir)) != NULL) {
            if (NULL != strstr(cur_ent->d_name, ".json")) {
                sprintf(generic_string, "[%d]", i++);
                cur_driver_json = cur_driver_path;
                cur_driver_json += "/";
                cur_driver_json += cur_ent->d_name;

                PrintBeginTableRow();
                PrintTableElement(generic_string, ALIGN_RIGHT);
                PrintTableElement(cur_ent->d_name);
                PrintTableElement("");
                PrintEndTableRow();

                std::ifstream *stream = NULL;
                stream = new std::ifstream(cur_driver_json.c_str(),
                                           std::ifstream::in);
                if (nullptr == stream || stream->fail()) {
                    sprintf(generic_string, "Error reading file %s!\n",
                            cur_driver_json.c_str());
                    PrintError(generic_string);
                    failed = true;
                    continue;
                } else {
                    Json::Value root = Json::nullValue;
                    Json::Reader reader;
                    if (!reader.parse(*stream, root, false) || root.isNull()) {
                        PrintError(reader.getFormattedErrorMessages());
                        failed = true;
                        stream->close();
                        delete stream;
                        continue;
                    } else {
                        PrintBeginTableRow();
                        PrintTableElement("");
                        PrintTableElement("JSON File Version");
                        if (!root["file_format_version"].isNull()) {
                            PrintTableElement(
                                root["file_format_version"].asString());
                        } else {
                            PrintTableElement("MISSING!");
                        }
                        PrintEndTableRow();

                        if (!root["ICD"].isNull()) {
                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("API Version");
                            if (!root["ICD"]["api_version"].isNull()) {
                                PrintTableElement(
                                    root["ICD"]["api_version"].asString());
                            } else {
                                PrintTableElement("MISSING!");
                            }
                            PrintEndTableRow();

                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("Library Path");
                            if (!root["ICD"]["library_path"].isNull()) {
                                PrintTableElement(
                                    root["ICD"]["library_path"].asString());
                                PrintEndTableRow();
                            } else {
                                PrintTableElement("MISSING!");
                                PrintEndTableRow();
                            }

                            char count_str[256];
                            j = 0;
                            Json::Value dev_exts =
                                root["ICD"]["device_extensions"];
                            if (!dev_exts.isNull() && dev_exts.isArray()) {
                                sprintf(count_str, "%d", dev_exts.size());
                                PrintBeginTableRow();
                                PrintTableElement("");
                                PrintTableElement("Device Extensions");
                                PrintTableElement(count_str);
                                PrintEndTableRow();

                                for (Json::ValueIterator dev_ext_it =
                                         dev_exts.begin();
                                     dev_ext_it != dev_exts.end();
                                     dev_ext_it++) {
                                    Json::Value dev_ext = (*dev_ext_it);
                                    Json::Value dev_ext_name = dev_ext["name"];
                                    if (!dev_ext_name.isNull()) {
                                        sprintf(generic_string, "[%d]", j);

                                        PrintBeginTableRow();
                                        PrintTableElement("");
                                        PrintTableElement(generic_string,
                                                          ALIGN_RIGHT);
                                        PrintTableElement(
                                            dev_ext_name.asString());
                                        PrintEndTableRow();
                                    }
                                }
                            }
                            Json::Value inst_exts =
                                root["ICD"]["instance_extensions"];
                            j = 0;
                            if (!inst_exts.isNull() && inst_exts.isArray()) {
                                sprintf(count_str, "%d", inst_exts.size());
                                PrintBeginTableRow();
                                PrintTableElement("");
                                PrintTableElement("Instance Extensions");
                                PrintTableElement(count_str);
                                PrintEndTableRow();

                                for (Json::ValueIterator inst_ext_it =

                                         inst_exts.begin();
                                     inst_ext_it != inst_exts.end();
                                     inst_ext_it++) {
                                    Json::Value inst_ext = (*inst_ext_it);
                                    Json::Value inst_ext_name =
                                        inst_ext["name"];
                                    if (!inst_ext_name.isNull()) {
                                        sprintf(generic_string, "[%d]", j);

                                        PrintBeginTableRow();
                                        PrintTableElement("");
                                        PrintTableElement(generic_string,
                                                          ALIGN_RIGHT);
                                        PrintTableElement(
                                            inst_ext_name.asString());
                                        PrintEndTableRow();
                                    }
                                }
                            }
                        } else {
                            PrintBeginTableRow();
                            PrintTableElement("");
                            PrintTableElement("ICD Section");
                            PrintTableElement("MISSING!");
                            PrintEndTableRow();
                        }
                    }

                    stream->close();
                    delete stream;
                    stream = NULL;
                }
            }
        }
    }
    PrintEndTable();
    if (failed) {
        throw -1;
    }
}

bool PrintRuntimesInFolder(std::string &folder_loc, bool print_header = true) {
    DIR *runtime_dir;
    bool success = false;
    bool failed = false;
    const char vulkan_so_prefix[] = "libvulkan.so.";

    runtime_dir = opendir(folder_loc.c_str());
    if (NULL != runtime_dir) {
        bool file_found = false;
        FILE *pfp;
        uint32_t i = 0;
        dirent *cur_ent;
        std::string command_str;
        std::stringstream generic_str;
        char path[1035];

        if (print_header) {
            PrintBeginTableRow();
            PrintTableElement(folder_loc, ALIGN_RIGHT);
            PrintTableElement("");
            PrintTableElement("");
            PrintEndTableRow();
        }

        while ((cur_ent = readdir(runtime_dir)) != NULL) {
            if (NULL != strstr(cur_ent->d_name, vulkan_so_prefix) &&
                strlen(cur_ent->d_name) == 14) {

                // Get the source of this symbolic link
                command_str = "stat -c%N ";
                command_str += folder_loc;
                command_str += "/";
                command_str += cur_ent->d_name;
                pfp = popen(command_str.c_str(), "r");

                generic_str << "[" << i++ << "]";

                PrintBeginTableRow();
                PrintTableElement(generic_str.str(), ALIGN_RIGHT);

                file_found = true;

                if (pfp == NULL) {
                    PrintTableElement(cur_ent->d_name);
                    PrintTableElement("Failed to retrieve symbolic link");
                    failed = true;
                } else {
                    if (NULL != fgets(path, sizeof(path) - 1, pfp)) {
                        std::string cmd = path;
                        size_t arrow_loc = cmd.find("->");
                        if (arrow_loc == std::string::npos) {
                            std::string trimmed_path = TrimWhitespace(path, " \t\n\r\'\"");

                            PrintTableElement(trimmed_path);
                            PrintTableElement("");
                        } else {
                            std::string before_arrow = cmd.substr(0, arrow_loc);
                            std::string trim_before = TrimWhitespace(before_arrow, " \t\n\r\'\"");
                            std::string after_arrow = cmd.substr(arrow_loc + 2, std::string::npos);
                            std::string trim_after = TrimWhitespace(after_arrow, " \t\n\r\'\"");
                            PrintTableElement(trim_before);
                            PrintTableElement(trim_after);
                        }
                    } else {
                        PrintTableElement(cur_ent->d_name);
                        PrintTableElement("Failed to retrieve symbolic link");
                    }

                    PrintEndTableRow();

                    pclose(pfp);
                }
            }
        }
        if (!file_found) {
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("No libvulkan.so files found");
            PrintTableElement("");
            PrintEndTableRow();
        }
        closedir(runtime_dir);

        success = !failed;
    } else {
        PrintBeginTableRow();
        PrintTableElement(folder_loc, ALIGN_RIGHT);
        PrintTableElement("No such folder");
        PrintTableElement("");
        PrintEndTableRow();
    }

    return success;
}

void PrintRunTimeInfo(void) {
    const char vulkan_so_prefix[] = "libvulkan.so.";
    char path[1035];
    char generic_string[512];
    char buff[PATH_MAX];
    std:: string runtime_dir_name;
    FILE *pfp;
    bool failed = false;

    PrintBeginTable("Gold", "Vulkan Runtimes", 3);

    PrintBeginTableRow();
    PrintTableElement("Possible Runtime Folders");
    PrintTableElement("");
    PrintTableElement("");
    PrintEndTableRow();

    for (uint32_t iii = 0; iii < 4; iii++) {
        switch (iii) {
        case 0:
            runtime_dir_name = "/usr/lib";
            break;
        case 1:
#if _WIN64 || __x86_64__ || __ppc64__
            runtime_dir_name = "/usr/lib64";
#else
            runtime_dir_name = "/usr/lib32";
#endif
            break;
        case 2:
            runtime_dir_name = "/usr/local/lib";
            break;
        case 3:
#if _WIN64 || __x86_64__ || __ppc64__
            runtime_dir_name = "/usr/local/lib64";
#else
            runtime_dir_name = "/usr/local/lib32";
#endif
            break;
        default:
            failed = true;
            continue;
        }

        if (!PrintRuntimesInFolder(runtime_dir_name)) {
            failed = true;
        }
    }

    ssize_t len = ::readlink("/proc/self/exe", buff, sizeof(buff) - 1);
    if (len != -1) {
        buff[len] = '\0';

        std::string runtime_dir_id = "Runtime Folder Used By VkValidator";
        sprintf(generic_string, "ldd %s", buff);
        pfp = popen(generic_string, "r");
        if (pfp == NULL) {
            PrintBeginTableRow();
            PrintTableElement(runtime_dir_id);
            PrintTableElement("Failed to query VkValidator library info");
            PrintTableElement("");
            PrintEndTableRow();
            failed = true;
        } else {
            bool found = false;
            while (fgets(path, sizeof(path) - 1, pfp) != NULL) {
                if (NULL != strstr(path, vulkan_so_prefix)) {
                    std::string cmd = path;
                    size_t arrow_loc = cmd.find("=>");
                    if (arrow_loc == std::string::npos) {
                        std::string trimmed_path = TrimWhitespace(path, " \t\n\r\'\"");
                        PrintBeginTableRow();
                        PrintTableElement(runtime_dir_id);
                        PrintTableElement(trimmed_path);
                        PrintTableElement("");
                        PrintEndTableRow();
                    } else {
                        std::string after_arrow = cmd.substr(arrow_loc + 2);
                        std::string before_slash = after_arrow.substr(0, after_arrow.rfind("/"));
                        std::string trimmed = TrimWhitespace(before_slash, " \t\n\r\'\"");

                        PrintBeginTableRow();
                        PrintTableElement(runtime_dir_id);
                        PrintTableElement(trimmed);
                        PrintTableElement("");
                        PrintEndTableRow();

                        if (!PrintRuntimesInFolder(trimmed, false)) {
                            failed = true;
                        }
                    }
                    found = true;
                    break;
                }
            }
            if (!found) {
                PrintBeginTableRow();
                PrintTableElement(runtime_dir_id);
                PrintTableElement("Failed to find Vulkan SO used for vkvalidator");
                PrintTableElement("");
                PrintEndTableRow();
            }
            pclose(pfp);
        }
        PrintEndTableRow();
    }

    PrintEndTable();

    if (failed) {
        throw -1;
    }
}


bool PrintExplicitLayersInFolder(std::string &id, std::string &folder_loc) {
    DIR *layer_dir;
    bool success = false;

    layer_dir = opendir(folder_loc.c_str());
    if (NULL != layer_dir) {
        dirent *cur_ent;
        std::string cur_layer;
        char generic_string[512];
        uint32_t i = 0;
        bool failed = false;
        bool found_json = false;

        PrintBeginTableRow();
        PrintTableElement(id);
        PrintTableElement(folder_loc);
        PrintTableElement("");
        PrintEndTableRow();

        while ((cur_ent = readdir(layer_dir)) != NULL) {
            if (NULL != strstr(cur_ent->d_name, ".json")) {
                found_json = true;

                sprintf(generic_string, "[%d]", i++);
                cur_layer = folder_loc;
                cur_layer += "/";
                cur_layer += cur_ent->d_name;

                std::ifstream *stream = NULL;
                stream = new std::ifstream(cur_layer, std::ifstream::in);
                if (nullptr == stream || stream->fail()) {
                    PrintBeginTableRow();
                    PrintTableElement(generic_string, ALIGN_RIGHT);
                    PrintTableElement(cur_ent->d_name);
                    PrintTableElement("ERROR reading JSON file!");
                    PrintEndTableRow();
                    failed = true;
                } else {
                    Json::Value root = Json::nullValue;
                    Json::Reader reader;
                    if (!reader.parse(*stream, root, false) ||
                        root.isNull()) {
                        // report to the user the failure and their
                        // locations in the document.
                        PrintBeginTableRow();
                        PrintTableElement(generic_string, ALIGN_RIGHT);
                        PrintTableElement(cur_ent->d_name);
                        PrintTableElement(
                            reader.getFormattedErrorMessages());
                        PrintEndTableRow();
                        failed = true;
                    } else {
                        PrintBeginTableRow();
                        PrintTableElement(generic_string, ALIGN_RIGHT);
                        PrintTableElement(cur_ent->d_name);
                        PrintTableElement("");
                        PrintEndTableRow();

                        PrintExplicitLayerJsonInfo(cur_layer.c_str(), root, 3);
                    }

                    stream->close();
                    delete stream;
                    stream = NULL;
                }
            }
        }
        if (!found_json) {
            PrintBeginTableRow();
            PrintTableElement(id);
            PrintTableElement(folder_loc);
            PrintTableElement("No JSON files found");
            PrintEndTableRow();
        }
        closedir(layer_dir);

        success = !failed;
    } else {
        PrintBeginTableRow();
        PrintTableElement(id);
        PrintTableElement(folder_loc);
        PrintTableElement("No such folder");
        PrintEndTableRow();
    }

    return success;
}

void PrintSDKInfo(void) {
    bool failed = false;
    bool sdk_exists = false;
    std::string sdk_path;
    std::string sdk_env_name;
    const char vulkan_so_prefix[] = "libvulkan.so.";
    DIR *sdk_dir;
    dirent *cur_ent;
    char *env_value;

    PrintBeginTable("DarkKhaki", "LunarG Vulkan SDKs", 3);

    for (uint32_t dir = 0; dir < 2; dir++) {
        switch (dir) {
            case 0:
                sdk_env_name = "VK_SDK_PATH";
                env_value = getenv(sdk_env_name.c_str());
                if (env_value == NULL) {
                    continue;
                }
                sdk_path = env_value;
                break;
            case 1:
                sdk_env_name = "VULKAN_SDK";
                env_value = getenv(sdk_env_name.c_str());
                if (env_value == NULL) {
                    continue;
                }
                sdk_path = env_value;
                break;
            default:
                failed = true;
                continue;
        }

        std::string explicit_layer_path = sdk_path;
        explicit_layer_path += "/etc/explicit_layer.d";

        sdk_dir = opendir(explicit_layer_path.c_str());
        if (NULL != sdk_dir) {
            while ((cur_ent = readdir(sdk_dir)) != NULL) {
                if (NULL != strstr(cur_ent->d_name, vulkan_so_prefix) &&
                    strlen(cur_ent->d_name) == 14) {
                }
            }
            closedir(sdk_dir);

            if (!PrintExplicitLayersInFolder(sdk_env_name, explicit_layer_path)) {
                failed = true;
            }

            global_items.sdk_found = true;
            global_items.sdk_path = sdk_path;
            sdk_exists = true;
        }
    }

    if (!sdk_exists) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("No installed SDKs found");
        PrintTableElement("");
        PrintEndTableRow();
    }

    PrintEndTable();

    if (failed) {
        throw -1;
    }
}

void PrintLayerInfo(void) {
    uint32_t i = 0;
    char generic_string[512];
    bool failed = false;
    char cur_vulkan_layer_json[512];
    DIR *layer_dir;
    dirent *cur_ent;
    const char implicit_layer_dir[] = "/etc/vulkan/implicit_layer.d";
    const char explicit_layer_dir[] = "/etc/vulkan/explicit_layer.d";
    std::string layer_path;

    PrintBeginTable("Orange", "Implicit Layers", 3);
    PrintBeginTableRow();
    PrintTableElement("Location");
    PrintTableElement(implicit_layer_dir);
    PrintTableElement("");
    PrintEndTableRow();

    layer_dir = opendir(implicit_layer_dir);
    if (NULL != layer_dir) {
        while ((cur_ent = readdir(layer_dir)) != NULL) {
            if (NULL != strstr(cur_ent->d_name, ".json")) {
                sprintf(generic_string, "[%d]", i++);
                sprintf(cur_vulkan_layer_json, "%s/%s", implicit_layer_dir,
                        cur_ent->d_name);

                PrintBeginTableRow();
                PrintTableElement(generic_string, ALIGN_RIGHT);
                PrintTableElement(cur_ent->d_name);
                PrintTableElement("");
                PrintEndTableRow();

                std::ifstream *stream = NULL;
                stream = new std::ifstream(cur_vulkan_layer_json,
                                           std::ifstream::in);
                if (nullptr == stream || stream->fail()) {
                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("ERROR reading JSON file!");
                    PrintTableElement("");
                    PrintEndTableRow();
                    failed = true;
                } else {
                    Json::Value root = Json::nullValue;
                    Json::Reader reader;
                    if (!reader.parse(*stream, root, false) ||
                        root.isNull()) {
                        // report to the user the failure and their
                        // locations in the document.
                        PrintBeginTableRow();
                        PrintTableElement("");
                        PrintTableElement("ERROR parsing JSON file!");
                        PrintTableElement(
                            reader.getFormattedErrorMessages());
                        PrintEndTableRow();
                        failed = true;
                    } else {
                        PrintExplicitLayerJsonInfo(cur_vulkan_layer_json,
                                                   root, 3);
                    }

                    stream->close();
                    delete stream;
                    stream = NULL;
                }
            }
        }
        closedir(layer_dir);
    } else {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Directory does not exist");
        PrintTableElement("");
        PrintEndTableRow();
    }
    PrintEndTable();

    PrintBeginTable("Sienna", "Explicit Layers", 3);

    std::string explicit_layer_id = "Global path";
    std::string explicit_layer_path = explicit_layer_dir;

    if (!PrintExplicitLayersInFolder(explicit_layer_id, explicit_layer_path)) {
        failed = true;
    }

    explicit_layer_id = "VK_LAYER_PATH"; 
    char *env_value = getenv("VK_LAYER_PATH");
    if (NULL != env_value) {
        explicit_layer_path = env_value;
        if (!PrintExplicitLayersInFolder(explicit_layer_id, explicit_layer_path)) {
            failed = true;
        }
    }

    PrintEndTable();

    if (failed) {
        throw -1;
    }
}

int RunTestInDirectory(std::string path, std::string test) {
    int err_code = -1;
    /*    char orig_dir[1024];
    orig_dir[0] = '\0';
    if (0 != GetCurrentDirectoryA(1023, orig_dir) &&
        TRUE == SetCurrentDirectoryA(path.c_str())) {
        if (0 == system(test.c_str())) {
            err_code = 0;
        }
        SetCurrentDirectoryA(orig_dir);
    }
*/ return err_code;
}

#endif

std::string TrimWhitespace(const std::string &str,
                           const std::string &whitespace) {
    const auto strBegin = str.find_first_not_of(whitespace);
    if (strBegin == std::string::npos) {
        return ""; // no content
    }

    const auto strEnd = str.find_last_not_of(whitespace);
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

struct SettingPair {
    std::string name;
    std::string value;
};

void PrintLayerSettingsFileInfo(void) {
    bool failed = false;
    char *settings_path = NULL;
    std::string settings_file;
    std::map<std::string, std::vector<SettingPair>> settings;

    PrintBeginTable("Gray", "Layer Settings File", 4);

#ifdef _WIN32
    char generic_string[512];
    if (0 != GetEnvironmentVariableA("VK_LAYER_SETTINGS_PATH", generic_string,
                                     511)) {
        settings_path = generic_string;
        settings_file = settings_path;
        settings_file += '\\';
    }
#else
    settings_path = getenv("VK_LAYER_SETTINGS_PATH");
    if (NULL != settings_path) {
        settings_file = settings_path;
        settings_file += '/';
    }
#endif
    settings_file += "vk_layer_settings.txt";

    PrintBeginTableRow();
    PrintTableElement("VK_LAYER_SETTINGS_PATH");
    if (NULL != settings_path) {
        PrintTableElement(settings_path);
    } else {
        PrintTableElement("Not Defined");
    }
    PrintTableElement("");
    PrintTableElement("");
    PrintEndTableRow();

    PrintBeginTableRow();
    PrintTableElement("Settings File");
    PrintTableElement("vk_layer_settings.txt");
    std::ifstream *settings_stream =
        new std::ifstream(settings_file, std::ifstream::in);
    if (nullptr == settings_stream || settings_stream->fail()) {
        PrintTableElement("Not Found");
        PrintTableElement("");
        PrintEndTableRow();
    } else {
        PrintTableElement("Found");
        PrintTableElement("");
        PrintEndTableRow();

        while (settings_stream->good()) {
            std::string cur_line;
            getline(*settings_stream, cur_line);
            std::string trimmed_line = TrimWhitespace(cur_line);

            // Skip blank and comment lines
            if (trimmed_line.length() == 0 || trimmed_line.c_str()[0] == '#') {
                continue;
            }

            // If no equal, treat as unknown
            size_t equal_loc = trimmed_line.find("=");
            if (equal_loc == std::string::npos) {
                continue;
            }

            SettingPair new_pair;

            std::string before_equal = trimmed_line.substr(0, equal_loc);
            std::string after_equal =
                trimmed_line.substr(equal_loc + 1, std::string::npos);
            new_pair.value = TrimWhitespace(after_equal);

            std::string trimmed_setting = TrimWhitespace(before_equal);

            // Look for period
            std::string setting_layer = "--None--";
            std::string setting_name = "";
            size_t period_loc = trimmed_setting.find(".");
            if (period_loc == std::string::npos) {
                setting_name = trimmed_setting;
            } else {
                setting_layer = trimmed_setting.substr(0, period_loc);
                setting_name =
                    trimmed_setting.substr(period_loc + 1, std::string::npos);
            }
            new_pair.name = setting_name;

            // Add items to settings map for now
            if (settings.find(setting_layer) == settings.end()) {
                // Not found
                std::vector<SettingPair> new_vector;
                new_vector.push_back(new_pair);
                settings[setting_layer] = new_vector;
            } else {
                // Already exists
                std::vector<SettingPair> &cur_vector = settings[setting_layer];
                cur_vector.push_back(new_pair);
            }
        }

        // Now that all items have been grouped in the settings map
        // appropriately, print
        // them out
        for (auto layer_iter = settings.begin(); layer_iter != settings.end();
             layer_iter++) {
            std::vector<SettingPair> &cur_vector = layer_iter->second;
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement(layer_iter->first, ALIGN_RIGHT);
            PrintTableElement("");
            PrintTableElement("");
            PrintEndTableRow();
            for (uint32_t cur_item = 0; cur_item < cur_vector.size();
                 cur_item++) {
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("");
                PrintTableElement(cur_vector[cur_item].name);
                PrintTableElement(cur_vector[cur_item].value);
                PrintEndTableRow();
            }
        }

        settings_stream->close();
        delete settings_stream;
    }
    PrintEndTable();

    if (failed) {
        throw -1;
    }
}

// Following functions should be OS agnostic:
//==========================================
void PrintExplicitLayerJsonInfo(const char *layer_json_filename, Json::Value root,
                                uint32_t num_cols) {
    char generic_string[512];
    uint32_t cur_col;
    uint32_t ext;
    if (!root["layer"].isNull()) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Name");
        if (!root["layer"]["name"].isNull()) {
            PrintTableElement(root["layer"]["name"].asString());
        } else {
            PrintTableElement("MISSING!");
        }
        cur_col = 3;
        while (num_cols > cur_col) {
            PrintTableElement("");
            cur_col++;
        }
        PrintEndTableRow();

        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Description");
        if (!root["layer"]["description"].isNull()) {
            PrintTableElement(root["layer"]["description"].asString());
        } else {
            PrintTableElement("MISSING!");
        }
        cur_col = 3;
        while (num_cols > cur_col) {
            PrintTableElement("");
            cur_col++;
        }
        PrintEndTableRow();

        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("API Version");
        if (!root["layer"]["api_version"].isNull()) {
            PrintTableElement(root["layer"]["api_version"].asString());
        } else {
            PrintTableElement("MISSING!");
        }
        cur_col = 3;
        while (num_cols > cur_col) {
            PrintTableElement("");
            cur_col++;
        }
        PrintEndTableRow();

        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("JSON File Version");
        if (!root["file_format_version"].isNull()) {
            PrintTableElement(root["file_format_version"].asString());
        } else {
            PrintTableElement("MISSING!");
        }
        cur_col = 3;
        while (num_cols > cur_col) {
            PrintTableElement("");
            cur_col++;
        }
        PrintEndTableRow();

        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Library Path");
        if (!root["layer"]["library_path"].isNull()) {
            PrintTableElement(root["layer"]["library_path"].asString());
            cur_col = 3;
            while (num_cols > cur_col) {
                PrintTableElement("");
                cur_col++;
            }
            PrintEndTableRow();

#ifdef _WIN32
            char full_layer_path[512];
            if (GenerateLibraryPath(
                    layer_json_filename,
                    root["layer"]["library_path"].asString().c_str(), 512,
                    full_layer_path) &&
                GetFileVersion(full_layer_path, 256, generic_string)) {
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("Layer File Version");
                PrintTableElement(generic_string);
                cur_col = 3;
                while (num_cols > cur_col) {
                    PrintTableElement("");
                    cur_col++;
                }
                PrintEndTableRow();
            }
#endif
        } else {
            PrintTableElement("MISSING!");
            cur_col = 3;
            while (num_cols > cur_col) {
                PrintTableElement("");
                cur_col++;
            }
            PrintEndTableRow();
        }

        char count_str[256];
        Json::Value dev_exts = root["layer"]["device_extensions"];
        ext = 0;
        if (!dev_exts.isNull() && dev_exts.isArray()) {
            sprintf(count_str, "%d", dev_exts.size());
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Device Extensions");
            PrintTableElement(count_str);
            cur_col = 3;
            while (num_cols > cur_col) {
                PrintTableElement("");
                cur_col++;
            }
            PrintEndTableRow();

            for (Json::ValueIterator dev_ext_it = dev_exts.begin();
                 dev_ext_it != dev_exts.end(); dev_ext_it++) {
                Json::Value dev_ext = (*dev_ext_it);
                Json::Value dev_ext_name = dev_ext["name"];
                if (!dev_ext_name.isNull()) {
                    sprintf(generic_string, "[%d]", ext);
                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement(generic_string, ALIGN_RIGHT);
                    PrintTableElement(dev_ext_name.asString());
                    cur_col = 3;
                    while (num_cols > cur_col) {
                        PrintTableElement("");
                        cur_col++;
                    }
                    PrintEndTableRow();
                }
            }
        }
        Json::Value inst_exts = root["layer"]["instance_extensions"];
        ext = 0;
        if (!inst_exts.isNull() && inst_exts.isArray()) {
            sprintf(count_str, "%d", inst_exts.size());
            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Instance Extensions");
            PrintTableElement(count_str);
            cur_col = 3;
            while (num_cols > cur_col) {
                PrintTableElement("");
                cur_col++;
            }
            PrintEndTableRow();

            for (Json::ValueIterator inst_ext_it = inst_exts.begin();
                 inst_ext_it != inst_exts.end(); inst_ext_it++) {
                Json::Value inst_ext = (*inst_ext_it);
                Json::Value inst_ext_name = inst_ext["name"];
                if (!inst_ext_name.isNull()) {
                    sprintf(generic_string, "[%d]", ext);
                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement(generic_string, ALIGN_RIGHT);
                    PrintTableElement(inst_ext_name.asString());
                    cur_col = 3;
                    while (num_cols > cur_col) {
                        PrintTableElement("");
                        cur_col++;
                    }
                    PrintEndTableRow();
                }
            }
        }
    } else {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Layer Section");
        PrintTableElement("MISSING!");
        cur_col = 3;
        while (num_cols > cur_col) {
            PrintTableElement("");
            cur_col++;
        }
        PrintEndTableRow();
    }
}

void PrintImplicitLayerJsonInfo(const char *layer_json_filename, Json::Value root) {
    bool enabled = true;
    std::string enable_env_variable = "--NONE--";
    bool enable_var_set = false;
    char enable_env_value[16];
    std::string disable_env_variable = "--NONE--";
    bool disable_var_set = false;
    char disable_env_value[16];

    PrintExplicitLayerJsonInfo(layer_json_filename, root, 4);

    Json::Value enable = root["layer"]["enable_environment"];
    if (!enable.isNull()) {
        for (Json::Value::iterator en_iter = enable.begin();
             en_iter != enable.end(); en_iter++) {
            if (en_iter.key().isNull()) {
                continue;
            }
            enable_env_variable = en_iter.key().asString();
            // If an enable define exists, set it to disabled by default.
            enabled = false;
#ifdef _WIN32
            if (0 != GetEnvironmentVariableA(enable_env_variable.c_str(),
                                             enable_env_value, 15)) {
#else
            char *enable_env = getenv(enable_env_variable.c_str());
            if (NULL != enable_env) {
                strncpy(enable_env_value, enable_env, 15);
                enable_env_value[15] = '\0';
#endif
                if (atoi(enable_env_value) != 0) {
                    enable_var_set = true;
                    enabled = true;
                }
            }
            break;
        }
    }
    Json::Value disable = root["layer"]["disable_environment"];
    if (!disable.isNull()) {
        for (Json::Value::iterator dis_iter = disable.begin();
             dis_iter != disable.end(); dis_iter++) {
            if (dis_iter.key().isNull()) {
                continue;
            }
            disable_env_variable = dis_iter.key().asString();
#ifdef _WIN32
            if (0 != GetEnvironmentVariableA(disable_env_variable.c_str(),
                                             disable_env_value, 15)) {
#else
            char *disable_env = getenv(disable_env_variable.c_str());
            if (NULL != disable_env) {
                strncpy(disable_env_value, disable_env, 15);
                disable_env_value[15] = '\0';
#endif
                if (atoi(disable_env_value) > 0) {
                    disable_var_set = true;
                    enabled = false;
                }
            }
            break;
        }
    }
    PrintBeginTableRow();
    PrintTableElement("");
    PrintTableElement("Enabled State");
    PrintTableElement(enabled ? "ENABLED" : "DISABLED");
    PrintTableElement("");
    PrintEndTableRow();
    PrintBeginTableRow();
    PrintTableElement("");
    PrintTableElement("Enable Env Var", ALIGN_RIGHT);
    PrintTableElement(enable_env_variable);
    if (enable_var_set) {
        PrintTableElement("");
    } else {
        PrintTableElement("Not Defined");
    }
    PrintEndTableRow();
    PrintBeginTableRow();
    PrintTableElement("");
    PrintTableElement("Disable Env Var", ALIGN_RIGHT);
    PrintTableElement(disable_env_variable);
    if (disable_var_set) {
        PrintTableElement(disable_env_value);
    } else {
        PrintTableElement("Not Defined");
    }
    PrintEndTableRow();
}

void PrintInstanceInfo(void) {
    VkApplicationInfo app_info;
    VkInstanceCreateInfo inst_info;
    uint32_t ext_count;
    std::vector<VkExtensionProperties> ext_props;
    VkResult status;
    char generic_string[256];

    memset(&app_info, 0, sizeof(VkApplicationInfo));
    app_info.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO;
    app_info.pNext = NULL;
    app_info.pApplicationName = "VkValidator";
    app_info.applicationVersion = 1;
    app_info.pEngineName = "VkValidator";
    app_info.engineVersion = 1;
    app_info.apiVersion = VK_API_VERSION_1_0;

    memset(&inst_info, 0, sizeof(VkInstanceCreateInfo));
    inst_info.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    inst_info.pNext = NULL;
    inst_info.pApplicationInfo = &app_info;
    inst_info.enabledLayerCount = 0;
    inst_info.ppEnabledLayerNames = NULL;
    inst_info.enabledExtensionCount = 0;
    inst_info.ppEnabledExtensionNames = NULL;

    PrintBeginTable("Coral", "Instance", 3);

    PrintBeginTableRow();
    PrintTableElement("vkEnumerateInstanceExtensionProperties");
    status = vkEnumerateInstanceExtensionProperties(NULL, &ext_count, NULL);
    if (status) {
        sprintf(generic_string,
                "ERROR: Failed to determine num inst extensions - %d", status);
        PrintTableElement(generic_string);
        PrintTableElement("");
        PrintEndTableRow();
    } else {
        sprintf(generic_string, "%d extensions found", ext_count);
        PrintTableElement(generic_string);
        PrintTableElement("");
        PrintEndTableRow();

        ext_props.resize(ext_count);
        status = vkEnumerateInstanceExtensionProperties(NULL, &ext_count,
                                                        ext_props.data());
        if (status) {
            PrintBeginTableRow();
            PrintTableElement("");
            sprintf(generic_string,
                    "ERROR: Failed to enumerate inst extensions - %d", status);
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintEndTableRow();
        } else {
            for (uint32_t iii = 0; iii < ext_count; iii++) {
                PrintBeginTableRow();
                sprintf(generic_string, "[%d]", iii);
                PrintTableElement(generic_string, ALIGN_RIGHT);
                PrintTableElement(ext_props[iii].extensionName);
                sprintf(generic_string, "Spec Vers %d",
                        ext_props[iii].specVersion);
                PrintTableElement(generic_string);
                PrintEndTableRow();
            }
        }
    }

    PrintBeginTableRow();
    PrintTableElement("vkCreateInstance");
    status = vkCreateInstance(&inst_info, NULL, &global_items.instance);
    if (status == VK_ERROR_INCOMPATIBLE_DRIVER) {
        PrintTableElement("ERROR: Incompatible Driver");
    } else if (status == VK_ERROR_OUT_OF_HOST_MEMORY) {
        PrintTableElement("ERROR: Out of memory");
    } else if (status) {
        sprintf(generic_string, "ERROR: Failed to create - %d", status);
        PrintTableElement(generic_string);
    } else {
        PrintTableElement("SUCCESSFUL");
    }
    PrintTableElement("");
    PrintEndTableRow();
    PrintEndTable();
    if (VK_SUCCESS != status) {
        throw -1;
    }
}

void PrintPhysDevInfo(void) {
    VkPhysicalDeviceProperties props;
    std::vector<VkPhysicalDevice> phys_devices;
    VkResult status;
    char generic_string[256];
    uint32_t gpu_count;
    uint32_t iii;
    uint32_t jjj;
    bool failed = false;

    PrintBeginTable("MediumOrchid", "Physical Devices", 4);

    PrintBeginTableRow();
    PrintTableElement("vkEnumeratePhysicalDevices");
    status =
        vkEnumeratePhysicalDevices(global_items.instance, &gpu_count, NULL);
    if (status) {
        sprintf(generic_string, "ERROR: Failed to query - %d", status);
        PrintTableElement(generic_string);
        failed = true;
    } else {
        sprintf(generic_string, "%d", gpu_count);
        PrintTableElement(generic_string);
    }
    PrintTableElement("");
    PrintTableElement("");
    PrintEndTableRow();

    phys_devices.resize(gpu_count);
    global_items.phys_devices.resize(gpu_count);
    status = vkEnumeratePhysicalDevices(global_items.instance, &gpu_count,
                                        phys_devices.data());
    if (VK_SUCCESS != status) {
        PrintBeginTableRow();
        PrintTableElement("");
        PrintTableElement("Failed to enumerate physical devices!");
        PrintTableElement("");
        PrintEndTableRow();
        failed = true;
    }
    for (iii = 0; iii < gpu_count; iii++) {
        global_items.phys_devices[iii].vulkan_phys_dev = phys_devices[iii];

        PrintBeginTableRow();
        sprintf(generic_string, "[%d]", iii);
        PrintTableElement(generic_string, ALIGN_RIGHT);
        if (status) {
            sprintf(generic_string, "ERROR: Failed to query - %d", status);
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintTableElement("");
            PrintEndTableRow();
        } else {
            sprintf(generic_string, "0x%p", phys_devices[iii]);
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintTableElement("");
            PrintEndTableRow();

            vkGetPhysicalDeviceProperties(phys_devices[iii], &props);

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Vendor");
            switch (props.vendorID) {
            case 0x8086:
            case 0x8087:
                sprintf(generic_string, "Intel [0x%04x]", props.vendorID);
                break;
            case 0x1002:
            case 0x1022:
                sprintf(generic_string, "AMD [0x%04x]", props.vendorID);
                break;
            case 0x10DE:
                sprintf(generic_string, "Nvidia [0x%04x]", props.vendorID);
                break;
            case 0x1EB5:
                sprintf(generic_string, "ARM [0x%04x]", props.vendorID);
                break;
            case 0x5143:
                sprintf(generic_string, "Qualcomm [0x%04x]", props.vendorID);
                break;
            case 0x1099:
            case 0x10C3:
            case 0x1249:
            case 0x4E8:
                sprintf(generic_string, "Samsung [0x%04x]", props.vendorID);
                break;
            default:
                sprintf(generic_string, "0x%04x", props.vendorID);
                break;
            }
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintEndTableRow();

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Device Name");
            PrintTableElement(props.deviceName);
            PrintTableElement("");
            PrintEndTableRow();

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Device ID");
            sprintf(generic_string, "0x%x", props.deviceID);
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintEndTableRow();

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Device Type");
            switch (props.deviceType) {
            case VK_PHYSICAL_DEVICE_TYPE_INTEGRATED_GPU:
                PrintTableElement("Integrated GPU");
                break;
            case VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU:
                PrintTableElement("Discrete GPU");
                break;
            case VK_PHYSICAL_DEVICE_TYPE_VIRTUAL_GPU:
                PrintTableElement("Virtual GPU");
                break;
            case VK_PHYSICAL_DEVICE_TYPE_CPU:
                PrintTableElement("CPU");
                break;
            case VK_PHYSICAL_DEVICE_TYPE_OTHER:
                PrintTableElement("Other");
                break;
            default:
                PrintTableElement("INVALID!");
                break;
            }
            PrintTableElement("");
            PrintEndTableRow();

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Driver Version");
            sprintf(generic_string, "%d.%d.%d",
                    VK_VERSION_MAJOR(props.driverVersion),
                    VK_VERSION_MINOR(props.driverVersion),
                    VK_VERSION_PATCH(props.driverVersion));
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintEndTableRow();

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("API Version");
            sprintf(generic_string, "%d.%d.%d",
                    VK_VERSION_MAJOR(props.apiVersion),
                    VK_VERSION_MINOR(props.apiVersion),
                    VK_VERSION_PATCH(props.apiVersion));
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintEndTableRow();

            uint32_t queue_fam_count;
            vkGetPhysicalDeviceQueueFamilyProperties(phys_devices[iii],
                                                     &queue_fam_count, NULL);
            if (queue_fam_count > 0) {
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("Queue Families");
                sprintf(generic_string, "%d", queue_fam_count);
                PrintTableElement(generic_string);
                PrintTableElement("");
                PrintEndTableRow();

                global_items.phys_devices[iii].queue_fam_props.resize(
                    queue_fam_count);
                vkGetPhysicalDeviceQueueFamilyProperties(
                    phys_devices[iii], &queue_fam_count,
                    global_items.phys_devices[iii].queue_fam_props.data());
                for (jjj = 0; jjj < queue_fam_count; jjj++) {
                    PrintBeginTableRow();
                    PrintTableElement("");
                    sprintf(generic_string, "[%d]", jjj);
                    PrintTableElement(generic_string, ALIGN_RIGHT);
                    PrintTableElement("Queue Count");
                    sprintf(generic_string, "%d", global_items.phys_devices[iii]
                                                      .queue_fam_props[jjj]
                                                      .queueCount);
                    PrintTableElement(generic_string);
                    PrintEndTableRow();

                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("");
                    PrintTableElement("Queue Flags");
                    generic_string[0] = '\0';
                    bool prev_set = false;
                    if (global_items.phys_devices[iii]
                            .queue_fam_props[jjj]
                            .queueFlags &
                        VK_QUEUE_GRAPHICS_BIT) {
                        strcat(generic_string, "GRAPHICS");
                        prev_set = true;
                    }
                    if (global_items.phys_devices[iii]
                            .queue_fam_props[jjj]
                            .queueFlags &
                        VK_QUEUE_COMPUTE_BIT) {
                        if (prev_set) {
                            strcat(generic_string, " | ");
                        }
                        strcat(generic_string, "COMPUTE");
                        prev_set = true;
                    }
                    if (global_items.phys_devices[iii]
                            .queue_fam_props[jjj]
                            .queueFlags &
                        VK_QUEUE_TRANSFER_BIT) {
                        if (prev_set) {
                            strcat(generic_string, " | ");
                        }
                        strcat(generic_string, "TRANSFER");
                        prev_set = true;
                    }
                    if (global_items.phys_devices[iii]
                            .queue_fam_props[jjj]
                            .queueFlags &
                        VK_QUEUE_SPARSE_BINDING_BIT) {
                        if (prev_set) {
                            strcat(generic_string, " | ");
                        }
                        strcat(generic_string, "SPARSE_BINDING");
                        prev_set = true;
                    }
                    if (!prev_set) {
                        strcat(generic_string, "--NONE--");
                    }
                    PrintTableElement(generic_string);
                    PrintEndTableRow();

                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("");
                    PrintTableElement("Timestamp Valid Bits");
                    sprintf(generic_string, "0x%x",
                            global_items.phys_devices[iii]
                                .queue_fam_props[jjj]
                                .timestampValidBits);
                    PrintTableElement(generic_string);
                    PrintEndTableRow();

                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("");
                    PrintTableElement("Image Granularity");
                    PrintTableElement("");
                    PrintEndTableRow();

                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("");
                    PrintTableElement("Width", ALIGN_RIGHT);
                    sprintf(generic_string, "0x%x",
                            global_items.phys_devices[iii]
                                .queue_fam_props[jjj]
                                .minImageTransferGranularity.width);
                    PrintTableElement(generic_string);
                    PrintEndTableRow();

                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("");
                    PrintTableElement("Height", ALIGN_RIGHT);
                    sprintf(generic_string, "0x%x",
                            global_items.phys_devices[iii]
                                .queue_fam_props[jjj]
                                .minImageTransferGranularity.height);
                    PrintTableElement(generic_string);
                    PrintEndTableRow();

                    PrintBeginTableRow();
                    PrintTableElement("");
                    PrintTableElement("");
                    PrintTableElement("Depth", ALIGN_RIGHT);
                    sprintf(generic_string, "0x%x",
                            global_items.phys_devices[iii]
                                .queue_fam_props[jjj]
                                .minImageTransferGranularity.depth);
                    PrintTableElement(generic_string);
                    PrintEndTableRow();
                }
            } else {
                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("vkGetPhysicalDeviceQueueFamilyProperties");
                PrintTableElement("FAILED: Returned 0!");
                PrintTableElement("");
                PrintEndTableRow();
            }

            VkPhysicalDeviceMemoryProperties memory_props;
            vkGetPhysicalDeviceMemoryProperties(phys_devices[iii],
                                                &memory_props);

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Memory Heaps");
            sprintf(generic_string, "%d", memory_props.memoryHeapCount);
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintEndTableRow();

            for (jjj = 0; jjj < memory_props.memoryHeapCount; jjj++) {
                PrintBeginTableRow();
                PrintTableElement("");
                sprintf(generic_string, "[%d]", jjj);
                PrintTableElement(generic_string, ALIGN_RIGHT);
                PrintTableElement("Property Flags");
                generic_string[0] = '\0';
                bool prev_set = false;
                if (memory_props.memoryHeaps[jjj].flags &
                    VK_MEMORY_HEAP_DEVICE_LOCAL_BIT) {
                    strcat(generic_string, "DEVICE_LOCAL");
                    prev_set = true;
                }
                if (!prev_set) {
                    strcat(generic_string, "--NONE--");
                }
                PrintTableElement(generic_string);
                PrintEndTableRow();

                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("");
                PrintTableElement("Heap Size");
                sprintf(generic_string, "%" PRIu64 "",
                        static_cast<uint64_t>(memory_props.memoryHeaps[jjj].size));
                PrintTableElement(generic_string);
                PrintEndTableRow();
            }

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Memory Types");
            sprintf(generic_string, "%d", memory_props.memoryTypeCount);
            PrintTableElement(generic_string);
            PrintTableElement("");
            PrintEndTableRow();

            for (jjj = 0; jjj < memory_props.memoryTypeCount; jjj++) {
                PrintBeginTableRow();
                PrintTableElement("");
                sprintf(generic_string, "[%d]", jjj);
                PrintTableElement(generic_string, ALIGN_RIGHT);
                PrintTableElement("Property Flags");
                generic_string[0] = '\0';
                bool prev_set = false;
                if (memory_props.memoryTypes[jjj].propertyFlags &
                    VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT) {
                    strcat(generic_string, "DEVICE_LOCAL");
                    prev_set = true;
                }
                if (memory_props.memoryTypes[jjj].propertyFlags &
                    VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT) {
                    if (prev_set) {
                        strcat(generic_string, " | ");
                    }
                    strcat(generic_string, "HOST_VISIBLE");
                    prev_set = true;
                }
                if (memory_props.memoryTypes[jjj].propertyFlags &
                    VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) {
                    if (prev_set) {
                        strcat(generic_string, " | ");
                    }
                    strcat(generic_string, "HOST_COHERENT");
                    prev_set = true;
                }
                if (memory_props.memoryTypes[jjj].propertyFlags &
                    VK_MEMORY_PROPERTY_HOST_CACHED_BIT) {
                    if (prev_set) {
                        strcat(generic_string, " | ");
                    }
                    strcat(generic_string, "HOST_CACHED");
                    prev_set = true;
                }
                if (memory_props.memoryTypes[jjj].propertyFlags &
                    VK_MEMORY_PROPERTY_LAZILY_ALLOCATED_BIT) {
                    if (prev_set) {
                        strcat(generic_string, " | ");
                    }
                    strcat(generic_string, "LAZILY_ALLOC");
                    prev_set = true;
                }
                if (!prev_set) {
                    strcat(generic_string, "--NONE--");
                }
                PrintTableElement(generic_string);
                PrintEndTableRow();

                PrintBeginTableRow();
                PrintTableElement("");
                PrintTableElement("");
                PrintTableElement("Heap Index");
                sprintf(generic_string, "%d",
                        memory_props.memoryTypes[jjj].heapIndex);
                PrintTableElement(generic_string);
                PrintEndTableRow();
            }

            uint32_t num_ext_props;
            std::vector<VkExtensionProperties> ext_props;

            PrintBeginTableRow();
            PrintTableElement("");
            PrintTableElement("Device Extensions");
            status = vkEnumerateDeviceExtensionProperties(
                phys_devices[iii], NULL, &num_ext_props, NULL);
            if (VK_SUCCESS != status) {
                PrintTableElement("FAILED querying number of extensions");
                PrintTableElement("");
                PrintEndTableRow();

                failed = true;
            } else {
                sprintf(generic_string, "%d", num_ext_props);
                PrintTableElement(generic_string);
                ext_props.resize(num_ext_props);
                status = vkEnumerateDeviceExtensionProperties(
                    phys_devices[iii], NULL, &num_ext_props, ext_props.data());
                if (VK_SUCCESS != status) {
                    PrintTableElement("FAILED querying actual extension info");
                    PrintEndTableRow();

                    failed = true;
                } else {
                    PrintTableElement("");
                    PrintEndTableRow();

                    for (jjj = 0; jjj < num_ext_props; jjj++) {
                        PrintBeginTableRow();
                        PrintTableElement("");
                        sprintf(generic_string, "[%d]", jjj);
                        PrintTableElement(generic_string, ALIGN_RIGHT);
                        PrintTableElement(ext_props[jjj].extensionName);
                        sprintf(generic_string, "Spec Vers %d",
                                ext_props[jjj].specVersion);
                        PrintTableElement(generic_string);
                        PrintEndTableRow();
                    }
                }
            }
        }
    }

    PrintEndTable();

    if (failed) {
        throw -1;
    }
}

void PrintLogicalDeviceInfo(void) {
    VkDeviceCreateInfo device_create_info;
    VkDeviceQueueCreateInfo queue_create_info;
    VkResult status = VK_SUCCESS;
    uint32_t dev_count =
        static_cast<uint32_t>(global_items.phys_devices.size());
    char generic_string[256];
    bool failed = false;

    PrintBeginTable("Olive", "Logical Devices", 3);

    PrintBeginTableRow();
    PrintTableElement("vkCreateDevice");
    sprintf(generic_string, "%d", dev_count);
    PrintTableElement(generic_string);
    PrintTableElement("");
    PrintEndTableRow();

    global_items.log_devices.resize(dev_count);
    for (uint32_t dev = 0; dev < dev_count; dev++) {
        memset(&device_create_info, 0, sizeof(VkDeviceCreateInfo));
        device_create_info.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
        device_create_info.pNext = NULL;
        device_create_info.queueCreateInfoCount = 0;
        device_create_info.pQueueCreateInfos = NULL;
        device_create_info.enabledLayerCount = 0;
        device_create_info.ppEnabledLayerNames = NULL;
        device_create_info.enabledExtensionCount = 0;
        device_create_info.ppEnabledExtensionNames = NULL;
        device_create_info.queueCreateInfoCount = 1;
        device_create_info.enabledLayerCount = 0;
        device_create_info.ppEnabledLayerNames = NULL;
        device_create_info.enabledExtensionCount = 0;
        device_create_info.ppEnabledExtensionNames = NULL;

        memset(&queue_create_info, 0, sizeof(VkDeviceQueueCreateInfo));
        float queue_priority = 0;
        queue_create_info.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
        queue_create_info.pNext = NULL;
        queue_create_info.queueCount = 1;
        queue_create_info.pQueuePriorities = &queue_priority;

        for (uint32_t queue = 0;
             queue < global_items.phys_devices[dev].queue_fam_props.size();
             queue++) {
            if (0 != (global_items.phys_devices[dev]
                          .queue_fam_props[queue]
                          .queueFlags &
                      VK_QUEUE_GRAPHICS_BIT)) {
                queue_create_info.queueFamilyIndex = queue;
                break;
            }
        }
        device_create_info.pQueueCreateInfos = &queue_create_info;

        PrintBeginTableRow();
        PrintTableElement("");
        sprintf(generic_string, "[%d]", dev);
        PrintTableElement(generic_string);

        status = vkCreateDevice(global_items.phys_devices[dev].vulkan_phys_dev,
                                &device_create_info, NULL,
                                &global_items.log_devices[dev]);
        if (VK_ERROR_INCOMPATIBLE_DRIVER == status) {
            PrintTableElement("FAILED: Incompatible Driver");
            failed = true;
        } else if (VK_ERROR_OUT_OF_HOST_MEMORY == status) {
            PrintTableElement("FAILED: Out of Host Memory");
            failed = true;
        } else if (VK_SUCCESS != status) {
            sprintf(generic_string, "FAILED : VkResult code = 0x%x", status);
            PrintTableElement(generic_string);
            failed = true;
        } else {
            PrintTableElement("SUCCESSFUL");
        }

        PrintEndTableRow();
    }

    PrintEndTable();
    if (failed) {
        throw -1;
    }
}

void PrintCleanupInfo(void) {
    char generic_string[256];
    uint32_t dev_count =
        static_cast<uint32_t>(global_items.phys_devices.size());

    PrintBeginTable("Cyan", "Cleanup", 3);

    PrintBeginTableRow();
    PrintTableElement("vkDestroyDevice");
    sprintf(generic_string, "%d", dev_count);
    PrintTableElement(generic_string);
    PrintTableElement("");
    PrintEndTableRow();
    for (uint32_t dev = 0; dev < dev_count; dev++) {
        vkDestroyDevice(global_items.log_devices[dev], NULL);
        PrintTableElement("");
        sprintf(generic_string, "[%d]", dev);
        PrintTableElement(generic_string, ALIGN_RIGHT);
        PrintTableElement("SUCCESSFUL");
        PrintEndTableRow();
    }

    PrintBeginTableRow();
    PrintTableElement("vkDestroyInstance");
    vkDestroyInstance(global_items.instance, NULL);
    PrintTableElement("SUCCESSFUL");
    PrintTableElement("");
    PrintEndTableRow();

    PrintEndTable();
}

void PrintTestResults(void) {
    bool failed = false;

    BeginSection("Vulkan Tests");
    if (global_items.sdk_found) {
        std::string cube_exe = "cube.exe --c 100";
        std::string path = global_items.sdk_path;

#if _WIN64
        path += "\\Bin";
#elif WIN32
        if (global_items.is_wow64) {
            path += "\\Bin32";
        } else {
            path += "\\Bin";
        }
#endif

        PrintBeginTable("FireBrick", "Cube", 2);

        PrintBeginTableRow();
        PrintTableElement("cube.exe --c 100");
        if (0 != RunTestInDirectory(path, cube_exe.c_str())) {
            PrintTableElement("FAILED!");
            failed = true;
        } else {
            PrintTableElement("SUCCESSFUL");
        }
        PrintEndTableRow();

        cube_exe += " --validate";

        PrintBeginTableRow();
        PrintTableElement("cube.exe --c 100 --validate");
        if (0 != RunTestInDirectory(path, cube_exe.c_str())) {
            PrintTableElement("FAILED!");
            failed = true;
        } else {
            PrintTableElement("SUCCESSFUL");
        }
        PrintEndTableRow();

        PrintEndTable();
    } else {
        BeginSubSection("No SDK Installed.  Skipping Tests");
    }
    EndSection();

    if (failed) {
        throw -1;
    }
}

void PrintVulkanInfo(void) {
    BeginSection("Vulkan Calls");

    PrintInstanceInfo();
    PrintPhysDevInfo();
    PrintLogicalDeviceInfo();
    PrintCleanupInfo();

    EndSection();
}
