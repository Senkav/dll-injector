// DLL Injector — Win32 GUI, zero external dependencies
// Compile: cl /std:c++20 /O2 /W4 /EHsc /DUNICODE /D_UNICODE
//          /MT injector_gui.cpp /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib comctl32.lib shell32.lib
//
// Or via Developer Command Prompt:
// cl /std:c++20 /O2 /W4 /EHsc /DUNICODE /D_UNICODE /MT injector_gui.cpp ^
//    /link /SUBSYSTEM:WINDOWS user32.lib kernel32.lib comctl32.lib shell32.lib

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <system_error>
#include <vector>
#include <expected>
#include <format>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ─────────────────────────────────────────────────────────────────────────────
// Control IDs
// ─────────────────────────────────────────────────────────────────────────────
enum : int {
    ID_DLL_EDIT    = 101,
    ID_DLL_BROWSE  = 102,
    ID_PROC_LIST   = 103,
    ID_PROC_REFRESH= 104,
    ID_METHOD_COMBO= 105,
    ID_INJECT_BTN  = 106,
    ID_LOG_EDIT    = 107,
    ID_STATUS_BAR  = 108,
    ID_FILTER_EDIT = 109,
};

// ─────────────────────────────────────────────────────────────────────────────
// RAII handle
// ─────────────────────────────────────────────────────────────────────────────
struct HandleDeleter { void operator()(HANDLE h) const noexcept { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); } };
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;
[[nodiscard]] inline UniqueHandle wrapHandle(HANDLE h) noexcept { return UniqueHandle{h}; }

// ─────────────────────────────────────────────────────────────────────────────
// Process list entry
// ─────────────────────────────────────────────────────────────────────────────
struct ProcessEntry {
    DWORD        pid;
    std::wstring name;
};

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
static HWND g_hWnd        = nullptr;
static HWND g_hDllEdit    = nullptr;
static HWND g_hProcList   = nullptr;
static HWND g_hMethodCombo= nullptr;
static HWND g_hLog        = nullptr;
static HWND g_hStatus     = nullptr;
static HWND g_hFilter     = nullptr;
static HFONT g_hFont      = nullptr;
static HFONT g_hFontMono  = nullptr;

static std::vector<ProcessEntry> g_allProcs;   // full unfiltered list

// ─────────────────────────────────────────────────────────────────────────────
// Logging helper
// ─────────────────────────────────────────────────────────────────────────────
static void log(const std::wstring& msg, COLORREF /*col*/ = 0) {
    // Append to log edit — use CR+LF
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    std::wstring line = msg + L"\r\n";
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

static void setStatus(const wchar_t* msg) {
    if (g_hStatus) SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)msg);
}

// ─────────────────────────────────────────────────────────────────────────────
// Process enumeration
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<ProcessEntry> enumProcesses() {
    std::vector<ProcessEntry> result;
    auto snap = wrapHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap || snap.get() == INVALID_HANDLE_VALUE) return result;

    PROCESSENTRY32W e{};
    e.dwSize = sizeof(e);
    if (!Process32FirstW(snap.get(), &e)) return result;
    do {
        result.push_back({ e.th32ProcessID, e.szExeFile });
    } while (Process32NextW(snap.get(), &e));

    std::sort(result.begin(), result.end(), [](auto& a, auto& b){
        // case-insensitive name sort
        std::wstring an = a.name, bn = b.name;
        for (auto& c : an) c = (wchar_t)towlower(c);
        for (auto& c : bn) c = (wchar_t)towlower(c);
        return an < bn;
    });
    return result;
}

static void populateProcList(const std::wstring& filter = L"") {
    SendMessageW(g_hProcList, LB_RESETCONTENT, 0, 0);
    std::wstring lf = filter;
    for (auto& c : lf) c = (wchar_t)towlower(c);

    for (auto& p : g_allProcs) {
        std::wstring low = p.name;
        for (auto& c : low) c = (wchar_t)towlower(c);
        if (!lf.empty() && low.find(lf) == std::wstring::npos) continue;
        std::wstring entry = std::format(L"[{:>6}]  {}", p.pid, p.name);
        LRESULT idx = SendMessageW(g_hProcList, LB_ADDSTRING, 0, (LPARAM)entry.c_str());
        SendMessageW(g_hProcList, LB_SETITEMDATA, idx, (LPARAM)p.pid);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Inject — LoadLibraryA
// ─────────────────────────────────────────────────────────────────────────────
static bool injectLoadLibrary(DWORD pid, const std::filesystem::path& dllPath) {
    log(std::format(L"[LoadLibrary] → PID {} | {}", pid, dllPath.wstring()));

    const DWORD kAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;
    auto hProc = wrapHandle(OpenProcess(kAccess, FALSE, pid));
    if (!hProc) {
        log(std::format(L"  ✗ OpenProcess failed: {}", GetLastError()));
        return false;
    }

    const std::string pathA = dllPath.string();
    const SIZE_T sz = pathA.size() + 1;

    LPVOID rem = VirtualAllocEx(hProc.get(), nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { log(std::format(L"  ✗ VirtualAllocEx failed: {}", GetLastError())); return false; }

    auto freeRem = [&]{ VirtualFreeEx(hProc.get(), rem, 0, MEM_RELEASE); };

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc.get(), rem, pathA.c_str(), sz, &written) || written != sz) {
        freeRem();
        log(std::format(L"  ✗ WriteProcessMemory failed: {}", GetLastError()));
        return false;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    auto pfn = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hK32, "LoadLibraryA"));

    auto hThread = wrapHandle(CreateRemoteThread(hProc.get(), nullptr, 0, pfn, rem, 0, nullptr));
    if (!hThread) {
        freeRem();
        log(std::format(L"  ✗ CreateRemoteThread failed: {}", GetLastError()));
        return false;
    }

    WaitForSingleObject(hThread.get(), 10000);
    DWORD code = 0;
    GetExitCodeThread(hThread.get(), &code);
    freeRem();

    if (!code) { log(L"  ✗ LoadLibraryA returned NULL (check DLL arch / path)"); return false; }
    log(std::format(L"  ✓ Success! hModule = 0x{:X}", code));
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Loader params + shellcode for ManualMap
// ─────────────────────────────────────────────────────────────────────────────
#pragma pack(push, 1)
struct LoaderParams {
    BYTE*   base;
    DWORD   ntOffset;
    using FnLL  = HMODULE(WINAPI*)(LPCSTR);
    using FnGPA = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    FnLL  pfnLoadLibraryA;
    FnGPA pfnGetProcAddress;
};
#pragma pack(pop)

static DWORD WINAPI shellcodeLoader(LoaderParams* p) {
    if (!p) return 0;
    BYTE* base = p->base;
    auto* nt   = reinterpret_cast<IMAGE_NT_HEADERS*>(base + p->ntOffset);
    ULONGLONG delta = reinterpret_cast<ULONGLONG>(base) - nt->OptionalHeader.ImageBase;

    // Relocations
    if (delta) {
        auto* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir->Size) {
            auto* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + dir->VirtualAddress);
            while (blk->VirtualAddress) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                auto* rel = reinterpret_cast<WORD*>(blk + 1);
                for (DWORD i = 0; i < cnt; i++)
                    if ((rel[i] >> 12) == IMAGE_REL_BASED_DIR64)
                        *reinterpret_cast<ULONGLONG*>(base + blk->VirtualAddress + (rel[i] & 0xFFF)) += delta;
                blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(blk) + blk->SizeOfBlock);
            }
        }
    }

    // IAT
    auto* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->Size) {
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + impDir->VirtualAddress);
        while (desc->Name) {
            HMODULE hMod = p->pfnLoadLibraryA(reinterpret_cast<LPCSTR>(base + desc->Name));
            auto* thunkO = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
            auto* thunk  = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
            while (thunkO->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(thunkO->u1.Ordinal))
                    thunk->u1.Function = reinterpret_cast<ULONGLONG>(
                        p->pfnGetProcAddress(hMod, reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(thunkO->u1.Ordinal))));
                else {
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunkO->u1.AddressOfData);
                    thunk->u1.Function = reinterpret_cast<ULONGLONG>(p->pfnGetProcAddress(hMod, ibn->Name));
                }
                ++thunkO; ++thunk;
            }
            ++desc;
        }
    }

    // DllMain
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        auto dllMain = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(
            base + nt->OptionalHeader.AddressOfEntryPoint);
        return dllMain(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr);
    }
    return 1;
}
static void shellcodeEnd() {}

static bool injectManualMap(DWORD pid, const std::filesystem::path& dllPath) {
    log(std::format(L"[ManualMap] → PID {} | {}", pid, dllPath.wstring()));

    // Read file
    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        log(std::format(L"  ✗ Cannot open DLL: {}", GetLastError())); return false;
    }
    auto fh = wrapHandle(hFile);
    DWORD fsz = GetFileSize(hFile, nullptr);
    std::vector<BYTE> raw(fsz);
    DWORD rd = 0;
    ReadFile(hFile, raw.data(), fsz, &rd, nullptr);

    // Validate PE
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { log(L"  ✗ Not a valid PE (bad DOS sig)"); return false; }
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(raw.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { log(L"  ✗ Not a valid PE (bad NT sig)"); return false; }

    const DWORD kAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;
    auto hProc = wrapHandle(OpenProcess(kAccess, FALSE, pid));
    if (!hProc) { log(std::format(L"  ✗ OpenProcess failed: {}", GetLastError())); return false; }

    // Allocate image
    LPVOID remImg = VirtualAllocEx(hProc.get(),
        reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase),
        nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remImg)
        remImg = VirtualAllocEx(hProc.get(), nullptr,
            nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remImg) { log(std::format(L"  ✗ VirtualAllocEx(image) failed: {}", GetLastError())); return false; }

    // Headers
    WriteProcessMemory(hProc.get(), remImg, raw.data(), nt->OptionalHeader.SizeOfHeaders, nullptr);

    // Sections
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        WriteProcessMemory(hProc.get(), static_cast<BYTE*>(remImg) + sec->VirtualAddress,
                           raw.data() + sec->PointerToRawData, sec->SizeOfRawData, nullptr);
    }

    // Shellcode
    SIZE_T stubSz = reinterpret_cast<SIZE_T>(shellcodeEnd) - reinterpret_cast<SIZE_T>(shellcodeLoader);
    SIZE_T totalSz = sizeof(LoaderParams) + stubSz;
    LPVOID remStub = VirtualAllocEx(hProc.get(), nullptr, totalSz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remStub) {
        VirtualFreeEx(hProc.get(), remImg, 0, MEM_RELEASE);
        log(std::format(L"  ✗ VirtualAllocEx(stub) failed: {}", GetLastError()));
        return false;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    LoaderParams lp{};
    lp.base              = static_cast<BYTE*>(remImg);
    lp.ntOffset          = dos->e_lfanew;
    lp.pfnLoadLibraryA   = reinterpret_cast<LoaderParams::FnLL>(GetProcAddress(hK32, "LoadLibraryA"));
    lp.pfnGetProcAddress = reinterpret_cast<LoaderParams::FnGPA>(GetProcAddress(hK32, "GetProcAddress"));

    WriteProcessMemory(hProc.get(), remStub, &lp, sizeof(LoaderParams), nullptr);
    WriteProcessMemory(hProc.get(), static_cast<BYTE*>(remStub) + sizeof(LoaderParams),
                       reinterpret_cast<LPCVOID>(shellcodeLoader), stubSz, nullptr);

    auto hT = wrapHandle(CreateRemoteThread(hProc.get(), nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<BYTE*>(remStub) + sizeof(LoaderParams)),
        remStub, 0, nullptr));

    if (!hT) {
        VirtualFreeEx(hProc.get(), remImg, 0, MEM_RELEASE);
        VirtualFreeEx(hProc.get(), remStub, 0, MEM_RELEASE);
        log(std::format(L"  ✗ CreateRemoteThread failed: {}", GetLastError()));
        return false;
    }

    WaitForSingleObject(hT.get(), 10000);
    DWORD code = 0;
    GetExitCodeThread(hT.get(), &code);
    VirtualFreeEx(hProc.get(), remStub, 0, MEM_RELEASE);

    if (!code) { log(L"  ✗ DllMain returned FALSE"); VirtualFreeEx(hProc.get(), remImg, 0, MEM_RELEASE); return false; }
    log(std::format(L"  ✓ Success! Base = 0x{:X}", reinterpret_cast<uintptr_t>(remImg)));
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Elevation helper
// ─────────────────────────────────────────────────────────────────────────────
static bool isElevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    auto t = wrapHandle(tok);
    TOKEN_ELEVATION e{}; DWORD n = 0;
    GetTokenInformation(t.get(), TokenElevation, &e, sizeof(e), &n);
    return e.TokenIsElevated != 0;
}

static void relaunchElevated() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    ShellExecuteW(nullptr, L"runas", path, nullptr, nullptr, SW_SHOWNORMAL);
}

// ─────────────────────────────────────────────────────────────────────────────
// Browse for DLL
// ─────────────────────────────────────────────────────────────────────────────
static void browseDll() {
    wchar_t buf[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = g_hWnd;
    ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile   = buf;
    ofn.nMaxFile    = MAX_PATH;
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrTitle  = L"Select DLL to Inject";
    if (GetOpenFileNameW(&ofn))
        SetWindowTextW(g_hDllEdit, buf);
}

// ─────────────────────────────────────────────────────────────────────────────
// Inject button handler
// ─────────────────────────────────────────────────────────────────────────────
static void doInject() {
    // DLL path
    wchar_t dllBuf[MAX_PATH]{};
    GetWindowTextW(g_hDllEdit, dllBuf, MAX_PATH);
    if (!dllBuf[0]) { MessageBoxW(g_hWnd, L"Select a DLL first.", L"Error", MB_ICONWARNING); return; }

    std::filesystem::path dllPath{dllBuf};
    if (!std::filesystem::exists(dllPath)) {
        MessageBoxW(g_hWnd, L"DLL file not found.", L"Error", MB_ICONERROR); return;
    }

    // PID from list selection
    LRESULT sel = SendMessageW(g_hProcList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) { MessageBoxW(g_hWnd, L"Select a process from the list.", L"Error", MB_ICONWARNING); return; }
    DWORD pid = static_cast<DWORD>(SendMessageW(g_hProcList, LB_GETITEMDATA, sel, 0));

    // Method
    int method = static_cast<int>(SendMessageW(g_hMethodCombo, CB_GETCURSEL, 0, 0));

    log(L"─────────────────────────────────────");
    bool ok = (method == 0) ? injectLoadLibrary(pid, dllPath)
                            : injectManualMap(pid, dllPath);
    setStatus(ok ? L"✓ Injection succeeded" : L"✗ Injection failed — see log");
}

// ─────────────────────────────────────────────────────────────────────────────
// Layout / creation
// ─────────────────────────────────────────────────────────────────────────────
static void createControls(HWND hWnd) {
    // Fonts
    g_hFont     = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    g_hFontMono = CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

    auto addLabel = [&](const wchar_t* txt, int x, int y, int w, int h) {
        HWND hw = CreateWindowExW(0, L"STATIC", txt, WS_CHILD|WS_VISIBLE|SS_LEFT,
                                  x, y, w, h, hWnd, nullptr, nullptr, nullptr);
        SendMessageW(hw, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        return hw;
    };
    auto addCtrl = [&](DWORD ex, const wchar_t* cls, const wchar_t* txt, DWORD style,
                        int x, int y, int w, int h, int id) {
        HWND hw = CreateWindowExW(ex, cls, txt, WS_CHILD|WS_VISIBLE|style,
                                  x, y, w, h, hWnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
        SendMessageW(hw, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        return hw;
    };

    // ── Section: DLL ─────────────────────────────────────────
    addLabel(L"DLL Path", 12, 14, 80, 20);
    g_hDllEdit = addCtrl(WS_EX_CLIENTEDGE, L"EDIT", L"", ES_AUTOHSCROLL,
                         12, 34, 520, 24, ID_DLL_EDIT);
    addCtrl(0, L"BUTTON", L"Browse…", BS_PUSHBUTTON,
            538, 34, 80, 24, ID_DLL_BROWSE);

    // ── Section: Process ────────────────────────────────────
    addLabel(L"Filter processes:", 12, 70, 120, 20);
    g_hFilter = addCtrl(WS_EX_CLIENTEDGE, L"EDIT", L"", ES_AUTOHSCROLL,
                        134, 68, 250, 22, ID_FILTER_EDIT);
    addCtrl(0, L"BUTTON", L"↺ Refresh", BS_PUSHBUTTON,
            394, 68, 80, 22, ID_PROC_REFRESH);

    g_hProcList = addCtrl(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
                          LBS_NOTIFY|WS_VSCROLL|LBS_NOINTEGRALHEIGHT,
                          12, 96, 606, 200, ID_PROC_LIST);
    SendMessageW(g_hProcList, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);

    // ── Section: Method + Inject ────────────────────────────
    addLabel(L"Method:", 12, 308, 60, 22);
    g_hMethodCombo = addCtrl(0, L"COMBOBOX", L"",
                              CBS_DROPDOWNLIST|WS_VSCROLL,
                              76, 306, 200, 150, ID_METHOD_COMBO);
    SendMessageW(g_hMethodCombo, CB_ADDSTRING, 0, (LPARAM)L"LoadLibraryA  (standard)");
    SendMessageW(g_hMethodCombo, CB_ADDSTRING, 0, (LPARAM)L"Manual Map    (stealth)");
    SendMessageW(g_hMethodCombo, CB_SETCURSEL, 0, 0);

    addCtrl(0, L"BUTTON", L"⚡  INJECT", BS_PUSHBUTTON|BS_DEFPUSHBUTTON,
            450, 304, 168, 30, ID_INJECT_BTN);

    // ── Log ─────────────────────────────────────────────────
    addLabel(L"Log:", 12, 346, 40, 18);
    g_hLog = addCtrl(WS_EX_CLIENTEDGE, L"EDIT", L"",
                     ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,
                     12, 366, 606, 180, ID_LOG_EDIT);
    SendMessageW(g_hLog, WM_SETFONT, (WPARAM)g_hFontMono, TRUE);

    // ── Status bar ───────────────────────────────────────────
    g_hStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"Ready",
                                 WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP,
                                 0, 0, 0, 0, hWnd, (HMENU)ID_STATUS_BAR, nullptr, nullptr);
    SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    // Elevation warning in log
    if (!isElevated())
        log(L"⚠  Not running as Administrator — some processes may be inaccessible.");
    else
        log(L"✓  Running as Administrator.");
}

static void onSize(HWND hWnd) {
    RECT rc; GetClientRect(hWnd, &rc);
    int W = rc.right - rc.left;
    // Resize DLL edit
    SetWindowPos(g_hDllEdit, nullptr, 0,0, W - 104, 24, SWP_NOMOVE|SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hWnd, ID_DLL_BROWSE), nullptr, W - 80, 34, 70, 24, SWP_NOZORDER);
    // Resize process list
    SetWindowPos(g_hProcList, nullptr, 0,0, W - 24, 200, SWP_NOMOVE|SWP_NOZORDER);
    // Resize inject button
    SetWindowPos(GetDlgItem(hWnd, ID_INJECT_BTN), nullptr, W - 180, 304, 168, 30, SWP_NOZORDER);
    // Resize log
    int logH = rc.bottom - 366 - 24;
    if (logH < 60) logH = 60;
    SetWindowPos(g_hLog, nullptr, 0,0, W - 24, logH, SWP_NOMOVE|SWP_NOZORDER);
    // Status
    SendMessageW(g_hStatus, WM_SIZE, 0, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Window proc
// ─────────────────────────────────────────────────────────────────────────────
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g_hWnd = hWnd;
        createControls(hWnd);
        g_allProcs = enumProcesses();
        populateProcList();
        return 0;

    case WM_SIZE:
        onSize(hWnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_DLL_BROWSE:
            browseDll();
            break;
        case ID_PROC_REFRESH:
            g_allProcs = enumProcesses();
            { wchar_t f[128]{}; GetWindowTextW(g_hFilter, f, 128); populateProcList(f); }
            setStatus(std::format(L"Refreshed — {} processes", g_allProcs.size()).c_str());
            break;
        case ID_INJECT_BTN:
            doInject();
            break;
        case ID_FILTER_EDIT:
            if (HIWORD(wParam) == EN_CHANGE) {
                wchar_t f[128]{}; GetWindowTextW(g_hFilter, f, 128);
                populateProcList(f);
            }
            break;
        }
        return 0;

    case WM_CTLCOLORSTATIC: {
        // Give log area a dark bg
        HDC hdc = reinterpret_cast<HDC>(wParam);
        SetBkColor(hdc, RGB(20, 20, 28));
        SetTextColor(hdc, RGB(180, 230, 180));
        static HBRUSH br = CreateSolidBrush(RGB(20, 20, 28));
        return reinterpret_cast<LRESULT>(br);
    }

    case WM_GETMINMAXINFO: {
        auto* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        mmi->ptMinTrackSize = { 640, 580 };
        return 0;
    }

    case WM_DESTROY:
        if (g_hFont)     DeleteObject(g_hFont);
        if (g_hFontMono) DeleteObject(g_hFontMono);
        PostQuitMessage(0);
        return 0;

    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0) == SC_CLOSE) { DestroyWindow(hWnd); return 0; }
        break;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// WinMain
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR cmdLine, int) {
    // Ask for elevation if not already elevated
    if (!isElevated()) {
        int r = MessageBoxW(nullptr,
            L"DLL Injector needs Administrator rights to inject into most processes.\n\n"
            L"Restart as Administrator?",
            L"DLL Injector", MB_YESNO | MB_ICONQUESTION);
        if (r == IDYES) { relaunchElevated(); return 0; }
    }

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"DllInjectorWnd";
    wc.hIcon         = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND hWnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        L"DllInjectorWnd",
        L"DLL Injector  ·  LoadLibrary + ManualMap",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        640, 620,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}
