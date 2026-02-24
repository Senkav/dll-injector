#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// ─────────────────────────────────────────────────────────────────────────────
// Control IDs
// ─────────────────────────────────────────────────────────────────────────────
enum : int {
    ID_DLL_EDIT     = 101,
    ID_DLL_BROWSE   = 102,
    ID_PROC_LIST    = 103,
    ID_PROC_REFRESH = 104,
    ID_METHOD_COMBO = 105,
    ID_INJECT_BTN   = 106,
    ID_LOG_EDIT     = 107,
    ID_STATUS_BAR   = 108,
    ID_FILTER_EDIT  = 109,
};

// ─────────────────────────────────────────────────────────────────────────────
// RAII HANDLE wrapper
// ─────────────────────────────────────────────────────────────────────────────
struct HandleDeleter {
    void operator()(HANDLE h) const noexcept {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using UniqueHandle = std::unique_ptr<std::remove_pointer_t<HANDLE>, HandleDeleter>;
static inline UniqueHandle wrapHandle(HANDLE h) noexcept { return UniqueHandle{h}; }

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
static HWND  g_hWnd         = nullptr;
static HWND  g_hDllEdit     = nullptr;
static HWND  g_hProcList    = nullptr;
static HWND  g_hMethodCombo = nullptr;
static HWND  g_hLog         = nullptr;
static HWND  g_hStatus      = nullptr;
static HWND  g_hFilter      = nullptr;
static HFONT g_hFont        = nullptr;
static HFONT g_hFontMono    = nullptr;

struct ProcessEntry { DWORD pid; std::wstring name; };
static std::vector<ProcessEntry> g_allProcs;

// ─────────────────────────────────────────────────────────────────────────────
// Log / status helpers
// ─────────────────────────────────────────────────────────────────────────────
static void log(const std::wstring& msg) {
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    std::wstring line = msg + L"\r\n";
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
    SendMessageW(g_hLog, EM_SCROLLCARET, 0, 0);
}

static void setStatus(const wchar_t* msg) {
    if (g_hStatus) SendMessageW(g_hStatus, SB_SETTEXTW, 0, (LPARAM)msg);
}

// ─────────────────────────────────────────────────────────────────────────────
// Process list
// ─────────────────────────────────────────────────────────────────────────────
static std::vector<ProcessEntry> enumProcesses() {
    std::vector<ProcessEntry> result;
    auto snap = wrapHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap || snap.get() == INVALID_HANDLE_VALUE) return result;
    PROCESSENTRY32W e{};
    e.dwSize = sizeof(e);
    if (!Process32FirstW(snap.get(), &e)) return result;
    do {
        result.push_back({ e.th32ProcessID, std::wstring(e.szExeFile) });
    } while (Process32NextW(snap.get(), &e));
    std::sort(result.begin(), result.end(), [](const ProcessEntry& a, const ProcessEntry& b) {
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
        wchar_t entry[512];
        swprintf_s(entry, 512, L"[%6lu]  %s", (unsigned long)p.pid, p.name.c_str());
        LRESULT idx = SendMessageW(g_hProcList, LB_ADDSTRING, 0, (LPARAM)entry);
        SendMessageW(g_hProcList, LB_SETITEMDATA, (WPARAM)idx, (LPARAM)p.pid);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Elevation
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
// Browse DLL
// ─────────────────────────────────────────────────────────────────────────────
static void browseDll() {
    wchar_t buf[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(OPENFILENAMEW);
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
// Inject — LoadLibraryA
// ─────────────────────────────────────────────────────────────────────────────
static bool injectLoadLibrary(DWORD pid, const wchar_t* dllPathW) {
    // Convert wide path to narrow
    char pathA[MAX_PATH]{};
    WideCharToMultiByte(CP_ACP, 0, dllPathW, -1, pathA, MAX_PATH, nullptr, nullptr);

    log(std::wstring(L"[LoadLibrary] PID: ") + std::to_wstring(pid));
    log(std::wstring(L"  DLL: ") + dllPathW);

    const DWORD kAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;
    auto hProc = wrapHandle(OpenProcess(kAccess, FALSE, pid));
    if (!hProc) {
        log(L"  X OpenProcess failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    SIZE_T sz  = strlen(pathA) + 1;
    LPVOID rem = VirtualAllocEx(hProc.get(), nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) {
        log(L"  X VirtualAllocEx failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc.get(), rem, pathA, sz, &written) || written != sz) {
        VirtualFreeEx(hProc.get(), rem, 0, MEM_RELEASE);
        log(L"  X WriteProcessMemory failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    auto pfn = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(hK32, "LoadLibraryA"));

    auto hThread = wrapHandle(
        CreateRemoteThread(hProc.get(), nullptr, 0, pfn, rem, 0, nullptr));
    if (!hThread) {
        VirtualFreeEx(hProc.get(), rem, 0, MEM_RELEASE);
        log(L"  X CreateRemoteThread failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    WaitForSingleObject(hThread.get(), 10000);
    DWORD code = 0;
    GetExitCodeThread(hThread.get(), &code);
    VirtualFreeEx(hProc.get(), rem, 0, MEM_RELEASE);

    if (!code) {
        log(L"  X LoadLibraryA returned NULL (wrong arch or bad DLL?)");
        return false;
    }
    wchar_t buf[64]; swprintf_s(buf, 64, L"  OK! hModule = 0x%llX", (unsigned long long)code);
    log(buf);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// ManualMap shellcode
// ─────────────────────────────────────────────────────────────────────────────
#pragma pack(push, 1)
struct LoaderParams {
    BYTE*   base;
    DWORD   ntOffset;
    typedef HMODULE (WINAPI* FnLL )(LPCSTR);
    typedef FARPROC (WINAPI* FnGPA)(HMODULE, LPCSTR);
    FnLL  pfnLoadLibraryA;
    FnGPA pfnGetProcAddress;
};
#pragma pack(pop)

static DWORD WINAPI shellcodeLoader(LoaderParams* p) {
    if (!p) return 0;
    BYTE* base = p->base;
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + p->ntOffset);
    ULONGLONG delta = (ULONGLONG)base - nt->OptionalHeader.ImageBase;

    // Relocations
    if (delta) {
        IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir->Size) {
            IMAGE_BASE_RELOCATION* blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + dir->VirtualAddress);
            while (blk->VirtualAddress) {
                DWORD cnt = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                WORD* rel = reinterpret_cast<WORD*>(blk + 1);
                for (DWORD i = 0; i < cnt; i++)
                    if ((rel[i] >> 12) == IMAGE_REL_BASED_DIR64)
                        *reinterpret_cast<ULONGLONG*>(base + blk->VirtualAddress + (rel[i] & 0xFFF)) += delta;
                blk = reinterpret_cast<IMAGE_BASE_RELOCATION*>((BYTE*)blk + blk->SizeOfBlock);
            }
        }
    }

    // IAT
    IMAGE_DATA_DIRECTORY* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->Size) {
        IMAGE_IMPORT_DESCRIPTOR* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + impDir->VirtualAddress);
        while (desc->Name) {
            HMODULE hMod = p->pfnLoadLibraryA(reinterpret_cast<LPCSTR>(base + desc->Name));
            IMAGE_THUNK_DATA* thunkO = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
            IMAGE_THUNK_DATA* thunk  = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
            while (thunkO->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(thunkO->u1.Ordinal))
                    thunk->u1.Function = (ULONGLONG)p->pfnGetProcAddress(hMod,
                        reinterpret_cast<LPCSTR>(IMAGE_ORDINAL(thunkO->u1.Ordinal)));
                else {
                    IMAGE_IMPORT_BY_NAME* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + thunkO->u1.AddressOfData);
                    thunk->u1.Function = (ULONGLONG)p->pfnGetProcAddress(hMod, ibn->Name);
                }
                ++thunkO; ++thunk;
            }
            ++desc;
        }
    }

    // DllMain
    if (nt->OptionalHeader.AddressOfEntryPoint) {
        typedef BOOL (WINAPI* FnDllMain)(HINSTANCE, DWORD, LPVOID);
        FnDllMain dm = reinterpret_cast<FnDllMain>(base + nt->OptionalHeader.AddressOfEntryPoint);
        return dm(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr);
    }
    return 1;
}
static void shellcodeEnd() {}

// ─────────────────────────────────────────────────────────────────────────────
// Inject — ManualMap
// ─────────────────────────────────────────────────────────────────────────────
static bool injectManualMap(DWORD pid, const wchar_t* dllPathW) {
    log(std::wstring(L"[ManualMap] PID: ") + std::to_wstring(pid));
    log(std::wstring(L"  DLL: ") + dllPathW);

    // Read file
    HANDLE hFile = CreateFileW(dllPathW, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        log(L"  X Cannot open DLL, error: " + std::to_wstring(GetLastError()));
        return false;
    }
    auto fh  = wrapHandle(hFile);
    DWORD fsz = GetFileSize(hFile, nullptr);
    std::vector<BYTE> raw(fsz);
    DWORD rd = 0;
    ReadFile(hFile, raw.data(), fsz, &rd, nullptr);

    // Validate PE
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(raw.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { log(L"  X Bad DOS signature"); return false; }
    IMAGE_NT_HEADERS* nt  = reinterpret_cast<IMAGE_NT_HEADERS*>(raw.data() + dos->e_lfanew);
    if (nt->Signature  != IMAGE_NT_SIGNATURE)  { log(L"  X Bad NT signature");  return false; }

    const DWORD kAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                          PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;
    auto hProc = wrapHandle(OpenProcess(kAccess, FALSE, pid));
    if (!hProc) {
        log(L"  X OpenProcess failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    // Allocate image in target
    LPVOID remImg = VirtualAllocEx(hProc.get(),
        reinterpret_cast<LPVOID>(nt->OptionalHeader.ImageBase),
        nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remImg)
        remImg = VirtualAllocEx(hProc.get(), nullptr,
            nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remImg) {
        log(L"  X VirtualAllocEx(image) failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    // Headers + sections
    WriteProcessMemory(hProc.get(), remImg, raw.data(), nt->OptionalHeader.SizeOfHeaders, nullptr);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!sec->SizeOfRawData) continue;
        WriteProcessMemory(hProc.get(), (BYTE*)remImg + sec->VirtualAddress,
                           raw.data() + sec->PointerToRawData, sec->SizeOfRawData, nullptr);
    }

    // Stub
    SIZE_T stubSz  = (SIZE_T)shellcodeEnd - (SIZE_T)shellcodeLoader;
    SIZE_T totalSz = sizeof(LoaderParams) + stubSz;
    LPVOID remStub = VirtualAllocEx(hProc.get(), nullptr, totalSz,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remStub) {
        VirtualFreeEx(hProc.get(), remImg, 0, MEM_RELEASE);
        log(L"  X VirtualAllocEx(stub) failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    LoaderParams lp{};
    lp.base              = static_cast<BYTE*>(remImg);
    lp.ntOffset          = dos->e_lfanew;
    lp.pfnLoadLibraryA   = reinterpret_cast<LoaderParams::FnLL>(GetProcAddress(hK32, "LoadLibraryA"));
    lp.pfnGetProcAddress = reinterpret_cast<LoaderParams::FnGPA>(GetProcAddress(hK32, "GetProcAddress"));

    WriteProcessMemory(hProc.get(), remStub, &lp, sizeof(LoaderParams), nullptr);
    WriteProcessMemory(hProc.get(), (BYTE*)remStub + sizeof(LoaderParams),
                       reinterpret_cast<LPCVOID>(shellcodeLoader), stubSz, nullptr);

    auto hThread = wrapHandle(CreateRemoteThread(hProc.get(), nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>((BYTE*)remStub + sizeof(LoaderParams)),
        remStub, 0, nullptr));
    if (!hThread) {
        VirtualFreeEx(hProc.get(), remImg, 0, MEM_RELEASE);
        VirtualFreeEx(hProc.get(), remStub, 0, MEM_RELEASE);
        log(L"  X CreateRemoteThread failed, error: " + std::to_wstring(GetLastError()));
        return false;
    }

    WaitForSingleObject(hThread.get(), 10000);
    DWORD code = 0;
    GetExitCodeThread(hThread.get(), &code);
    VirtualFreeEx(hProc.get(), remStub, 0, MEM_RELEASE);

    if (!code) {
        VirtualFreeEx(hProc.get(), remImg, 0, MEM_RELEASE);
        log(L"  X DllMain returned FALSE");
        return false;
    }
    wchar_t buf[80]; swprintf_s(buf, 80, L"  OK! Base = 0x%llX", (unsigned long long)(uintptr_t)remImg);
    log(buf);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Inject dispatcher
// ─────────────────────────────────────────────────────────────────────────────
static void doInject() {
    wchar_t dllBuf[MAX_PATH]{};
    GetWindowTextW(g_hDllEdit, dllBuf, MAX_PATH);
    if (!dllBuf[0]) { MessageBoxW(g_hWnd, L"Select a DLL first.", L"Error", MB_ICONWARNING); return; }
    if (GetFileAttributesW(dllBuf) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_hWnd, L"DLL file not found on disk.", L"Error", MB_ICONERROR); return; }

    LRESULT sel = SendMessageW(g_hProcList, LB_GETCURSEL, 0, 0);
    if (sel == LB_ERR) { MessageBoxW(g_hWnd, L"Select a process from the list.", L"Error", MB_ICONWARNING); return; }
    DWORD pid = (DWORD)SendMessageW(g_hProcList, LB_GETITEMDATA, (WPARAM)sel, 0);

    int method = (int)SendMessageW(g_hMethodCombo, CB_GETCURSEL, 0, 0);

    log(L"-------------------------------------");
    bool ok = (method == 0) ? injectLoadLibrary(pid, dllBuf)
                            : injectManualMap(pid, dllBuf);
    setStatus(ok ? L"OK  Injection succeeded" : L"FAIL  Injection failed — see log");
}

// ─────────────────────────────────────────────────────────────────────────────
// UI creation
// ─────────────────────────────────────────────────────────────────────────────
static void createControls(HWND hWnd) {
    g_hFont     = CreateFontW(-14,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,
                              DEFAULT_PITCH|FF_SWISS, L"Segoe UI");
    g_hFontMono = CreateFontW(-13,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,
                              OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,
                              FIXED_PITCH|FF_MODERN, L"Consolas");

    auto mkWnd = [&](DWORD ex, const wchar_t* cls, const wchar_t* txt, DWORD style,
                     int x, int y, int w, int h, int id, HFONT fnt) -> HWND {
        HWND hw = CreateWindowExW(ex, cls, txt, WS_CHILD|WS_VISIBLE|style,
                                  x, y, w, h, hWnd, (HMENU)(INT_PTR)id, nullptr, nullptr);
        SendMessageW(hw, WM_SETFONT, (WPARAM)fnt, TRUE);
        return hw;
    };

    // DLL row
    mkWnd(0,L"STATIC",L"DLL Path:",WS_VISIBLE,12,14,70,18,0,g_hFont);
    g_hDllEdit = mkWnd(WS_EX_CLIENTEDGE,L"EDIT",L"",ES_AUTOHSCROLL,12,34,520,24,ID_DLL_EDIT,g_hFont);
    mkWnd(0,L"BUTTON",L"Browse...",BS_PUSHBUTTON,540,34,78,24,ID_DLL_BROWSE,g_hFont);

    // Filter row
    mkWnd(0,L"STATIC",L"Filter:",WS_VISIBLE,12,70,44,20,0,g_hFont);
    g_hFilter = mkWnd(WS_EX_CLIENTEDGE,L"EDIT",L"",ES_AUTOHSCROLL,60,68,240,22,ID_FILTER_EDIT,g_hFont);
    mkWnd(0,L"BUTTON",L"Refresh",BS_PUSHBUTTON,310,68,80,22,ID_PROC_REFRESH,g_hFont);

    // Process listbox
    g_hProcList = mkWnd(WS_EX_CLIENTEDGE,L"LISTBOX",L"",
                        LBS_NOTIFY|WS_VSCROLL|LBS_NOINTEGRALHEIGHT,
                        12,96,606,200,ID_PROC_LIST,g_hFontMono);

    // Method + Inject
    mkWnd(0,L"STATIC",L"Method:",WS_VISIBLE,12,308,58,22,0,g_hFont);
    g_hMethodCombo = mkWnd(0,L"COMBOBOX",L"",CBS_DROPDOWNLIST|WS_VSCROLL,
                           74,306,220,150,ID_METHOD_COMBO,g_hFont);
    SendMessageW(g_hMethodCombo, CB_ADDSTRING, 0, (LPARAM)L"LoadLibraryA  (standard)");
    SendMessageW(g_hMethodCombo, CB_ADDSTRING, 0, (LPARAM)L"Manual Map    (stealth)");
    SendMessageW(g_hMethodCombo, CB_SETCURSEL, 0, 0);

    mkWnd(0,L"BUTTON",L">> INJECT <<",BS_PUSHBUTTON|BS_DEFPUSHBUTTON,
          450,304,168,30,ID_INJECT_BTN,g_hFont);

    // Log
    mkWnd(0,L"STATIC",L"Log:",WS_VISIBLE,12,346,30,18,0,g_hFont);
    g_hLog = mkWnd(WS_EX_CLIENTEDGE,L"EDIT",L"",
                   ES_MULTILINE|ES_AUTOVSCROLL|ES_READONLY|WS_VSCROLL,
                   12,366,606,180,ID_LOG_EDIT,g_hFontMono);

    // Status bar
    g_hStatus = CreateWindowExW(0,STATUSCLASSNAMEW,L"Ready",
                                 WS_CHILD|WS_VISIBLE|SBARS_SIZEGRIP,
                                 0,0,0,0,hWnd,(HMENU)ID_STATUS_BAR,nullptr,nullptr);
    SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_hFont, TRUE);

    if (!isElevated())
        log(L"WARNING: Not running as Administrator. Some processes may fail.");
    else
        log(L"Running as Administrator - OK");
}

static void onResize(HWND hWnd) {
    RECT rc; GetClientRect(hWnd, &rc);
    int W = rc.right;
    SetWindowPos(g_hDllEdit,    nullptr, 0,0, W-106, 24, SWP_NOMOVE|SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hWnd,ID_DLL_BROWSE), nullptr, W-82,34, 70,24, SWP_NOZORDER);
    SetWindowPos(g_hProcList,   nullptr, 0,0, W-24,  200, SWP_NOMOVE|SWP_NOZORDER);
    SetWindowPos(GetDlgItem(hWnd,ID_INJECT_BTN), nullptr, W-182,304, 170,30, SWP_NOZORDER);
    int logH = rc.bottom - 366 - 24; if (logH < 60) logH = 60;
    SetWindowPos(g_hLog,        nullptr, 0,0, W-24,  logH, SWP_NOMOVE|SWP_NOZORDER);
    SendMessageW(g_hStatus, WM_SIZE, 0, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// WndProc
// ─────────────────────────────────────────────────────────────────────────────
static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        g_hWnd    = hWnd;
        createControls(hWnd);
        g_allProcs = enumProcesses();
        populateProcList();
        return 0;

    case WM_SIZE:
        onResize(hWnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_DLL_BROWSE:   browseDll(); break;
        case ID_PROC_REFRESH: {
            g_allProcs = enumProcesses();
            wchar_t f[128]{}; GetWindowTextW(g_hFilter, f, 128);
            populateProcList(f);
            wchar_t sb[64]; swprintf_s(sb,64,L"Refreshed - %zu processes",(size_t)g_allProcs.size());
            setStatus(sb);
            break;
        }
        case ID_INJECT_BTN: doInject(); break;
        case ID_FILTER_EDIT:
            if (HIWORD(wParam) == EN_CHANGE) {
                wchar_t f[128]{}; GetWindowTextW(g_hFilter, f, 128);
                populateProcList(f);
            }
            break;
        }
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = reinterpret_cast<MINMAXINFO*>(lParam);
        mmi->ptMinTrackSize = { 640, 580 };
        return 0;
    }

    case WM_DESTROY:
        if (g_hFont)     DeleteObject(g_hFont);
        if (g_hFontMono) DeleteObject(g_hFontMono);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// WinMain
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    if (!isElevated()) {
        int r = MessageBoxW(nullptr,
            L"DLL Injector needs Administrator rights.\n\nRestart as Administrator?",
            L"DLL Injector", MB_YESNO|MB_ICONQUESTION);
        if (r == IDYES) { relaunchElevated(); return 0; }
    }

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES|ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW|CS_VREDRAW;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.hCursor = LoadCursorW(nullptr, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE+1);
    wc.lpszClassName = L"DllInjectorWnd";
    wc.hIcon = LoadIconW(nullptr, (LPCWSTR)IDI_APPLICATION);
    RegisterClassExW(&wc);

    HWND hWnd = CreateWindowExW(WS_EX_APPWINDOW,
        L"DllInjectorWnd", L"DLL Injector  -  LoadLibrary + ManualMap",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 620,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(hWnd, SW_SHOWNORMAL);
    UpdateWindow(hWnd);

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
