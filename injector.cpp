// Auto-injector for stalcraftw.exe
// Usage: put any .dll next to this .exe and run it — done.
// Before injection: kills EXENS Game Launcher process.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

// ── targets ──────────────────────────────────────────────────────────────────
static const wchar_t* TARGET_GAME    = L"stalcraftw.exe";
static const wchar_t* TARGET_KILL    = L"ExensLauncher.exe";

// ── helpers ──────────────────────────────────────────────────────────────────
static void die(const wchar_t* msg, DWORD err = 0) {
    wchar_t buf[512];
    if (err) wsprintfW(buf, L"%s\nError code: %lu", msg, err);
    else     lstrcpyW(buf, msg);
    MessageBoxW(nullptr, buf, L"Injector", MB_ICONERROR | MB_OK);
    ExitProcess(1);
}

static void info(const wchar_t* msg) {
    MessageBoxW(nullptr, msg, L"Injector", MB_ICONINFORMATION | MB_OK);
}

// ── find PID by name ─────────────────────────────────────────────────────────
static DWORD findPid(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e{}; e.dwSize = sizeof(e);
    DWORD pid = 0;
    if (Process32FirstW(snap, &e)) do {
        if (lstrcmpiW(e.szExeFile, name) == 0) { pid = e.th32ProcessID; break; }
    } while (Process32NextW(snap, &e));
    CloseHandle(snap);
    return pid;
}

// ── kill ALL instances of a process by name ───────────────────────────────────
static int killProcess(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e{}; e.dwSize = sizeof(e);
    int killed = 0;
    if (Process32FirstW(snap, &e)) do {
        if (lstrcmpiW(e.szExeFile, name) == 0) {
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, e.th32ProcessID);
            if (hProc) {
                TerminateProcess(hProc, 0);
                // wait up to 3s for it to actually die
                WaitForSingleObject(hProc, 3000);
                CloseHandle(hProc);
                killed++;
            }
        }
    } while (Process32NextW(snap, &e));
    CloseHandle(snap);
    return killed;
}

// ── find first .dll next to this exe ─────────────────────────────────────────
static bool findDll(wchar_t* outPath) {
    wchar_t selfDir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, selfDir, MAX_PATH);
    wchar_t* slash = wcsrchr(selfDir, L'\\');
    if (slash) *(slash + 1) = L'\0';

    wchar_t pattern[MAX_PATH]{};
    lstrcpyW(pattern, selfDir);
    lstrcatW(pattern, L"*.dll");

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return false;

    lstrcpyW(outPath, selfDir);
    lstrcatW(outPath, fd.cFileName);
    FindClose(h);
    return true;
}

// ── inject via LoadLibraryA ───────────────────────────────────────────────────
static void inject(DWORD pid, const wchar_t* dllW) {
    char dllA[MAX_PATH]{};
    WideCharToMultiByte(CP_ACP, 0, dllW, -1, dllA, MAX_PATH, nullptr, nullptr);

    const DWORD acc = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                      PROCESS_VM_OPERATION  | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE hProc = OpenProcess(acc, FALSE, pid);
    if (!hProc) die(L"OpenProcess failed.\nRun as Administrator.", GetLastError());

    SIZE_T sz  = strlen(dllA) + 1;
    LPVOID rem = VirtualAllocEx(hProc, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { CloseHandle(hProc); die(L"VirtualAllocEx failed.", GetLastError()); }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, rem, dllA, sz, &written) || written != sz) {
        VirtualFreeEx(hProc, rem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        die(L"WriteProcessMemory failed.", GetLastError());
    }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pfn = (LPTHREAD_START_ROUTINE)GetProcAddress(hK32, "LoadLibraryA");

    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pfn, rem, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, rem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        die(L"CreateRemoteThread failed.", GetLastError());
    }

    WaitForSingleObject(hThread, 10000);
    DWORD code = 0;
    GetExitCodeThread(hThread, &code);
    VirtualFreeEx(hProc, rem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProc);

    if (!code) die(L"Injection failed: LoadLibraryA returned NULL.\n"
                   L"Make sure the DLL is 64-bit.");

    wchar_t msg[512];
    wsprintfW(msg, L"Injected successfully!\n\nDLL: %s\nPID: %lu", dllW, pid);
    info(msg);
}

// ── entry point ──────────────────────────────────────────────────────────────
int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {

    // 1. find DLL
    wchar_t dllPath[MAX_PATH]{};
    if (!findDll(dllPath))
        die(L"No .dll found next to the injector.\nPut your .dll in the same folder.");

    // 2. kill launcher
    int killed = killProcess(TARGET_KILL);
    if (killed > 0) {
        wchar_t killMsg[256];
        wsprintfW(killMsg, L"Closed %d instance(s) of:\n%s", killed, TARGET_KILL);
        info(killMsg);
        Sleep(500);
    } else {
        info(L"EXENS Game Launcher was not running\n(nothing to close)");
    }

    // 3. find game
    DWORD pid = findPid(TARGET_GAME);
    if (!pid) {
        wchar_t msg[256];
        wsprintfW(msg, L"Game process not found: %s\n\nStart the game first.", TARGET_GAME);
        die(msg);
    }

    // 4. inject
    inject(pid, dllPath);
    return 0;
}
