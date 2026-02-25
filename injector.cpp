#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

static const wchar_t* TARGET_GAME = L"stalcraftw.exe";
static const wchar_t* TARGET_KILL = L"ExensLauncher.exe";

static void die(const wchar_t* msg) {
    MessageBoxW(nullptr, msg, L"Injector", MB_ICONERROR|MB_OK);
    ExitProcess(1);
}
static void info(const wchar_t* msg) {
    MessageBoxW(nullptr, msg, L"Injector", MB_ICONINFORMATION|MB_OK);
}

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

static int killProcess(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W e{}; e.dwSize = sizeof(e);
    int killed = 0;
    if (Process32FirstW(snap, &e)) do {
        if (lstrcmpiW(e.szExeFile, name) == 0) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, e.th32ProcessID);
            if (h) { TerminateProcess(h,0); WaitForSingleObject(h,3000); CloseHandle(h); killed++; }
        }
    } while (Process32NextW(snap, &e));
    CloseHandle(snap);
    return killed;
}

static bool findDll(wchar_t* out) {
    wchar_t dir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    wchar_t* s = wcsrchr(dir, L'\\'); if (s) *(s+1)=0;
    wchar_t pat[MAX_PATH]{}; lstrcpyW(pat, dir); lstrcatW(pat, L"*.dll");
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    lstrcpyW(out, dir); lstrcatW(out, fd.cFileName);
    FindClose(h);
    return true;
}

// Копируем DLL с рандомным именем во Temp — чтобы имя файла не детектилось
static bool randomizeDll(const wchar_t* src, wchar_t* outTmp) {
    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    // Рандомное имя: 8 hex символов + .dll
    wchar_t rnd[32]{};
    FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
    DWORD seed = ft.dwLowDateTime ^ ft.dwHighDateTime ^ GetCurrentProcessId();
    wsprintfW(rnd, L"%08X.dll", seed);
    lstrcpyW(outTmp, tmp);
    lstrcatW(outTmp, rnd);
    return CopyFileW(src, outTmp, FALSE) != 0;
}

static void inject(DWORD pid, const wchar_t* dllW) {
    char dllA[MAX_PATH]{};
    WideCharToMultiByte(CP_ACP,0,dllW,-1,dllA,MAX_PATH,nullptr,nullptr);

    const DWORD acc = PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|
                      PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ;
    HANDLE hProc = OpenProcess(acc, FALSE, pid);
    if (!hProc) die(L"OpenProcess failed. Запусти от имени Администратора.");

    SIZE_T sz = strlen(dllA)+1;
    LPVOID rem = VirtualAllocEx(hProc,nullptr,sz,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!rem) { CloseHandle(hProc); die(L"VirtualAllocEx failed."); }

    SIZE_T wr=0;
    if (!WriteProcessMemory(hProc,rem,dllA,sz,&wr)||wr!=sz) {
        VirtualFreeEx(hProc,rem,0,MEM_RELEASE); CloseHandle(hProc); die(L"WriteProcessMemory failed."); }

    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pfn = (LPTHREAD_START_ROUTINE)GetProcAddress(hK32,"LoadLibraryA");
    HANDLE hT = CreateRemoteThread(hProc,nullptr,0,pfn,rem,0,nullptr);
    if (!hT) { VirtualFreeEx(hProc,rem,0,MEM_RELEASE); CloseHandle(hProc); die(L"CreateRemoteThread failed."); }

    WaitForSingleObject(hT,10000);
    DWORD code=0; GetExitCodeThread(hT,&code);
    VirtualFreeEx(hProc,rem,0,MEM_RELEASE);
    CloseHandle(hT); CloseHandle(hProc);

    if (!code) die(L"Injection failed.");
}

int WINAPI wWinMain(HINSTANCE,HINSTANCE,LPWSTR,int) {
    // 1. Найти DLL
    wchar_t dllPath[MAX_PATH]{};
    if (!findDll(dllPath)) die(L"DLL не найдена рядом с инжектором.");

    // 2. Скопировать с рандомным именем
    wchar_t tmpDll[MAX_PATH]{};
    if (!randomizeDll(dllPath, tmpDll)) die(L"Не удалось скопировать DLL.");

    // 3. Убить лаунчер
    int killed = killProcess(TARGET_KILL);
    if (killed > 0) {
        wchar_t msg[128]; wsprintfW(msg, L"Закрыт: %s", TARGET_KILL);
        info(msg);
        Sleep(500);
    }

    // 4. Найти игру
    DWORD pid = findPid(TARGET_GAME);
    if (!pid) {
        DeleteFileW(tmpDll);
        die(L"stalcraftw.exe не найден. Запусти игру сначала.");
    }

    // 5. Инжект
    inject(pid, tmpDll);

    // 6. Подождать и удалить временный файл
    Sleep(5000);
    DeleteFileW(tmpDll);

    return 0;
}
