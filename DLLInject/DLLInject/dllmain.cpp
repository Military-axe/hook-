#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <io.h>
#include <tchar.h>
using namespace std;


void InjectDLL(DWORD pid, LPCTSTR dllpath) {
    HANDLE                  hProcess = NULL;//保存目标进程的句柄
    LPVOID                  pRemoteBuf = NULL;//目标进程开辟的内存的起始地址
    DWORD                   dwBufSize = (DWORD)(_tcslen(dllpath) + 1) * sizeof(TCHAR);//开辟的内存的大小
    LPTHREAD_START_ROUTINE  pThreadProc = NULL;//loadLibreayW函数的起始地址
    HMODULE                 hMod = NULL;//kernel32.dll模块的句柄
    BOOL                    bRet = FALSE;

    //打开目标进程，获得句柄
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    //开辟一块内存
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
    //向内存中复制dll路径
    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)dllpath, dwBufSize, NULL);
    //获取kernel32.dll
    hMod = GetModuleHandle(L"kernel32.dll");
    //从kernel32.dll中获取loadLibraryW的地址
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
    //远程线程注入
    HANDLE hRemoteThread;
    hRemoteThread=CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    if (hRemoteThread) {

    }
}


int main() {
    InjectDLL(6666, L"C:\\Users\\axe\\Documents\\C\\MyDll.dll");
    return 0;
}