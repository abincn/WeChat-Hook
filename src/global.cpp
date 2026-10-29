#include "global.h"

HMODULE g_hModule = NULL;
uint64_t g_MyModuleBase = 0;
uint64_t g_MyModuleSize = 0;
uint64_t g_MyModuleEnd = 0;
DWORD   进程PID = 0;
DWORD   父进程PID = 0;
DWORD   g_MainThreadId = 0;
HANDLE g_hLoginMonitor = nullptr;
HANDLE g_hAfterLoginInit = nullptr;

HMODULE g_hWeixinDll = nullptr;
HMODULE g_hWeixinExe = nullptr;
HWND    g_WeixinMainHwnd = nullptr;
volatile uint64_t g_IsLogin = 0;
volatile bool g_ScanDatabasesForced = false;   // 登录探测期间临时绕过 g_IsLogin 门禁
volatile uint64_t g_getprofile = 0;
CRITICAL_SECTION g_dbMgrCriticalSection;

volatile bool g_LoginMonitorRunning = true;
std::string g_CallBack_Url;
std::string g_BindAddr = "127.0.0.1";   // 默认只监听回环, 需要局域网再显式改
std::string g_Token;                    // 空 = 不校验

std::wstring g_AppDataDir;
std::wstring g_DocumentDir;
std::wstring g_UsersDir;

SelfInfo_t SelfInfo;
