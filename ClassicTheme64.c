#define WIN32_NO_STATUS
#include <windows.h>
#include <psapi.h>
#include <ntndk.h>

PVOID faddr;

HMODULE modules[1024];

int IsUser32Loaded(HANDLE hProcess) {
  char name[256];
  DWORD i, n=0;

  EnumProcessModules(hProcess, modules, sizeof(modules), &n);
  n = n / sizeof(HMODULE);

  for(i=0; i<n; i++) {
    GetModuleBaseName(hProcess, modules[i], name, sizeof(name));
    if(!lstrcmpi(name, "user32.dll")) return 1;
  }

  return 0;
}

void InjectDpiDll(UINT pid) {
  HANDLE hProcess, hThread;
  DWORD temp1=0, temp2=0;
  CLIENT_ID CID;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

  if(!IsUser32Loaded(hProcess)) {
    CloseHandle(hProcess);
    return;
   }

  RtlCreateUserThread(hProcess, NULL, 0, 0, temp1, temp2, faddr, NULL, &hThread, &CID);
  CloseHandle(hThread);
  CloseHandle(hProcess);
}

char *cmdLine() {
  char *cmdl; int i, guim=0;

  cmdl = GetCommandLine();

  for(i=0; cmdl[i]; i++) {
    if(cmdl[i]=='"') guim = !guim;
    else if(!guim && cmdl[i]==' ') return cmdl+i+1;
  }

  return NULL;
}

int a2i(char *a) {
  int res=0;

  while(*a==' ') a++;

  while(*a>='0' && *a<='9') {
    res = 10*res + *a-'0';
    a++;
  }

  return res;
}

void WinMainCRTStartup() {
  char *cmdl;
  int pid;

  faddr = GetProcAddress(LoadLibrary("user32.dll"), "SetProcessDPIAware");

  cmdl = cmdLine();

  pid = a2i(cmdl);

  if(pid) InjectDpiDll(pid);

  ExitProcess(0);
}
