#define WIN32_NO_STATUS
#define _WIN32_IE 0x0600
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <Sddl.h>
#include <cpl.h>
#include <psapi.h>
#include <ntndk.h>
#include <szddexp.h>

#include "resource.h"

#define PROCESSNAME "WinLogon.exe"
#define HANDLENAME L"\\ThemeSection"
#define PROGNAME "ClassicTheme"

char *InstallGUID = "6e6d357c-47b4-4469-a7a8-5069ec340ad1";
char *UninstGUID  = "feae031c-779a-489f-a89c-ae0152195d67";
char *PatchIEGUID = "7bd06249-cf71-4667-b461-d9216e1c3fdf";
char *DPIGUID = "fc995941-4456-4344-9478-1d1df757302c";
char *DoNowGUID = "53522c68-df59-4566-85c2-07d06e57b381";
char *DoNowGUIDs = " ca18cc4e-b373-495b-91a3-3c2a8d53e12d";


int IsWin10=0;

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

int GetPID(char *name) {
  HANDLE hth=0; PROCESSENTRY32 pe; int ret=0;

  hth = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if(!hth) return 0;
  ZeroMemory(&pe, sizeof(pe));
  pe.dwSize = sizeof(pe);
  Process32First(hth, &pe);

  do {
    if(!lstrcmpi(pe.szExeFile, name)) ret = pe.th32ProcessID;
  } while(Process32Next(hth, &pe));

  return ret;
}

//////////////////////////////////////////////////////////////

HANDLE CreateEvt(char *evtname) {
  SECURITY_ATTRIBUTES sa; char *satext;

  sa.nLength = sizeof(sa);
  sa.bInheritHandle = FALSE;
  satext = "D:(A;;GA;;;CO)(A;;GA;;;AU)";
  ConvertStringSecurityDescriptorToSecurityDescriptor(satext, 1, &(sa.lpSecurityDescriptor), NULL);

  return CreateEvent(&sa, TRUE, FALSE, evtname);
}

SERVICE_STATUS srvStatus;
SERVICE_STATUS_HANDLE hSrvStatus=0;

SERVICE_STATUS srv2Status;
SERVICE_STATUS_HANDLE hSrv2Status=0;

void MainService() {
  HANDLE hNtDll=0; HANDLE hProcess;
  UINT i, pid=0, ret; char tmp[256]; int bsize=0;
  SYSTEM_HANDLE_INFORMATION *pshi=NULL;
  char nameh[2048]; WORD *namehc; int namehl;
  HANDLE handle, hEvt3=NULL;

  hEvt3 = OpenEvent(EVENT_MODIFY_STATE, FALSE, "Global\\ClassicThemeEvent3");

  pid = GetPID(PROCESSNAME);
  if(!pid) goto ProcessNotFound;
  
  // Récupère la liste globale des Handles
  ret = NtQuerySystemInformation(16, tmp, sizeof(SYSTEM_HANDLE_INFORMATION), &bsize);
  if(ret==STATUS_INFO_LENGTH_MISMATCH && bsize) {
    pshi = HeapAlloc(GetProcessHeap(), 0, bsize);
    if(!pshi) ExitProcess(1);
    ret = NtQuerySystemInformation(16, pshi, bsize, NULL);
  } 

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if(!hProcess) goto ProcessNotFound;

  for(i=0; i<pshi->NumberOfHandles; i++) {
    if(pshi->Handles[i].UniqueProcessId == pid) {
      // Duplique le handle pour pouvoir obtenir son nom
      DuplicateHandle(hProcess, (HANDLE)pshi->Handles[i].HandleValue, GetCurrentProcess(), &handle, 0, FALSE, DUPLICATE_SAME_ACCESS);
      // Demande le nom du handle
      NtQueryObject(handle, 1, &nameh, sizeof(nameh), NULL);
      namehl = ((UNICODE_STRING*)nameh)->Length;
      if(!namehl) goto cont;
      namehc = ((UNICODE_STRING*)nameh)->Buffer;
      if(namehl) *(WORD*)(namehc+namehl) = 0;

      if(StrStrIW(namehc, HANDLENAME)) {
	// Détruit le handle
	DuplicateHandle(hProcess, (HANDLE)pshi->Handles[i].HandleValue, GetCurrentProcess(), NULL, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
	CloseHandle(handle);
	break;
      }
cont:
      CloseHandle(handle);
    }
  }

  CloseHandle(hProcess);

ProcessNotFound:

  SetEvent(hEvt3);

  ExitProcess(0);
}

void MainService2() {
  HKEY hKey=NULL;
  char ExplorerName[] = "explorer.exe";
  char Path[256];
  HANDLE hEvt=NULL, hEvt3=NULL;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  hEvt3 = CreateEvt("Global\\ClassicThemeEvent3");

  GetModuleFileName(GetModuleHandle(NULL), Path, sizeof(Path));

  ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
  CreateProcess(NULL, Path, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

  WaitForSingleObject(hEvt3, 30000);
  ResetEvent(hEvt3);
  Sleep(500);

  hEvt = CreateEvt("Global\\ClassicThemeEvent1");

  WaitForSingleObject(hEvt, 30000);

  RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
  if(hKey) {
    RegSetValueEx(hKey, "Shell", 0, REG_SZ, ExplorerName, sizeof(ExplorerName));
  }

  SetEvent(hEvt3);

  Sleep(5000);

  RegSetValueEx(hKey, "Shell", 0, REG_SZ, Path, strlen(Path));
  RegCloseKey(hKey);

}

void WINAPI SrvCtrlHandler(DWORD code) {

  switch(code) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
    srvStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(hSrvStatus, &srvStatus);
    break;
  }
  SetServiceStatus(hSrvStatus, &srvStatus);
}

///////////////////////////////////////////////////////////////

void WINAPI SrvMain(int argc, char **argv) {

  srvStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  srvStatus.dwCurrentState = SERVICE_RUNNING;
  srvStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  srvStatus.dwWin32ExitCode = 0;
  srvStatus.dwServiceSpecificExitCode = 0;
  srvStatus.dwCheckPoint = 0;
  srvStatus.dwWaitHint = 0;

  hSrvStatus = RegisterServiceCtrlHandler("ClassicTheme", &SrvCtrlHandler);
  if(!hSrvStatus) return;

  SetServiceStatus(hSrvStatus, &srvStatus);

  MainService2();

  srvStatus.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(hSrvStatus, &srvStatus);

  ExitProcess(0);
  return;
}

///////////////////////////////////////////////////////////////

SERVICE_TABLE_ENTRY srvTable[] = {
  {"ClassicTheme", (LPSERVICE_MAIN_FUNCTION)&SrvMain},
  {NULL, NULL}
};

void ServiceEntry() {

  StartServiceCtrlDispatcher(srvTable);
}

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

NTSTATUS WINAPI NtCreateThreadEx  (
   OUT PHANDLE hThread,
   IN ACCESS_MASK DesiredAccess,
   IN LPVOID ObjectAttributes,
   IN HANDLE ProcessHandle,
   IN LPTHREAD_START_ROUTINE lpStartAddress,
   IN LPVOID lpParameter,
   IN BOOL CreateSuspended, 
   IN ULONG StackZeroBits,
   IN ULONG SizeOfStackCommit,
   IN ULONG SizeOfStackReserve,
   OUT LPVOID lpBytesBuffer
 );

struct NtCreateThreadExBuffer
 {
   ULONG Size;
   ULONG Unknown1;
   ULONG Unknown2;
   PULONG Unknown3;
   ULONG Unknown4;
   ULONG Unknown5;
   ULONG Unknown6;
   PULONG Unknown7;
   ULONG Unknown8;
 };

PVOID faddr;
char DPI64Path[256];

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
  DWORD temp1=0, temp2=0, Wow64=0;
  char cmdl[512];
  PROCESS_INFORMATION pi; STARTUPINFO si;
  CLIENT_ID CID;

  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid); 

  IsWow64Process(hProcess, &Wow64);
  if(!Wow64 && *DPI64Path) {
    CloseHandle(hProcess);
    wsprintf(cmdl, "%s %u", DPI64Path, pid);
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    CreateProcess(NULL, cmdl, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return;
  }

  if(!IsUser32Loaded(hProcess)) {
    CloseHandle(hProcess);
    return;
   }

  RtlCreateUserThread(hProcess, NULL, 0, 0, temp1, temp2, faddr, NULL, &hThread, &CID);

  CloseHandle(hThread);
  CloseHandle(hProcess);
}

#define MAXPROC 25000
UINT PidList[MAXPROC], _PidList[MAXPROC];
SYSTEM_PROCESS_INFORMATION spi[2048];

void MainServiceDPI() {
  int i;
  char *verdata; int versize, zero; char NewPath[256];
  HRSRC hRes; HANDLE hFile; BOOL Wow64=FALSE;
  PSYSTEM_PROCESS_INFORMATION pspi;
  HANDLE hEvt;
  SECURITY_ATTRIBUTES sa; char *satext;
  int done;
  int fsize; char *fbuff=NULL;

  IsWow64Process(GetCurrentProcess(), &Wow64);
  if(Wow64) {
    GetTempPath(sizeof(NewPath), NewPath);
    GetTempFileName(NewPath, "tmp", 0, DPI64Path);
  
    hRes = FindResource(NULL, (LPCTSTR)IDR_DPI64, "BIN");
    versize = SizeofResource(NULL, hRes);
    verdata = LockResource(LoadResource(NULL, hRes));

    fsize = ExpandSZDD(verdata, versize, &fbuff);
    if(!fsize) return;
    
    hFile = CreateFile(DPI64Path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if(hFile==INVALID_HANDLE_VALUE) {
      FreeSZDD(fbuff, fsize);
      return;
    }
    WriteFile(hFile, fbuff, fsize, &zero, NULL);
    CloseHandle(hFile);
    FreeSZDD(fbuff, fsize);
  }

  faddr = GetProcAddress(LoadLibrary("user32.dll"), "SetProcessDPIAware");

  sa.nLength = sizeof(sa);
  sa.bInheritHandle = FALSE;
  satext = "D:(A;;GA;;;CO)(A;;0x00100000;;;AU)";
  ConvertStringSecurityDescriptorToSecurityDescriptor(satext, 1, &(sa.lpSecurityDescriptor), NULL);

  hEvt = CreateEvent(&sa, FALSE, FALSE, "Global\\ClassicThemeDPIEvt");

  SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);

  while(1) {

    ZeroMemory(PidList, sizeof(PidList));
    ZeroMemory(spi, sizeof(spi));
    done=0;

    NtQuerySystemInformation(SystemProcessInformation, spi, sizeof(spi), NULL);
    
    for(pspi=&spi[0]; ; pspi=(PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pspi + pspi->NextEntryOffset)) {
      if(pspi->SessionId && (int)pspi->UniqueProcessId < MAXPROC) 
        PidList[(int)pspi->UniqueProcessId >> 2] = 1;
      if(!pspi->NextEntryOffset) break;
    }

    for(i=0; i<MAXPROC; i++) {
      if(PidList[i]) {
        if(!_PidList[i]) {
          InjectDpiDll(i << 2);
          done=1;
          _PidList[i] = 1;
        }
      }
      else _PidList[i] = 0;
    }

    Sleep(500);

    if(done) SetEvent(hEvt);
  }


}

void WINAPI Srv2CtrlHandler(DWORD code) {

  switch(code) {
  case SERVICE_CONTROL_STOP:
  case SERVICE_CONTROL_SHUTDOWN:
    if(*DPI64Path) DeleteFile(DPI64Path);
    srv2Status.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(hSrvStatus, &srv2Status);
    ExitProcess(0);
    break;
  }
  SetServiceStatus(hSrvStatus, &srv2Status);
}

///////////////////////////////////////////////////////////////

void WINAPI Srv2Main(int argc, char **argv) {

  srv2Status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  srv2Status.dwCurrentState = SERVICE_RUNNING;
  srv2Status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  srv2Status.dwWin32ExitCode = 0;
  srv2Status.dwServiceSpecificExitCode = 0;
  srv2Status.dwCheckPoint = 0;
  srv2Status.dwWaitHint = 0;

  hSrv2Status = RegisterServiceCtrlHandler("ClassicTheme2", &Srv2CtrlHandler);
  if(!hSrv2Status) return;

  SetServiceStatus(hSrv2Status, &srv2Status);

  MainServiceDPI();

  srvStatus.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(hSrv2Status, &srv2Status);

  ExitProcess(0);
  return;
}

///////////////////////////////////////////////////////////////

SERVICE_TABLE_ENTRY srv2Table[] = {
  {"ClassicTheme2", (LPSERVICE_MAIN_FUNCTION)&Srv2Main},
  {NULL, NULL}
};

void ServiceEntry2() {

  StartServiceCtrlDispatcher(srv2Table);
}


//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

void MainUserinit() {
  SC_HANDLE sc_Handle = NULL, drv_Handle;
  HANDLE hEvt=NULL, hEvt3=NULL;

  ///////

  sc_Handle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
  if(sc_Handle) {
    drv_Handle = OpenService(sc_Handle, PROGNAME, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE);
    if(drv_Handle) {
      StartService(drv_Handle, 0, NULL);
      CloseServiceHandle(drv_Handle);
    }
    drv_Handle = OpenService(sc_Handle, PROGNAME "2", SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE);
    if(drv_Handle) {
      StartService(drv_Handle, 0, NULL);
      CloseServiceHandle(drv_Handle);
    }
    CloseServiceHandle(sc_Handle);
  }

  while(!hEvt) {
    Sleep(100);
    hEvt = OpenEvent(EVENT_MODIFY_STATE, FALSE, "Global\\ClassicThemeEvent1");
  }

  while(!hEvt3) {
    Sleep(100);
    hEvt3 = OpenEvent(SYNCHRONIZE, FALSE, "Global\\ClassicThemeEvent3");
  }

  SetEvent(hEvt);

  WaitForSingleObject(hEvt3, 10000);

  ///////
    
  ShellExecute(0, "open", "userinit.exe", NULL, NULL, SW_SHOWDEFAULT);

  ExitProcess(0);
}

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

char *GetTrustedSID() {
  PSID Sid=NULL; int SidSize=0, tmp=0;
  SID_NAME_USE peUse=0;
  char *str=NULL;

  LookupAccountName(NULL, "NT SERVICE\\TrustedInstaller", NULL, &SidSize, NULL, &tmp, &peUse);
  Sid = HeapAlloc(GetProcessHeap(), 0, SidSize);
  str = HeapAlloc(GetProcessHeap(), 0, tmp);
  LookupAccountName(NULL, "NT SERVICE\\TrustedInstaller", Sid, &SidSize, str, &tmp, &peUse);
  HeapFree(GetProcessHeap(), 0, str);
  ConvertSidToStringSid(Sid, &str);
  HeapFree(GetProcessHeap(), 0, Sid);
  return str;
}

void CopyDLL() {
  char *verdata; int versize, zero; char NewPath[512], NewPath2[512];
  HRSRC hRes; HANDLE hFile; BOOL Wow64=FALSE; PVOID oldval;
  int fsize; char *fbuff=NULL;

  IsWow64Process(GetCurrentProcess(), &Wow64);

  if(Wow64) Wow64DisableWow64FsRedirection(&oldval);

  GetSystemWindowsDirectory(NewPath, sizeof(NewPath));
  strcat(NewPath, "\\dwm_rdr.dll");

  GetSystemWindowsDirectory(NewPath2, sizeof(NewPath2));
  strcat(NewPath2, "\\system32\\dwmapi.dll");

  CopyFile(NewPath2, NewPath, FALSE);

  if(Wow64) Wow64RevertWow64FsRedirection(oldval);

  GetSystemWindowsDirectory(NewPath, sizeof(NewPath));
  strcat(NewPath, "\\dwmapi.dll");

  if(!IsWin10) {
    if(Wow64) hRes = FindResource(NULL, (LPCTSTR)IDR_DWMAPI64, "BIN");  
    else hRes = FindResource(NULL, (LPCTSTR)IDR_DWMAPI32, "BIN");  
  }
  else {
    if(Wow64) hRes = FindResource(NULL, (LPCTSTR)IDR_DWMAPI64_10, "BIN");  
    else hRes = FindResource(NULL, (LPCTSTR)IDR_DWMAPI32_10, "BIN");  
  }
  versize = SizeofResource(NULL, hRes);
  verdata = LockResource(LoadResource(NULL, hRes));

  fsize = ExpandSZDD(verdata, versize, &fbuff);
  if(!fsize) return;
  
  hFile = CreateFile(NewPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if(hFile==INVALID_HANDLE_VALUE) {
      FreeSZDD(fbuff, fsize);
      return;
    }
  WriteFile(hFile, fbuff, fsize, &zero, NULL);
  CloseHandle(hFile);
  FreeSZDD(fbuff, fsize);

  if(Wow64) {
    GetSystemWindowsDirectory(NewPath, sizeof(NewPath));
    strcat(NewPath, "\\dwmapi32.dll");
  
    if(!IsWin10) {
      hRes = FindResource(NULL, (LPCTSTR)IDR_DWMAPI32, "BIN");
    }
    else {
      hRes = FindResource(NULL, (LPCTSTR)IDR_DWMAPI32_10, "BIN");
    }
    versize = SizeofResource(NULL, hRes);
    verdata = LockResource(LoadResource(NULL, hRes));

    fsize = ExpandSZDD(verdata, versize, &fbuff);
    if(!fsize) return;

    hFile = CreateFile(NewPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if(hFile==INVALID_HANDLE_VALUE) {
      FreeSZDD(fbuff, fsize);
      return;
    }
    WriteFile(hFile, fbuff, fsize, &zero, NULL);
    CloseHandle(hFile);
    FreeSZDD(fbuff, fsize);
  }
}

void RemoveDLL() {

  char NewPath[512];

  GetSystemWindowsDirectory(NewPath, sizeof(NewPath));
  strcat(NewPath, "\\dwmapi.dll");
  DeleteFile(NewPath);

  GetSystemWindowsDirectory(NewPath, sizeof(NewPath));
  strcat(NewPath, "\\dwm_rdr.dll");
  DeleteFile(NewPath);
}

void Install() {
  char Path[512]; HKEY hKey=NULL;
  SC_HANDLE sc_Handle = NULL, drv_Handle;
  SECURITY_DESCRIPTOR *psd; char satext[256];
  UINT dw;

  sc_Handle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);

  GetModuleFileName(GetModuleHandle(NULL), Path, sizeof(Path));

  if(sc_Handle) {
    drv_Handle = CreateService(sc_Handle, PROGNAME, PROGNAME, SERVICE_ALL_ACCESS, \
      SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Path, NULL, NULL,  NULL, NULL, NULL);

    if(!drv_Handle) {
      MessageBox(NULL, "Unable to create the service.", PROGNAME, 16);
      ExitProcess(1);
    }

    strcpy(satext, "D:(A;;GA;;;CO)(A;;GA;;;BA)(A;;CCLCRPWPLO;;;AU)");
    ConvertStringSecurityDescriptorToSecurityDescriptor(satext, 1, &psd, NULL);
    SetServiceObjectSecurity(drv_Handle, DACL_SECURITY_INFORMATION, psd);

    CloseServiceHandle(drv_Handle);

    if(!IsWin10) {

    strcat(Path, " "); strcat(Path, DPIGUID);

    drv_Handle = CreateService(sc_Handle, PROGNAME "2", PROGNAME "2", SERVICE_ALL_ACCESS, \
      SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Path, NULL, NULL,  NULL, NULL, NULL);
    SetServiceObjectSecurity(drv_Handle, DACL_SECURITY_INFORMATION, psd);

    CloseServiceHandle(drv_Handle);
    }

    CloseServiceHandle(sc_Handle);
  }

  //

  
  RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &hKey);

  GetModuleFileName(GetModuleHandle(NULL), Path, sizeof(Path));
  RegSetValueEx(hKey, "Shell", 0, REG_SZ, Path, strlen(Path));

  RegCloseKey(hKey);

  if(IsWin10) {
    RegCreateKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlightedFeatures", 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKey, NULL);
    dw = 0;
    RegSetValueEx(hKey, "ImmersiveContextMenu", 0, REG_DWORD, (LPBYTE)&dw, sizeof(dw));
    RegCloseKey(hKey);
  }

  CopyDLL();

  if(hKey) {
    MessageBox(NULL, "Program successfully installed. You are going to be logged off.", PROGNAME, 64);
  }

  ExitWindowsEx(EWX_LOGOFF, 0);
}

void Uninstall() {
  char Path[512]; HKEY hKey;
  SC_HANDLE sc_Handle = NULL, drv_Handle;
  char ExplorerName[] = "explorer.exe";
  HANDLE hTH, hProcess; PROCESSENTRY32 pe;
  SERVICE_STATUS srvstatus;

  hTH = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  pe.dwSize = sizeof(pe);
  Process32First(hTH, &pe);
  do {
      if(!lstrcmpi(pe.szExeFile, ExplorerName)) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
        TerminateProcess(hProcess, 1);
        CloseHandle(hProcess);
        break;
      }
  } while(Process32Next(hTH, &pe));
  CloseHandle(hTH);

  Sleep(4000);

  RemoveDLL();

  sc_Handle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);

  GetModuleFileName(GetModuleHandle(NULL), Path, sizeof(Path));

  drv_Handle = OpenService(sc_Handle, PROGNAME, SERVICE_ALL_ACCESS);
  DeleteService(drv_Handle);

  CloseServiceHandle(drv_Handle);

  drv_Handle = OpenService(sc_Handle, PROGNAME "2", SERVICE_ALL_ACCESS);
  ControlService(drv_Handle, SERVICE_CONTROL_STOP, &srvstatus);
  DeleteService(drv_Handle);

  CloseServiceHandle(drv_Handle);

  CloseServiceHandle(sc_Handle);

  //

  RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &hKey);
  RegSetValueEx(hKey, "Shell", 0, REG_SZ, ExplorerName, sizeof(ExplorerName));

  if(IsWin10) {
    RegCreateKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FlightedFeatures", 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &hKey, NULL);
    RegDeleteValue(hKey, "ImmersiveContextMenu");
    RegCloseKey(hKey);
  }

  if(hKey) {
    MessageBox(NULL, "Program successfully uninstalled. You are going to be logged off.", PROGNAME, 64);
  }

  ExitWindowsEx(EWX_LOGOFF, 0);
}

//////////////////////////////////////////////////////////////

typedef LONG (__stdcall *___O_CPlApplet) (HWND hwndCPl,
    UINT uMsg,
    LPARAM lParam1,
    LPARAM lParam2
);
___O_CPlApplet ___o_CPlApplet;


void DeskN(HWND hWnd) {
  char buff[256], tmpfname[256], tmpfname2[256];
  HANDLE hFile, hLib; HRSRC hRes; char *verdata; int versize, zero;
  CPLINFO cpli;
  HANDLE hEvt;

  GetTempPath(sizeof(buff), buff);
  GetTempFileName(buff, "tmp", 0, tmpfname);
  strcpy(tmpfname2, tmpfname);

  hRes = FindResource(NULL, (LPCTSTR)IDR_DESKN, "BIN");
  
  versize = SizeofResource(NULL, hRes);
  verdata = LockResource(LoadResource(NULL, hRes));
  
  hFile = CreateFile(tmpfname2, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
  if(hFile==INVALID_HANDLE_VALUE) return;

  WriteFile(hFile, verdata, versize, &zero, NULL);
  CloseHandle(hFile);

  hLib = LoadLibrary(tmpfname2);
  ___o_CPlApplet = (___O_CPlApplet)GetProcAddress(hLib, "CPlApplet");
  if(___o_CPlApplet) {
    ZeroMemory(&cpli, sizeof(cpli));
    ___o_CPlApplet(hWnd, CPL_INIT, 0, 0);
    ___o_CPlApplet(hWnd, CPL_INQUIRE, 0, (LPARAM)&cpli);
    ___o_CPlApplet(hWnd, CPL_DBLCLK, 0, cpli.lData);
    ___o_CPlApplet(hWnd, CPL_STOP, 0, cpli.lData);
    ___o_CPlApplet(hWnd, CPL_EXIT, 0, 0);

    hEvt = OpenEvent(EVENT_MODIFY_STATE, FALSE, "ClassicTheme_ColorsChanged");
    if(hEvt) {
      SetEvent(hEvt);
      CloseHandle(hEvt);
    }
  }
  FreeLibrary(hLib);
  DeleteFile(tmpfname2);

}

void PatchIE() {
  char tmp[512], tmp2[512], tmp3[512];
  int ret, i=0, Wow64=0, ok=0; PVOID oldval;
  HANDLE hRes;
  HRSRC hRes2; char *verdata; int versize;
  int fsize; char *fbuff=NULL;

  IsWow64Process(GetCurrentProcess(), &Wow64);
  if(Wow64) Wow64DisableWow64FsRedirection(&oldval);

  WinExec("TASKKILL /F /IM iexplore.exe", SW_HIDE);
  Sleep(500);

  SHGetFolderPath(NULL, CSIDL_PROGRAM_FILES, NULL, 0, tmp);
  i=strlen(tmp);
  if(tmp[i-1]==')' && tmp[i-2]=='6') tmp[i-6]=0;
  
  strcpy(tmp2, "TAKEOWN /A /F \""); strcat(tmp2, tmp); strcat(tmp2, "\\Internet Explorer\\iexplore.exe\"");
  WinExec(tmp2, SW_HIDE);
  Sleep(500);

  strcpy(tmp2, "ICACLS \""); strcat(tmp2, tmp); strcat(tmp2, "\\Internet Explorer\\iexplore.exe\" /grant *S-1-5-32-544:F");
  WinExec(tmp2, SW_HIDE);
  Sleep(500); 

  i=0;
  strcpy(tmp2, tmp); strcat(tmp2, "\\Internet Explorer\\iexplore.exe");
rec:
  wsprintf(tmp3, "%s\\Internet Explorer\\iexplore.bak%u", tmp, i);
  ret = CopyFile(tmp2, tmp3, TRUE);
  if(!ret && GetLastError()==ERROR_FILE_EXISTS) {
    i++;
    goto rec;
  }
  else if(!ret) goto fin;

  hRes2 = FindResource(NULL, (LPCTSTR)IDR_IEMANIFEST, "BIN");
  versize = SizeofResource(NULL, hRes2);
  verdata = LockResource(LoadResource(NULL, hRes2));

  fsize = ExpandSZDD(verdata, versize, &fbuff);
  if(!fsize) return;

  hRes = BeginUpdateResource(tmp2, FALSE);
  UpdateResource(hRes, MAKEINTRESOURCE(RT_MANIFEST), MAKEINTRESOURCE(1), 1033, fbuff, fsize);
  EndUpdateResource(hRes, FALSE);
  FreeSZDD(fbuff, fsize);

  GetSystemWindowsDirectory(tmp2, sizeof(tmp));
  strcat(tmp2, "\\dwmapi.dll");
  strcpy(tmp3, tmp); strcat(tmp3, "\\Internet Explorer\\dwmapi.dll");
  CopyFile(tmp2, tmp3, FALSE);

  GetSystemWindowsDirectory(tmp2, sizeof(tmp));
  strcat(tmp2, "\\dwm_rdr.dll");
  strcpy(tmp3, tmp); strcat(tmp3, "\\Internet Explorer\\dwm_rdr.dll");
  CopyFile(tmp2, tmp3, FALSE);

  ok=1;

fin:
  if(Wow64) Wow64RevertWow64FsRedirection(oldval);

  if(ok) MessageBox(NULL, "Internet Explorer has been successfully patched.", "ClassicTheme", 64);
  else MessageBox(NULL, "Internet Explorer could not be patched.", "ClassicTheme", 16);
}


int DoNow() {
  int ret=1;
  char Path[512]; HANDLE hEvt;
  SC_HANDLE sc_Handle = NULL, drv_Handle; SERVICE_STATUS sst;

  sc_Handle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);

  GetModuleFileName(GetModuleHandle(NULL), Path, sizeof(Path));
  strcat(Path, DoNowGUIDs);

  if(sc_Handle) {
    drv_Handle = CreateService(sc_Handle, DoNowGUID, DoNowGUID, SERVICE_ALL_ACCESS, \
      SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, Path, NULL, NULL, NULL, NULL, NULL);

    if(drv_Handle) {
      hEvt = CreateEvt("Global\\ClassicThemeEvent3");

      StartService(drv_Handle, 0, NULL);

      ret = !!WaitForSingleObject(hEvt, 5000);
      CloseHandle(hEvt);

      ControlService(drv_Handle, SERVICE_CONTROL_STOP, &sst);
      DeleteService(drv_Handle);      
      CloseServiceHandle(drv_Handle);
    }
    CloseServiceHandle(sc_Handle);
  }

  return ret;
}


int IsAdmin, IsInstalled;

void RunElevated(char *GUID) {
  char Path[512];
  int ret;

  GetModuleFileName(GetModuleHandle(NULL), Path, sizeof(Path));
  ret = (int)ShellExecute(NULL, "runas", Path, GUID, NULL, SW_SHOWNORMAL);
}

BOOL CALLBACK DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
  switch(uMsg) {
    case WM_INITDIALOG:
      SendMessage(hWnd, WM_SETICON, ICON_BIG, (LPARAM)
          LoadImage(GetModuleHandle(NULL), (LPCTSTR)IDI_ICON1, IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), 0)
      );
      SendMessage(hWnd, WM_SETICON, ICON_SMALL, (LPARAM)
          LoadImage(GetModuleHandle(NULL), (LPCTSTR)IDI_ICON1, IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0)
      );
      if(!IsAdmin) {
        SendDlgItemMessage(hWnd, IDC_INSTALL, BCM_SETSHIELD, 0, TRUE);
        SendDlgItemMessage(hWnd, IDC_UNINST, BCM_SETSHIELD, 0, TRUE);
        SendDlgItemMessage(hWnd, IDC_PATCHIE, BCM_SETSHIELD, 0, TRUE);
        SendDlgItemMessage(hWnd, IDC_DONOW, BCM_SETSHIELD, 0, TRUE);
      }
      if(IsInstalled) {
        EnableWindow(GetDlgItem(hWnd, IDC_INSTALL), FALSE);
      }
      else {
        EnableWindow(GetDlgItem(hWnd, IDC_UNINST), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_DESKN), FALSE);
        EnableWindow(GetDlgItem(hWnd, IDC_PATCHIE), FALSE);
      }
      break;
    case WM_COMMAND:
      switch(wParam) {
        case IDC_INSTALL:
          if(IsAdmin) Install();
          else RunElevated(InstallGUID);
          break;
        case IDC_UNINST:
          if(IsAdmin) Uninstall();
          else RunElevated(UninstGUID);
          break;
        case IDC_PATCHIE:
          if(IsAdmin) PatchIE();
          else RunElevated(PatchIEGUID);
          break;
        case IDC_DESKN:
          DeskN(hWnd);
          break;
        case IDC_DONOW:
          if(IsAdmin) DoNow();
          else RunElevated(DoNowGUID);
          break;
      }
      break;
    case WM_CLOSE:
      EndDialog(hWnd, 0);
      break;
  } 
  return 0;
}

void MainNormal() {
  SC_HANDLE sc_Handle = NULL, drv_Handle;
  OSVERSIONINFO osvi; 

  ZeroMemory(&osvi, sizeof(osvi)); osvi.dwOSVersionInfoSize=sizeof(osvi);
  GetVersionEx(&osvi);

  if(osvi.dwMajorVersion<6 || osvi.dwMajorVersion==6 && osvi.dwMinorVersion<2) {
    MessageBox(NULL, "This program is meant to be run under Windows 8 or more recent.", PROGNAME, 48);
    ExitProcess(0);
  }

  IsAdmin = IsUserAnAdmin();

  sc_Handle = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
  drv_Handle = OpenService(sc_Handle, PROGNAME, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE);

  if(drv_Handle) {
    CloseServiceHandle(drv_Handle);
    CloseServiceHandle(sc_Handle);
    IsInstalled=1;
  }
  else {
    CloseServiceHandle(sc_Handle);
    IsInstalled=0;
  }

  DialogBoxParam(GetModuleHandle(NULL), (LPCTSTR)IDD_MAINWIN, NULL, DlgProc, 0);

  ExitProcess(0);
}

//////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////

void WinMainCRTStartup() {
  HANDLE hTH; PROCESSENTRY32 pe; UINT pid, parpid;
  char *cmdl;
  char modname[256];
  OSVERSIONINFO osvi; 

  ZeroMemory(&osvi, sizeof(osvi)); osvi.dwOSVersionInfoSize=sizeof(osvi);
  GetVersionEx(&osvi);

  if(osvi.dwMajorVersion>6 || osvi.dwMinorVersion>3) IsWin10=1;

  cmdl = GetCommandLine();

  GetModuleBaseName(GetCurrentProcess(), NULL, modname, sizeof(modname));

  if(StrStr(cmdl, InstallGUID)) Install();
  else if(StrStr(cmdl, UninstGUID)) Uninstall();
  else if(StrStr(cmdl, PatchIEGUID)) PatchIE();
  else if(StrStr(cmdl, DPIGUID)) ServiceEntry2();
  else if(StrStr(cmdl, DoNowGUID)) ExitProcess(DoNow());
  else if(StrStr(cmdl, DoNowGUIDs)) MainService();

  pid = GetCurrentProcessId();

  hTH = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  
  pe.dwSize = sizeof(pe);
  Process32First(hTH, &pe);
  do {
    if(pe.th32ProcessID==pid) {
      parpid = pe.th32ParentProcessID;
      break;
    }
  } while(Process32Next(hTH, &pe));

  pe.dwSize = sizeof(pe);
  Process32First(hTH, &pe);
  do {
    if(pe.th32ProcessID==parpid) {
      if(!lstrcmpi(pe.szExeFile, modname)) MainService();
      if(!lstrcmpi(pe.szExeFile, "services.exe")) ServiceEntry();
      if(!lstrcmpi(pe.szExeFile, "userinit.exe")) MainUserinit();
    }
  } while(Process32Next(hTH, &pe));

  if(!lstrcmpi(modname, "ClassicThemeA.exe")) {
    ExitProcess(DoNow());
  }

  MainNormal();

  ExitProcess(0);
}
