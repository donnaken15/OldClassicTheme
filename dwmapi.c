#include <windows.h>
#include <shlwapi.h>
#include <dwmapi.h>
#include "out.txt"

struct WINCOMPATTRDATA
{
    DWORD attribute;
    PVOID pData;
    ULONG dataSize;
};

typedef HRESULT (WINAPI *___ORIG_SetWindowCompositionAttribute) (
  HWND hWnd,
  struct WINCOMPATTRDATA *str
);
___ORIG_SetWindowCompositionAttribute ___orig_SetWindowCompositionAttribute;

typedef HRESULT (WINAPI *___ORIG_DwmSetWindowAttribute) (
  HWND hwnd,
  DWORD dwAttribute,
  _In_  LPCVOID pvAttribute,
  DWORD cbAttribute
);
___ORIG_DwmSetWindowAttribute ___orig_DwmSetWindowAttribute;

typedef HRESULT (WINAPI *___ORIG_DwmEnableBlurBehindWindow) (
  HWND hWnd,
  void *pBlurBehind
);
___ORIG_DwmEnableBlurBehindWindow ___orig_DwmEnableBlurBehindWindow;

typedef HRESULT (WINAPI* ___ORIG_DwmExtendFrameIntoClientArea) (
  HWND hWnd,
  _In_  const MARGINS *pMarInset
);
___ORIG_DwmExtendFrameIntoClientArea ___orig_DwmExtendFrameIntoClientArea;

int DSWA_Count=0, TBarChanged=0;

DWORD WINAPI ThrProc(LPVOID lpParm) {
  struct WINCOMPATTRDATA str;
  int dat[4]={0, 0, 0, 0};

  str.attribute = 0x13;
  str.pData = &dat;
  str.dataSize = sizeof(dat);

  Sleep(400);

  ___orig_SetWindowCompositionAttribute(lpParm, &str);

  TBarChanged = 1;

  ExitThread(0);
  return 0;
}

HRESULT WINAPI ___DwmSetWindowAttribute(
  HWND hwnd,
  DWORD dwAttribute,
  _In_  LPCVOID pvAttribute,
  DWORD cbAttribute
) {
  char ClassName[256];

  GetModuleFileName(NULL, ClassName, sizeof(ClassName));
  //if(!StrStrI(ClassName, "explorer.exe") && !StrStrI(ClassName, "iexplore.exe")) return 0xC0000001;

  GetClassName(hwnd, ClassName, sizeof(ClassName));

  if(!lstrcmpi(ClassName, "Shell_TrayWnd") || !lstrcmpi(ClassName, "DV2ControlHost") || !lstrcmpi(ClassName, "TasklistThumbnailWnd")  || !lstrcmpi(ClassName, "Shell_SecondaryTrayWnd")) {
    if(!TBarChanged) {
      CloseHandle(CreateThread(NULL, 0, ThrProc, hwnd, 0, NULL));
    }
    return 0xC0000001;
  }

  return ___orig_DwmSetWindowAttribute(hwnd, dwAttribute, pvAttribute, cbAttribute);
}


HRESULT WINAPI ___DwmExtendFrameIntoClientArea(
  HWND hWnd,
  _In_  const MARGINS *pMarInset
) {

  return ___orig_DwmExtendFrameIntoClientArea(hWnd, pMarInset);
  //return 0xC0000001;
}


HRESULT WINAPI ___DwmEnableBlurBehindWindow(
  HWND hwnd,
  void *pBlurBehind
) {
  char ClassName[256];

  GetModuleFileName(NULL, ClassName, sizeof(ClassName));
  if(!StrStrI(ClassName, "explorer.exe")) return 0xC0000001;

  GetClassName(hwnd, ClassName, sizeof(ClassName));

  if(!lstrcmpi(ClassName, "Shell_TrayWnd") || !lstrcmpi(ClassName, "DV2ControlHost")  || !lstrcmpi(ClassName, "TasklistThumbnailWnd") || !lstrcmpi(ClassName, "Shell_SecondaryTrayWnd")) {
        if(!DSWA_Count) {
      InterlockedIncrement(&DSWA_Count);
      SetWindowLongPtr(hwnd, GWL_STYLE, WS_BORDER | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | DS_MODALFRAME | DS_3DLOOK | WS_POPUP | WS_VISIBLE);
      SetWindowLongPtr(hwnd, GWL_EXSTYLE, WS_EX_TOOLWINDOW | WS_EX_DLGMODALFRAME | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE);
      InterlockedDecrement(&DSWA_Count);
    }

    return 0xC0000001;
  }

  return ___orig_DwmEnableBlurBehindWindow(hwnd, pBlurBehind);
}

HRESULT WINAPI ___DwmIsCompositionEnabled(
  _Out_  BOOL *pfEnabled
) {
  char ClassName[256];

/*  
  GetModuleFileName(NULL, ClassName, sizeof(ClassName));
  if(StrStrI(ClassName, "explorer.exe")) {

    *pfEnabled = TRUE;
    return S_OK;
  }
  */
  *pfEnabled = FALSE;

  return S_OK;
}


BOOL WINAPI ___IsCompositionActive(VOID) {
  return FALSE;
}

int sys_colors[30];
int sav_colors[30];

DWORD WINAPI ThrColorProc(LPVOID lpParm) {
  int i;
  HANDLE hEvt[2];

  hEvt[0] = OpenEvent(SYNCHRONIZE, FALSE, "WinSta0_DesktopSwitch");
  hEvt[1] = CreateEvent(NULL, FALSE, FALSE, "ClassicTheme_ColorsChanged");

colorschanged:
  for(i=0; i<30; i++) {
    sys_colors[i] = i;
    sav_colors[i] = GetSysColor(i);
  }

  while(1) {
    i = WaitForMultipleObjects(2, hEvt, FALSE, INFINITE);
    if(i == WAIT_OBJECT_0 + 1) goto colorschanged;

    SetSysColors(30, sys_colors, sav_colors);
  }

  return 0;
}

DWORD WINAPI ThrTaskbar(LPVOID lpParm) {
  HWND hWnd;

  while(1) {
  hWnd = FindWindowA("Shell_TrayWnd", NULL);
  if(hWnd && TBarChanged) {
    SetWindowLongPtr(hWnd, GWL_STYLE, WS_BORDER | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | DS_MODALFRAME | DS_3DLOOK | WS_POPUP | WS_VISIBLE);
    SetWindowLongPtr(hWnd, GWL_EXSTYLE, WS_EX_TOOLWINDOW | WS_EX_DLGMODALFRAME | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE); 
    TBarChanged=0;
  }

  hWnd = FindWindowA("NotifyIconOverflowWindow", NULL);
  if(hWnd && IsWindowVisible(hWnd)) {
    SetWindowLongPtr(hWnd, GWL_STYLE, WS_BORDER | WS_CLIPSIBLINGS | DS_MODALFRAME | DS_3DLOOK | WS_POPUP | WS_VISIBLE);
    SetWindowLongPtr(hWnd, GWL_EXSTYLE, WS_EX_TOOLWINDOW | WS_EX_DLGMODALFRAME | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE);
  }

  Sleep(750);
  }
}

DWORD WINAPI ThrDPIInvalidate(LPVOID lpParm) {
  int i;
  HANDLE hEvt=NULL;

  while(!hEvt) {
    Sleep(250);
    hEvt = OpenEvent(SYNCHRONIZE, FALSE, "Global\\ClassicThemeDPIEvt");
  }

  while(1) {
    if(WAIT_OBJECT_0 == WaitForSingleObject(hEvt, INFINITE)) {
      ResetEvent(hEvt);
      InvalidateRect(NULL, NULL, TRUE);
      Sleep(200);
      InvalidateRect(NULL, NULL, TRUE);
    }
  }

  return 0;
}

BOOL __stdcall ___OpenThemeData(HWND hWnd, PVOID pvoid) {
  return FALSE;
}

void PatchCode(HANDLE hDll, char *fname, PVOID newfunc) {
#ifdef _WIN64
  char code[] = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0}; // mov rax,x; jmp [rax];
#else
  char code[] = {0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0}; // mov eax,x; jmp [eax];
#endif
  PVOID oldfunc;
  DWORD oldprot;

  oldfunc = GetProcAddress(hDll, fname);

#ifdef _WIN64
  *(PVOID*)(code+2) = newfunc;
#else
  *(PVOID*)(code+1) = newfunc;
#endif

  VirtualProtect(oldfunc,sizeof(code),PAGE_EXECUTE_READWRITE,&oldprot);
  CopyMemory(oldfunc, code, sizeof(code));
  VirtualProtect(oldfunc,sizeof(code),oldprot,&oldprot);
}

BOOL __stdcall _start(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
  HANDLE hDll;
  char ClassName[256];
  DWORD OldProtect;
  PVOID IsComp_IATAddress;

  if(fdwReason != DLL_PROCESS_ATTACH) return TRUE;

  hDll = LoadLibrary("dwm_rdr.dll");
  ___orig_DwmSetWindowAttribute = (___ORIG_DwmSetWindowAttribute)GetProcAddress(hDll, "DwmSetWindowAttribute");
  ___orig_DwmEnableBlurBehindWindow = (___ORIG_DwmEnableBlurBehindWindow)GetProcAddress(hDll, "DwmEnableBlurBehindWindow");
  ___orig_DwmExtendFrameIntoClientArea = (___ORIG_DwmExtendFrameIntoClientArea)GetProcAddress(hDll, "DwmExtendFrameIntoClientArea");

  hDll = LoadLibrary("user32.dll");
  ___orig_SetWindowCompositionAttribute = (___ORIG_SetWindowCompositionAttribute)GetProcAddress(hDll, "SetWindowCompositionAttribute");

  GetModuleFileName(NULL, ClassName, sizeof(ClassName));
  /*
  if(StrStrI(ClassName, "explorer.exe")) {
    hDll = LoadLibrary("uxtheme.dll");
    PatchCode(hDll, "OpenThemeData", ___OpenThemeData);
  }
  */
  if(StrStrI(ClassName, "iexplore.exe")) {
    hDll = LoadLibrary("uxtheme.dll");
    PatchCode(hDll, "IsCompositionActive", ___IsCompositionActive);
  }

  if(StrStrI(ClassName, "explorer.exe")) {
    CloseHandle(CreateThread(NULL, 0, ThrColorProc, NULL, 0, NULL));
    CloseHandle(CreateThread(NULL, 0, ThrDPIInvalidate, NULL, 0, NULL));
    CloseHandle(CreateThread(NULL, 0, ThrTaskbar, NULL, 0, NULL));
  }
  
  return TRUE;
}
