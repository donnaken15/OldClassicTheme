cl /Ox /GS- dwmapi.c /link /DLL /NODEFAULTLIB /ENTRY:_start /OUT:dwmapi.dll /DYNAMICBASE /NXCOMPAT /RELEASE /DEF:dwmapi.def KERNEL32.LIB USER32.LIB SHLWAPI.LIB
cl64 /Ox /GS- dwmapi.c /link /DLL /NODEFAULTLIB /ENTRY:_start /OUT:dwmapi64.dll /DYNAMICBASE /NXCOMPAT /RELEASE /DEF:dwmapi.def C:\WINSDK\v7.1\Lib\x64\KERNEL32.LIB C:\WINSDK\v7.1\Lib\x64\USER32.LIB C:\WINSDK\v7.1\Lib\x64\SHLWAPI.LIB
@pause