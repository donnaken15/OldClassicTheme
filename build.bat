CL /c /Ox /Gr /GS- /W3 /D_CRT_SECURE_NO_WARNINGS ClassicTheme.c
RC script1.rc
LINK.EXE ClassicTheme.obj script1.res kernel32.lib user32.lib advapi32.lib shell32.lib shlwapi.lib psapi.lib memset.obj C:\WINDDK\7600.16385.1\lib\win7\i386\ntdll.lib /subsystem:windows /nodefaultlib /release /nxcompat /dynamicbase
pause
