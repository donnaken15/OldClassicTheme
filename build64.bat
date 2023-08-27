CL64 /c /Ox /Gr /GS- /W3 /D_CRT_SECURE_NO_WARNINGS ClassicTheme64.c
LINK.EXE ClassicTheme64.obj C:\WINSDK\v7.1\lib\x64\kernel32.lib C:\WINSDK\v7.1\lib\x64\user32.lib C:\WINSDK\v7.1\lib\x64\advapi32.lib C:\WINSDK\v7.1\lib\x64\shell32.lib C:\WINSDK\v7.1\lib\x64\shlwapi.lib C:\WINSDK\v7.1\lib\x64\psapi.lib C:\WINDDK\7600.16385.1\lib\win7\amd64\ntdll.lib /subsystem:windows /nodefaultlib /release /nxcompat /dynamicbase
pause
