#!/usr/bin/env python


funcDict = { 
	# 
	'CREATETHREAD': ['CreateThread'],
	'PROCESSITER': ['CreateToolhelp32Snapshot', 'Process32First', 'Process32Next'],
	'WINHOOK': ['SetWindowsHookEx'],
	'RETROINJECTION': ['GetCurrentProcess', 'CreatePipe', 'DuplicateHandle'],
	'WINEXEC': ['WinExec'],
	'SHELLEXEC': ['ShellExecute'],
	'CREATEPROC': ['CreateProcess'],
	'EXITSYSTEM': ['ExitWindows'],
	'REMTHREAD': ['CreateThread', 'WriteProcessMemory', 'ReadProcessMemory', 'ResumeThread'],
	
	# Autostarts & infiltration
	'REGSETVAL': ['RegOpenKey', 'RegSetValue'],
	'REGQUERY': ['RegOpenKey', 'RegQueryValue'],
	'CREATESTARTSERVICE': ['OpenSCManager', 'CreateService', 'OpenService', 'StartService'],
	'DUMPRSRC': ['FindResource', 'LoadResource', 'CreateFile', 'WriteFile'],
	'LOADRSRC': ['FindResource', 'LoadResource', 'LockResource'],
	'UPDATERESOURCE': ['BeginUpdateResource', 'UpdateResource', 'EndUpdateResource'],

	# Dynamic API loading
	'APILOADING': ['GetProcAddress'],
	#'APILOADING2': ['GetModuleHandle', 'GetProcAddress'],
	
	# File interaction
	'WRITEFILE': ['CreateFile', 'WriteFile'],
	'READFILE': ['CreateFile', 'ReadFile'],
	'TEMPFILEWRITE': ['GetTempFileName', 'CreateFile', 'WriteFile'],
	'FPRINT': ['fopen', 'fprintf', 'fclose'],
	
	# Malware activity
	'DRIVESITER': ['GetLogicalDriveStrings', 'GetDriveType'],
	'FILEITER': ['FindFirstFile', 'FindNextFile', 'FindClose'],
	'WINDOW': ['CreateWindow', 'RegisterClass', 'DispatchMessage'],
	'SCREENSHOT': ['CreateCompatibleDC', 'GetDeviceCaps', 'CreateCompatibleBitmap', 'BitBlt'],
	'CRYPTENCRYPT': ['CryptEncrypt'],

	# Network activity
	'WSASEND': ['WSAStartup', 'gethostbyname', 'send'],
	'RECV': ['recv'],
	'SEND': ['send']
	
	
}

rbotDict = {
	'DOWNLOAD': ['InternetOpenUrl', 'CreateFile', 'GetTickCount', 'WriteFile', 'CloseHandle', 'ShellExecute', 'CreateProcess'],
	'DRIVEINFO': ['GetDriveType', 'GetDiskFreeSpace', 'GetLogicalDriveStrings', 'DriveSpace'],
	'FINDFILE': ['FindFirstFile', 'FindNextFile', 'FindClose', 'ExitThread']
}




 
# TODO extend on those, and add moarrr:
# spawn a process
# execute a file
# move file, delete, create dir                                          -
# regenumkey
# createmutex
# fopen, fread, fwrite
# clipboard
# screen capture etc.

