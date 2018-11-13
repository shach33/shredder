# Shachee Mishra #
import idaapi
from idautils import *
from idc import *
import sys
import inspect
import copy
from bisect import bisect
import csv
import os
import numpy
from numpy import ndarray
import time
from datetime import timedelta

start_time = time.time()

nimps = idaapi.get_import_module_qty()

print "Found %d import(s)..." % nimps
imported_list=[]
#'''
import_list = ["VirtualProtect","CreateThread", "VirtualProtectEx", "VirtualAllocEx", "VirtualAlloc"
               ,"LoadLibraryExA"
               "LoadLibraryExW"
               ,"CloseHandle", "CreateFileA", "CreateFileW", "CreateFileMappingA","WinExec","WriteFile", "ReadFile"
               , "CreateFileMappingW", "CreateProcessA", "CreateProcessW"
               , "DeleteFileA", "DeleteFileW", "DuplicateHandle","ExitProcess","ExitThread","accept","bind","closesocket","connect","ioctlsocket"
               , "listen" , "recv" , "send" , "socket"
               , "URLDownloadToFileA" , "URLDownloadToFileW"
               , " __execv", "fclose" , "fopen" , "fwrite"
               , "InternetOpenA" , "InternetOpenUrlA" ,"InternetOpenUrlW", "InternetOpenW", "InternetReadFile"
               ]
'''
#import_list = ["VirtualProtect"]
import_list = ["VirtualProtect","CreateThread", "VirtualProtectEx", "VirtualAllocEx", "VirtualAlloc"
               ,"LoadLibraryExA"
               ,"LoadLibraryExW"
			   , "LoadLibraryW"
			   , "LoadLibraryA"
			   , "LoadLibrary"
               , "LoadLibraryEx"
			   ,"CloseHandle", "CreateFileA", "CreateFileW", "CreateFileMappingA","WinExec","WriteFile", "ReadFile"
               , "CreateFileMappingW", "CreateProcessA", "CreateProcessW"
               , "DeleteFileA", "DeleteFileW", "DuplicateHandle","ExitProcess","ExitThread","GetProcAddress","accept","bind","closesocket","connect","ioctlsocket"
               , "DeleteFileA", "DeleteFileW", "DuplicateHandle","ExitProcess","ExitThread","accept","bind","closesocket","connect","ioctlsocket"
               , "listen" , "recv" , "send" , "socket"
               , "URLDownloadToFileA" , "URLDownloadToFileW"
               , " __execv", "fclose" , "fopen" , "fwrite"
               , "InternetOpenA" , "InternetOpenUrlA" ,"InternetOpenUrlW", "InternetOpenW", "InternetReadFile"
			   , "coTaskmemAlloc", "globalAlloc", "heapAlloc", "localAlloc", "malloc", "new" 
			   , "CreateRemoteThread", "ShellExecute", "ShellExecuteEx", "system"
			   , "FindClose"
			   , "CreateTextFile", "WriteAllText", "WriteAllLines", "Write", "WriteLine", "WriteAsync"
               , "WriteTextAsync", "WriteLinesAsync", "WriteLineAsync", "AppendLinesAsync", "AppendTextAsync"
			   , "AppendAllLines", "AppendAllText", "AppendText", "WriteFile", "FtpGetFile", "FtpPutFile"
			   , "FileOpenPicker"
			 	, "OpenFile", "FtpOpenFile", "ReadFile", "CreateFileMapping"
				, "remove", "unlink", "MoveFileEx", "MoveFileTransacted", "MoveFileWithProgress"
				, "FtpDeleteFile", "_wremove"
				, "WSADuplicateHandle"
				, "TerminateProcess", "_tsystem"
				, "shutdown"
				, "WSAAsyncSelect", "WSAEventSelect", "WSAIoctl"
				, "libcurl"
				, "open", "WinInet", "HttpOpenRequest", "HttpSendRequest"
				, "FtpGetFile", "FtpGetFileEx", "FtpOpenFile"]



#'''
methods = dict()
#methods["VirtualProtect"] = ["lpflOldProtect", "flNewProtect", "dwSize"]#, "lpAddress"]
methods["VirtualProtect"] = ["aa","flNewProtect","aa",  "dwSize"]#, "lpAddress"]
methods["CreateThread"] = ["lpThreadId", "dwCreationFlags", "lpParameter", "lpStartAddress", "dwStackSize", "lpThreadAttributes"]
methods["CreateFileW"] = ["hTemplateFile", "dwFlagsAndAttributes", "dwCreationDisposition", "lpSecurityAttributes", "dwShareMode", "dwDesiredAccess" , "lpFileName"]
methods["VirtualProtectEx"] = ["lpflOldProtect", "flNewProtect", "dwSize", "lpAddress", "hProcess"]
methods["CreateProcessW"] = ["ProcessInfo", "StartUpInfo", "CurrentDirectory", "lpEnvironment", "lpThreadAttributes", "lpProcessAttributes", "lpCommandLine", "lpApplicationName", "bIntehirtHandles", "dwCreationFlags"]
methods["LoadLibraryExA"] = ["dwFlags", "hFile"]
methods["LoadLibraryExW"] = ["dwFlags", "hFile", "lpLibFileName"]
methods["VirtualAllocEx"] = ["flProtect", "flAllocationType", "dwSize", "lpAddress", "hProcess"]
methods["VirtualAlloc"] = ["flProtect", "flAllocationType", "dwSize", "lpAddress"]
methods["CloseHandle"] = ["hObject"]
methods["CreateFileA"] = ["hTemplateFile", "dwFlagsAndAttributes", "dwCreationDisposition", "lpSecurityAttributes", "dwShareMode", "dwDesiredAccess", "lpFileName"]
methods["CreateFileMappingA"] = ["lpName","dwMaximumSizeLow","dwMaximumSizeHigh","flProtect","lpFileMappingAttributes","hFile"]
methods["CreateFileMappingW"] = ["lpName","dwMaximumSizeLow","dwMaximumSizeHigh","flProtect","lpFileMappingAttributes","hFile"]
methods["CreateProcessA"] = ["lpProcessInformation","lpStartupInfo","lpCurrentDirectory","lpEnvironment","dwCreationFlags","bInheritHandles","lpThreadAttributes","lpProcessAttributes","lpCommandLine","lpApplicationName"]
methods["CreateProcessW"] = ["lpProcessInformation","lpStartupInfo","lpCurrentDirectory","lpEnvironment","dwCreationFlags","bInheritHandles","lpThreadAttributes","lpProcessAttributes","lpCommandLine","lpApplicationName"]
methods["DeleteFileA"] = ["lpFileName"]
methods["DeleteFileW"] = ["lpFileName"]
methods["DuplicateHandle"] = ["dwOptions","bInheritHandle","dwDesiredAccess","lpTargetHandle","hTargetProcessHandle","hSourceHandle","hSourceProcessHandle"]
methods["ExitProcess"] = ["uExitCode"]
methods["ExitThread"] = ["dwExitCode"]
methods["GetProcAddress"] = ["lpProcName","hModule"]
methods["accept"] = ["addrlen","addr","s"]
methods["bind"] = ["namelen","name","s"]
methods["closesocket"] = ["s"]
methods["connect"] = ["namelen","name","s"]
methods["ioctlsocket"] = ["argp","cmd","s"]
methods["listen"] = ["backlog","s"]
methods["recv"] = ["flags","len","buf","s"]
methods["send"] = ["flags","len","buf","s"]
methods["socket"] = ["protocol","type","af"]
methods["WinExec"] = ["uCmdShow","lpCmdLine"]
methods["WriteFile"] = ["lpOverlapped","lpNumberOfBytesWritten","nNumberOfBytesToWrite","lpBuffer","hFile"]
methods["ReadFile"] = ["lpOverlapped","lpNumberOfBytesRead","nNumberOfBytesToRead","lpBuffer","hFile"]
methods["URLDownloadToFileA"] = ["lpfnCB","dwReserved","szFileName","szURL","pCaller"]
methods["URLDownloadToFileW"] = ["lpfnCB","dwReserved","szFileName","szURL","pCaller"]
methods["__execv"] = ["argv","cmdname"]
methods["fclose"] = ["stream"]
methods["fopen"] = ["mode","filename"]
methods["fwrite"] = ["stream","count","size","buffer"]
methods["InternetOpenA"] = ["dwFlags","lpszProxyBypass" , "lpszProxyName" , "dwAccessType" ,"lpszAgent"]
methods["InternetOpenUrlA"] = ["dwContext" , "dwFlags" , "dwHeadersLength" , "lpszHeaders" , "lpszUrl" , "hInternet"]
methods["InternetOpenUrlW"] = ["dwContext" , "dwFlags" , "dwHeadersLength" , "lpszHeaders" , "lpszUrl" , "hInternet"]
methods["InternetOpenW"] = ["dwFlags","lpszProxyBypass" , "lpszProxyName" , "dwAccessType" ,"lpszAgent"]
methods["InternetReadFile"] = ["lpdwNumberOfBytesRead" , "dwNumberOfBytesToRead" , "lpBuffer" , "hFile"]
methods["WSASocketW"] = ["dwFlags" , "g" , "lpProtocolInfo" , "protocol" , "type", "af"]
methods["WSASocketA"] = ["dwFlags" , "g" , "lpProtocolInfo" , "protocol" , "type", "af"]
methods["WSAStartup "] = ["lpWSAData","wVersionRequested"]

numCritImported=0
nCallSite = 0
used_funcs = 0
kernel32Imp = 0
advapiImp = 0
user32Imp = 0
ole32Imp = 0

def find_xrefs(ea, name):
	xrefs = 0;
	for addr in XrefsTo(ea, flags=0):
		xrefs+=1
	return xrefs
	
    
def imp_cb(ea, name, ord):
	global numCritImported
	if not name:
		print "%08x: ord#%d" % (ea, ord)
	else:
		global used_funcs
		used_funcs+=1
		if name in import_list:
			numCritImported+=1
			imported_list.insert(0,name)

    # True -> Continue enumeration
    # False -> Stop enumeration
	return True# used_funcs
	
	
for i in xrange(0, nimps):
	name = idaapi.get_import_module_name(i)
	if not name:
		print "Failed to get import module name for #%d" % i
		continue
	#global numCritImported
	#global used_funcs
	idaapi.enum_import_names(i, imp_cb)
	if name=="KERNEL32":
		kernel32Imp+= used_funcs;
	if name=="ADVAPI32":
		advapiImp+= used_funcs;
	if name=="USER32":
		user32Imp+= used_funcs;
	if name=="OLE32":
		ole32Imp+= used_funcs;
	used_funcs = 0
		
	#numCritImported = 0
    
print "Kernel32 imports: %d " % (kernel32Imp)
print "ADVAPI imports: %d " % (advapiImp)
print "User32 imports: %d " % (user32Imp)
print "Ole32 imports: %d " % (ole32Imp)

print("--- %s seconds ---" % (time.time() - start_time))
