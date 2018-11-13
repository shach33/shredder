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
import random
from datetime import timedelta

start_time = time.time()

MAX_RECURSION = 5
NUMPREVINST = 15
DEBUG = 0

'''
if DEBUG:
    print idc.GetOpType(addr, 1)
    print "_____"
    print idc.o_reg  # 1
    print idc.o_imm  # 5
    print idc.o_mem  # 2
    print idc.o_phrase  # 3
    print idc.o_displ  # 4
'''
'''
import_list = ["VirtualProtect","CreateThread"
                #, "VirtualProtectEx", "VirtualAllocEx"
               , "VirtualAlloc"
               ,"LoadLibraryExA"
               "LoadLibraryExW"
               ,"CloseHandle"
               , "CreateFileA", "CreateFileW", "CreateFileMappingA","WinExec"#,"WriteFile"
               #, "GetProcAddress"
               #, "ReadFile"
               , "CreateFileMappingW", "CreateProcessA", "CreateProcessW"
               #, "DeleteFileA", "DeleteFileW", "DuplicateHandle","ExitProcess","ExitThread","GetProcAddress","accept","bind","closesocket","connect","ioctlsocket"
               , "DeleteFileA", "DeleteFileW", "DuplicateHandle","ExitProcess","ExitThread","accept","bind","closesocket","connect","ioctlsocket"
               , "listen" , "recv" , "send" , "socket"
               , "URLDownloadToFileA" , "URLDownloadToFileW"
               , " __execv"#, "fclose"
               , "fopen" , "fwrite"
               , "InternetOpenA" , "InternetOpenUrlA" ,"InternetOpenUrlW", "InternetOpenW", "InternetReadFile"
               , "CreateRemoteThread"
               ]
'''
import_list = ["VirtualAlloc","VirtualProtect"]
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
methods["CreateRemoteThread"] = ["hProcess", "lpThreadAttributes", "dwStackSize" , "lpStartAddress", "lpParameter","dwCreationFlags", "lpThreadId"]
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

outfile = "out.csv"
handle = open(outfile,"w")

intStrArg1 = ["rcx","rdx","r8d", "r9d"]
intStrArg2 = ["ecx","edx","r8", "r9"]
intStrArg3 = ["rcx","rdx","r8d", "r9d"]
floatArg = ["xmm0","xmm1","xmm2", "xmm3"]

# Wrapper to operate on sorted basic blocks.
class BBWrapper(object):
  def __init__(self, ea, bb):
    self.ea_ = ea
    self.bb_ = bb

  def get_bb(self):
    return self.bb_

  def __lt__(self, other):
    return self.ea_ < other.ea_

# Creates a basic block cache for all basic blocks in the given function.
class BBCache(object):
  def __init__(self, f):
    self.bb_cache_ = []
    for bb in idaapi.FlowChart(f):
      self.bb_cache_.append(BBWrapper(bb.startEA, bb))
    self.bb_cache_ = sorted(self.bb_cache_)

  def find_block(self, ea):
    #i = bisect_right(self.bb_cache_, BBWrapper(ea, None))
    i = bisect(self.bb_cache_, BBWrapper(ea, None))
    if i:
      return self.bb_cache_[i-1].get_bb()
    else:
      return None


def get_prev_BBs(addr, cur_bb, bb_dep, bb_startEA, bb_endEA):
     prevAdd = idc.PrevHead(addr)
     if addr != bb_startEA[str(cur_bb)] :
         return cur_bb
     else:
         if str(cur_bb) in bb_dep:
           prev_bb = bb_dep[str(cur_bb)]
           #print "Reurning: %s for %s" %(prev_bb,cur_bb)
           return list(prev_bb)
         else:
           #print "Returing blank for %s" % (cur_bb)
           return None

def ret_bb_deps(addr):
    #Get Flowchart of function, the current address belongs to
    f = idaapi.FlowChart(idaapi.get_func(addr))#here()))
    #Check Successor n predecessor blocks for each
    bb_dep =  dict()
    bb_startEA = dict()
    bb_endEA = dict()

    bb_cache = BBCache(idaapi.get_func(addr))
    found = bb_cache.find_block(addr)

    #Finding Basic Block dependencies
    for block in f:
        bb_startEA[str(block.id)] = block.startEA
        bb_endEA[str(block.id)] = idc.PrevHead(block.endEA)
        for succ_block in block.succs():
            #print "Block id: %s, succ id: %s" % (block.id, succ_block.id)
            if not str(succ_block.id) in bb_dep.keys():
                bb_dep[str(succ_block.id)] = set()
            bb_dep[str(succ_block.id)].add(block.id)
        for pred_block in block.preds():
            if not str(block.id) in bb_dep.keys():
                bb_dep[str(block.id)] = set()
            #print "Block id: %s, prev id: %s" % (block.id, pred_block.id)
            bb_dep[str(block.id)].add(pred_block.id)
    return bb_dep, bb_startEA, bb_endEA, found

def getDRegName(addr):
    return GetOpnd(addr,0)

def getArgLoc(reg):
    if reg=="rcx" or reg=="ecx" or reg=="xmm0":
        return 1
    elif reg=="rdx" or reg=="edx" or reg=="xmm1":
        return 2
    elif reg=="r8d" or reg=="r8" or reg=="xmm2":
        return 3
    elif reg=="r9d" or reg=="r9" or reg=="xmm3":
        return 4
    else:
        if reg.find('rsp+')!=-1:
            return 5
        return 0

#Function to find  register values
def find_value(addr, reg_name, bb, bb_dep, bb_startEA, bb_endEA,depth):
    if depth>=MAX_RECURSION:
        #print "returning NF 4"
        return "NF"
    pred_bb_iter = -1
    '''
    if DEBUG:
        for i in bb_dep:
            print "BlockID: %s, {%X,%X}" % (i, bb_startEA[str(i)], bb_endEA[str(i)])
            print bb_dep[i]
    '''
    #rn = random.random()
    ret_set = list()
    if DEBUG:
        print "Cur BB : %s , lookingf for : %s" % (bb, reg_name)
    while True:
        inst = idc.GetMnem(addr)
        dest =  idc.GetOpnd(addr, 0)
        if dest == reg_name or dest == equiReg(reg_name):
            if inst=="xor":
                ret_set.insert(0,0)
                if DEBUG:
                    print "Setting for xor"
            return ret_set
            break

        elif inst == "mov":
            if dest==reg_name:
                new_bb = get_prev_BBs(addr, bb, bb_dep, bb_startEA, bb_endEA)
                if new_bb == bb:
                  addr = idc.PrevHead(addr)
                #Pred Basic block
                else:
                  if new_bb == None:
                    if ret_set == []:
                        return None
                    return ret_set
                  pred_bb_iter = pred_bb_iter + 1
                  while pred_bb_iter < int(len(new_bb)):
                    bb_this_iter  =  new_bb[pred_bb_iter] #str(next(iter(new_bb)))
                    #print "new bB: %s , origin : %s"  %  (bb_this_iter, bb)
                    if int(bb_this_iter) >= int(bb):
                        if DEBUG:
                            print " continuing"
                        pred_bb_iter = pred_bb_iter + 1
                        continue;
                    #print "This bb_iter: " + str(bb_this_iter)
                    addr = bb_endEA[str(bb_this_iter)]
                    #print "Bfre %X" %(addr)
                    rTemp = find_value(addr, reg_name, bb_this_iter,  bb_dep, bb_startEA, bb_endEA,depth+1)
                    if rTemp!=None:
                        ret_set.insert(0,rTemp)
                    #print "return for " + str(bb) + "  dep:" + str(bb_this_iter)  + "this ::: " +  str(pred_bb_iter)
                    pred_bb_iter = pred_bb_iter + 1
            else:
                continue
        else:
            return ret_set
        break


def equiReg(name):
    if name=="ecx":
        return "rcx"
    if name=="edx":
        return "rdx"
    if name=="rdx":
        return "edx"
    if name=="rcx":
        return "ecx"

def getRegUsed(name):
    if name.find('rcx+') != -1:
        return name[name.find('rcx+'):3]
    if name.find('rdx+') != -1:
        return name[name.find('rdx+'):3]

def get_reg_arg(addr, name):
    functions = copy.deepcopy(methods)
    handle.write("\n" + name + "\n")
    if DEBUG:
        print "*************"
        print "for" + name
    s = ()
    #print functions[name]
    numArg = len(functions[name])
    if DEBUG:
        print numArg
    arrArg = ["O"] * numArg
    stackArg = 5
    if DEBUG:
        print "#### StackArg: " + str(stackArg)
    bb_dep, bb_startEA, bb_endEA, found = ret_bb_deps(addr)

    while True:
        if numArg<=0:
            #print "Break Now"
            break
        addr = idc.PrevHead(addr)
        inst = idc.GetMnem(addr)
        #print "Left Args:: " + str(numArg)
        if DEBUG:
            print "instruction: " + inst
        if inst == "xor":
            regName  = getDRegName(addr)
            argLoc = getArgLoc(regName)
            if DEBUG:
                print "[xor] Setting : " + str(argLoc)
            if argLoc <=4:
                arrArg[argLoc-1] = "I"
            else:
                arrArg[stackArg-1] = "I"
                stackArg+=1
            #print arrArg
            numArg-=1
        elif inst == "mov" or inst == "lea" or inst =="test":
            regName  = getDRegName(addr)
            if DEBUG:
                print "Register here: " + regName
            if regName==0:
                continue
            argLoc = getArgLoc(regName)
            if DEBUG:
                print "******Location::" + str(argLoc)

            if argLoc>4:
                if DEBUG:
                    print "In stack  stackArg" + str(stackArg)
                argLoc=stackArg
                stackArg+=1
            if idc.GetOpType(addr, 1) == idc.o_reg:
                if DEBUG:
                    print "argLoc here: ::::::::: "  + str(argLoc)
                reg_val = find_value(addr, regName, found.id, bb_dep, bb_startEA, bb_endEA, 0)
                #print "REG --------------------------"
                if DEBUG:
                    print ":" + str(reg_val)
                arrArg[argLoc - 1] =  "R"
                #print "Register found"
            elif idc.GetOpType(addr, 1) == idc.o_imm:
                arrArg[argLoc - 1] = "I"
                if DEBUG:
                    print "Immediate  value found "
                    print arrArg
            elif idc.GetOpType(addr, 1) == idc.o_mem:
                arrArg[argLoc - 1] =  "A"
                if DEBUG:
                    print "Memory address found"
            elif idc.GetOpType(addr, 1) == idc.o_phrase:
                arrArg[argLoc - 1] =  "F"
                if DEBUG:
                    print "Memory Ref found"
            elif idc.GetOpType(addr, 1) == idc.o_displ:
                arrArg[argLoc - 1] =  "D"
                regUsed = getRegUsed(regName);
                reg_val = find_value(addr, regName, found.id, bb_dep, bb_startEA, bb_endEA, 0)
                if reg_val==None:
                    reg_val = find_value(addr, equiReg(regName), found.id, bb_dep, bb_startEA, bb_endEA, 0)
                if reg_val:
                    arrArg[argLoc-1] = "I"
                if DEBUG:
                    print "Memory (base+reg+disp) found"
                    print arrArg
            else:
                arrArg[argLoc - 1] = "0"
                if DEBUG:
                    print "None found"
            if DEBUG:
                print str(GetOpnd(addr, 1)) + "=>" + str(GetOperandValue(addr,1)) #GetDisasm(addr).split(";")[0]
            numArg-=1
        elif inst=="and" or inst=="sub" or inst=="add" or inst=="or":
            reg1=  getDRegName(addr)
            reg2 = GetOpnd(addr, 1)
            argLoc = getArgLoc(reg1)
            arrArg[argLoc-1] = "L"
            #Find Regs 1,2
            if DEBUG:
                print "To Find now: " + reg1 + " " + inst + " " + reg2
            reg1_val = find_value(addr, reg1, found.id, bb_dep, bb_startEA, bb_endEA, 0)
            if idc.GetOpType(addr, 1) == idc.o_reg:
                if DEBUG:
                    print "reg2: " + str(reg2)
                reg2_val = find_value(addr, reg2, found.id, bb_dep, bb_startEA, bb_endEA, 0)
            elif idc.GetOpType(addr, 1) == idc.o_imm:
                reg2_val = GetOpnd(addr, 1)
            else:
                reg2 = "NF"
            if DEBUG:
                print "reg1: " + str(reg1_val)
                print "reg2: " + str(reg2_val)
            numArg-=1
        else:
            continue
    s = s + (str(arrArg),)
    print frozenset(s)
    # return frozenset(s)
    return s


def find_xrefs(ea, name):
    setArgs = set()
    for addr in XrefsTo(ea, flags=0):
        if str(XrefTypeName(addr.type))=="Code_Near_Call":
            #print hex(addr.frm)
            #print "%08x" % (addr.frm)
            stack_args = get_reg_arg(addr.frm, name)
            #print stack_args
            #setArgs.add(stack_args)
    #for x in setArgs:
    #    target.writerow(list(x))
    #mat = numpy.row_stack(setArgs)
    numOfUniqueInstances = len(setArgs)
    numArgs = len(methods[name])
    print "numArgs " + str(numArgs)
    toCompare = ''
    predNum = 0
    for i in range(0, numOfUniqueInstances):
        toCompare = toCompare + str("I")
    for c in range(0,numArgs ):
        txt = ''
        for r in range(0, numOfUniqueInstances):
            txt = txt + mat[r][c]
        if txt==toCompare:
            predNum = predNum + 1
    print "predNums " + str(predNum)
    target.writerow([name,numArgs,predNum])


def imp_cb(ea, name, ord):
    if not name:
        print "%08x: ord#%d" % (ea, ord)
    else:
        if name in import_list:
            print "%08x: %s (ord#%d)" % (ea, name, ord)
            find_xrefs(ea, name)
    # True -> Continue enumeration
    # False -> Stop enumeration
    return True


nimps = idaapi.get_import_module_qty()
print "Found %d import(s)..." % nimps

#CSV File To Write
fileName = idaapi.get_root_filename().split('.')[0] +'.csv'
filePath = os.path.expanduser('~')  + "\\Documents\\shredder\\Shredder64\\" + fileName

try:
    os.remove(filePath)
except OSError:
    pass
target = csv.writer(open(filePath, 'wb'))

for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        print "Failed to get import module name for #%d" % i
        continue

    #print "Walking-> %s" % name
    #if name=="KERNEL32":
    idaapi.enum_import_names(i, imp_cb)

print "All done..."

print("--- %s seconds ---" % (time.time() - start_time))
handle.close()

