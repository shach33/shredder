import glob
import os
from subprocess import call

'''
list_of_files = glob.glob("C:\Users\vmuser01\Documents\IDAPython\Exploits\Payloads\*") 
print list_of_files
latest_file = max(list_of_files, key=os.path.getctime)
print latest_file
'''
#newest = max(glob.iglob('*.txt'), key=os.path.getctime)
#print newest
print "******************"
listOfPayloads =  glob.glob("*.txt")
for l in listOfPayloads:
    if l!="apitracker.exe":
        print l
        '''
        cmdToRun = "apitracker.exe " + l + " 0"
        call(cmdToRun, shell=True)
        newest = max(glob.iglob('*.txt'), key=os.path.getctime)
        newFileName = l.split('.')[0] + '.txt'
        print newFileName
        os.rename(newest,newFileName)
        '''
