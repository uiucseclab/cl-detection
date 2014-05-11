'''
Created on Mar 11, 2014

@author: donaldcha
'''
import xml.etree.ElementTree as ET
import sys

def parse_sandbox(xml_file):

    ignore_files = ["C:\Program Files\Internet Explorer\iexplore.exe", \
                    "C:\WINDOWS\explorer.exe"]

    '''
    Getting suspicious processes through looping the xml file.
    '''
    xml_root = xml_file.getroot()
    processes = xml_root[0]
    total = 0
    proc_list = []
    for process in processes:
        if 'path' in process.attrib:
            if process.attrib['path'] not in ignore_files and "C:\WINDOWS\system32\\" not in process.attrib['path']\
            and "C:\Program Files\\" not in process.attrib['path']:
                #print process.attrib['path']
                proc_list.append(process.attrib['path'])
                
    '''
    Check each process
    '''
    for process in processes:
        if 'path' in process.attrib and process.attrib['path'] in proc_list:
            '''
            Check if arg is encoded in base64
            '''
            for arg in process.iter('args'):
                if "binary.base64" in arg.attrib['dt']:
                    total += 5

            '''
            Check if .exe file is written to Application Data
            '''
            for file in process.iter('filesystem_section'):
                for write in file.iter('write_file'):
                    if "Application Data" in write.attrib['path'] and ".exe" in write.attrib['path']:
                        #check if a process writes an .exe file
                        #print write.attrib['path']
                        total += 15 #this evidence is worth 15 points for now (a lot)
            
            '''
            Check for suspicious registry modifications
            '''
            for registry in process.iter('registry_section'):
                for set_value in registry.iter('set_value_key'):
                    '''
                    Check if executable in application data is set to auto run
                    '''
                    if "Application Data" in set_value.attrib['data'] and ".exe" in set_value.attrib['data']\
                     and "\Windows\CurrentVersion\Run" in set_value.attrib['key']:
                        #Check if the exe file sets run registry
                        #print set_value.attrib['data']
                        total += 10
                    '''
                    Check if registry entry is stored for PublicKey
                    '''
                    if "PublicKey" in set_value.attrib['value']:
                        #Check if the process sets a public key on registry section
                        total += 5
                    '''
                    Check if path to encrypted file is stored in registry
                    '''
                    if set_value.attrib['key'].endswith("\Files"):
                        #Checks for the file that are encrypted
                        print "Encrypted file - " + set_value.attrib['value']
                        total += 2
    
    print ("Total score: " + str(total))
    if total >= 40:
        print ("This is not a false positive. This binary is cryptolocker.\n")
    elif total >= 20:
        print ("Unable to indentify - Program might have detected running in a sandbox and taken action.\n")
    else:
        print ("FALSE POSITIVE\n")
        
    
                        