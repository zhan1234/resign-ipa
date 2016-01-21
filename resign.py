#!/usr/bin/env python
# author: zhanxianbo
import os
import subprocess 
import zipfile
import tempfile
import glob
import shutil
import  plistlib
import  re

def findCert():
  out = subprocess.Popen(['security', 'find-identity','-v','-p','codesigning'],stdout=subprocess.PIPE)
  oc = out.communicate()

  array = oc[0].split("\n")
  size = len(array)
  for i in range(0,size):
    if i == size-2:
      break
    print array[i]
  print "select a certificate:"
  input = raw_input()
  inputIndex = None
  try:
    inputIndex = int(input) - 1
  except:
    print "invalid inpur"
    return findCert()
  cert = array[inputIndex]
  pattern = re.compile('"(.*)"')
  return pattern.findall(cert)[0]

def entitlementsFix(provision):
  out = subprocess.Popen(['security', 'cms','-D', '-i', provision],stdout=subprocess.PIPE)
  oc = out.communicate()
  plist = plistlib.readPlistFromString(oc[0])
  entity = plist["Entitlements"]
  plistlib.writePlist(entity,"entity.plist")

def copyReplaceRes(res,appDir):
  for path,dirs,files in os.walk(res):
      if len(files) != 0:
        for file in files:
          fullPath = os.path.join(path,file)
          newPath = os.path.join(appDir,file)
          shutil.copy(fullPath,newPath)

def resign(ipa, identity, provision,res="res"):

  output = os.path.splitext(ipa)[0]  + '.resigned.ipa'
  working_dir = tempfile.gettempdir()
  working_dir = os.path.join(os.getcwd(), "package")

  zfile = zipfile.ZipFile(ipa,'r')
  zfile.extractall(working_dir)

  app_dir = glob.glob(working_dir + '/Payload/*')[0]
  # replace resources before resign
  if res:
    if os.path.exists(res):
      copyReplaceRes(res,app_dir)
  #copyProvision
  shutil.copy(provision, os.path.join(app_dir, 'embedded.mobileprovision'))
  #fix entitlements
  entitlementsFix(provision)
  # resign app
  subprocess.call(['codesign', '-fs',identity,'--no-strict','--entitlements=entity.plist',app_dir])

  #pack to zip
  f = zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED)
  for dirpath, dirnames, filenames in os.walk(working_dir):
    for filename in filenames:
      filepath = os.path.join(dirpath, filename)
      f.write(filepath, os.path.relpath(filepath, working_dir))
  f.close()

  shutil.rmtree("package")

def findIpa():
  result = None
  for file in glob.glob("*.ipa"):
    if file.find("resigned") == -1:
      return file
  return  result

def main(argv=None):
  ipa = findIpa()
  identity = findCert()
  provision = glob.glob("*.mobileprovision")[0]
  print ipa,identity,provision
  resign(ipa,identity,provision)

if __name__ == '__main__':
  main()
