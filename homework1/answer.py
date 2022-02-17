# Maryclare Leonard
# created 1-18-22

#!/usr/bin/env python3
import sys #for user input
import xml.etree.ElementTree as xml
import json

import sqlite3 

dbName = 'example.db' 
con = sqlite3.connect(dbName)
cur = con.cursor()
cur.execute('''CREATE TABLE if not exists cpe (vendor text, product text, versionStart text, startInc text, versionEnd text, endInc text)''')  

# instructions to re-attempt to run program
def printReRunInstruction ():
    print("Run Command:")
    print("python answer.py [filename]") 

def createVersionList(version):
    versionList = []
    for i in version.split("."):
        versionList.append(i)
    return versionList

def minimum(a,b):
    if a <= b:
        return a
    else: 
        return b

def versionCheck (pomVersion, start, startInc, end, endInc):
    pomList = createVersionList(pomVersion)
    startList = createVersionList(start)
    endList = createVersionList(end)

    inStartBound = 0
    inEndBound = 0
    x = len(pomList)
    y = len(startList)
    z = len(endList)
    
    min = minimum(x,y)      #minimum length amongst pomList and startList
    if (startInc=="true"):  #if inclusive check if there is an exact match
        if (x==y):
            for i in range(min): 
                if (pomList[i] != startList[i]):
                    break
                elif (i == min-1):
                    inStartBound = 1
                else:
                    continue
    if (inStartBound == 0):
        for i in range(min):
            if (pomList[i] < startList[i]):             
                break
            elif (pomList[i] > startList[i]):
                inStartBound = 1
            elif ( i == range(min)):
                if ( x > y ):
                    if (pomList(i) != 0):
                        inStartBound = 1
                    else:
                        break
                elif ( x < y ):
                    if (startList(i) == 0 & y == (i)):
                        inStartBound = 1
                    else:
                        break
            else:
                continue

    minEnd = minimum(x,z)   #minimum length amongst pomList and endList
    if (endInc=="true"):    #if inclusive check if there is an exact match
        if (x==z):          #cannot be same if they are not the same size
            for i in range(minEnd): 
                if (pomList[i] != endList[i]):
                    break
                elif (i == minEnd-1):
                    inEndBound = 1
                else:
                    continue
    if (inEndBound == 0):
        for i in range(minEnd):
            if (pomList[i] > endList[i]):
                break
            elif (pomList[i] < endList[i]):
                inEndBound = 1
            elif ( i == range(minEnd)):
                if ( x > z ):
                    if (pomList(i) == 0):
                        inEndBound = 1 
                    else:
                        break
                elif ( x < z ):
                    if (pomList(i) == 0 & y == (i)):
                        inEndBound = 1
                    else:
                        break
            else:
                continue
    if (inStartBound == 1 & inEndBound == 1):
        return "inBounds"
    else:
        return "notIn"

#read file contents to parse for dependencies
def readXml(f):
    print("Known security vulnerabilities detected: ")
    pom = xml.parse(f)
    nsmap = {'m':'http://maven.apache.org/POM/4.0.0'}
    depInfo = {}
    for dependency in pom.findall('.//{http://maven.apache.org/POM/4.0.0}dependency'):
        groupId = dependency.find('m:groupId',nsmap).text           #to match with vendor
        artifactId = dependency.find('m:artifactId',nsmap).text     #to match with product
        version = dependency.find('m:version',nsmap).text           #to check within versionStart versionEnd bounds
        depInfo[groupId] = [artifactId, version]
    return depInfo


#break down cpe23Uri for vendor name
def getVendor(uri):
    vendor = uri.split(':')[3]
    return vendor

#break down cpe23Uri for product name
def getProduct(uri):
    product = uri.split(':')[4]
    return product

#parse json file to add to database
def parseJson(jsonFile):
    with open(jsonFile,'r') as f:
        data = json.load(f)
    cve = data["CVE_Items"]
    for cveItem in cve:
        configs = cveItem["configurations"]
        for a in configs:
            nodes = configs["nodes"]
            for b in nodes:
                children = b["children"]
                for m in children:
                    matches = m["cpe_match"]
                    for c in matches:
                        cpeUri = c["cpe23Uri"]
                        vendor = getVendor(cpeUri)
                        product = getProduct(cpeUri)
                        if "versionStartIncluding" in c:
                            versionStart = c["versionStartIncluding"]
                            startIn = 'true'
                        elif "versionStartExcluding" in c:
                            versionStart = c["versionStartExcluding"]
                            startIn = 'false'
                        if "versionEndIncluding" in c:
                            versionEnd = c["versionEndIncluding"]
                            endIn = 'true'
                        elif "versionEndExcluding" in c:
                            versionEnd = c["versionEndExcluding"] 
                            endIn = 'false'
                        list = [vendor, product, versionStart, startIn, versionEnd, endIn]
                        # enter info into database
                        cur.executemany("INSERT INTO cpe VALUES (?,?,?,?,?,?)",(list,))
                        print("inserted")
                        con.commit() 
    print("done inserting")
                        
def searchDB(db,depInfo):
    for i in depInfo:
        vend = i                    #vendor name
        prod = depInfo[i][0]        #depInfo at vendor name index, first element is product
        version = depInfo[i][1]     #depInfo at vendor name index, second element is version
        listVuls = cur.execute("select * from cpe WHERE vendor=:vend AND product=:prod",{"vend": vend, "prod":prod}).fetchall()
        for i in listVuls:
            startVersion = i[2]
            startInc = i[3]
            endVersion = i[4]
            endInc = i[5]
            inBounds = versionCheck(version,startVersion,startInc,endVersion,endInc)
            if(inBounds == "inBounds"):
                print('\n')
                vendor = i[0]
                print("Vendor: " + vendor)
                product = i[1]
                print("Product: " + product)
                print("Version: " + version)
                print("The Bounds were " + startVersion + " to " + endVersion)
                print("Start Version Inclusive " + startInc)
                print("End Version Inclusive: " + endInc)
   
#main function to grab input from user
def main():
    if (len(sys.argv) == 2):
        depInfo = readXml(sys.argv[1])
    parseJson("nvdcve-1.1-2022.json")  #commented out once database is loaded
    if (depInfo):
        searchDB(dbName,depInfo)

if __name__ == "__main__":
    main()
