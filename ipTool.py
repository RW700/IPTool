import argparse
import threading
import nmap
from subprocess import Popen, PIPE
import json


def main():
    if args.search == True:
        titlePrint("ACTIVE IPS:")
        search()

    elif args.status:
        titlePrint("STATUS OF RELEVANT IPS:")
        status()
    
    elif args.difference == True:
        titlePrint("DIFFERENCES:")
        difference()


def search():
    nm = nmap.PortScanner()
    results = nm.scan(hosts='192.168.1.0/24', arguments='-n -sP')
    results = results['scan']
    for key, value in results.items():
        fancyPrint(key, True)
    writeJson(results)


def status():
    ipList = []
    for _,value in args._get_kwargs():
        if value is not False:
            ipList = value

    for ip in ipList:
        if "-" in ip:
            ipList.remove(ip)
            ipSplit = ip.split("-")
            prefix = '.'.join(ipSplit[0].split(".")[:-1]) + "."
            firstSuffix = int(ipSplit[0].split(".")[-1])
            for subIp in range(int(ipSplit[1]) - firstSuffix + 1):
                newEnd = subIp + firstSuffix
                newFullIp = prefix + str(newEnd)
                ipList.append(newFullIp)

    for singleIp in ipList:
        threading.Thread(target=pingFunct, args=(singleIp,)).start()

def pingFunct(ipToPing):
    cmd = ['ping', '-c', '3', ipToPing]
    proc = Popen(cmd, stdout=PIPE)
    res = str(proc.stdout.read())
    if 'Destination Host Unreachable' in res:
        fancyPrint(ipToPing, False)
    else:
        for line in res.split('\\n'):
            if 'min/avg/max/mdev' in line:
                avg = line.split('=')[1].split('/')[1]
                fancyPrint("{} - {} ms".format(ipToPing, avg), True)

def difference():
    diff = False
    oldSearch = dict(readJson())
    nm = nmap.PortScanner()
    newSearch = nm.scan(hosts='192.168.1.0/24', arguments='-n -sP') 
    newSearch = newSearch['scan']
    
    for k,v in oldSearch.items():
        if not k in newSearch: 
            fancyPrint(k, False)
            diff = True
    for key,val in newSearch.items():
        if not key in oldSearch: 
            fancyPrint(key, True)
            diff = True
    if not diff: fancyPrint("NO DIFFERENCE", False)

def titlePrint(val):
    print("\033[1;35;40m {} \033[0;37;40m".format(val))

def fancyPrint(val, ifActive):
    if ifActive:
        print("\033[1;32;40m  {}  \033[0;37;40m".format(val))
    else:
        print("\033[1;31;40m  {}  \033[0;37;40m".format(val))

def writeJson(toWrite):
    with open('lastSearch.json', 'w', encoding='utf-8') as f:
        json.dump(toWrite, f, ensure_ascii=False, indent=4)

def readJson():
    with open('lastSearch.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
        return data



if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--search', action="store_true", help="Search all IP's on network to find active IPs")
    parser.add_argument('--status', nargs='+', help="Check the status of the following IPs")
    parser.add_argument('--difference', action="store_true", help="Compare new search of all IPs on network to last run")
    args = parser.parse_args()

    main()