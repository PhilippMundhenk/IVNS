'''
Created on 1 Jul, 2015

@author: philipp.mundhenk
'''

import csv
import sys
import time


def main(argv):
    
    path = "/home/cladmin/workspacemasterthesis/Testcases/testcases/synthetic/"
#     f = open(path+'summarizedresults', 'w')
#     f.write("ecu\tauth_time_s\n")
    
    while(1):
#     for e in range(4,101):
        reader = csv.reader(open(path+"test100.csv"), delimiter=";")
#         reader = csv.reader(open(path+"varyECUs_"+str(e)+".csv"), delimiter=";")
    
#         sortedlist = sorted(reader, key=operator.itemgetter(0), reverse=False)
            
        filteredList = [i[0] for i in reader if i[3] == "MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE"]
#         filteredList.sort(key=float)
        
        maxVal=max(filteredList, key=float)
#         f.write(str(e)+"\t"+str(maxVal)+"\n")
#         print(str(e)+": "+ maxVal + " : "+str(filteredList))
        print(maxVal + " : "+str(filteredList))
        print(str(len(filteredList))+" items")
        
        time.sleep(60)
        
#     f.close()
if __name__ == '__main__':
    main(sys.argv[1:])