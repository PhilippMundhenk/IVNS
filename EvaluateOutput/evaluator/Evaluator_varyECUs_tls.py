'''
Created on 1 Jul, 2015

@author: philipp.mundhenk
'''

import csv
import operator
import sys


def main(argv):

    paths = ["tls/CyaSSL/False/","tls/Crypto_Lib_HW/False/"]

    for p in paths:
        common_path = "/home/cladmin/workspacemasterthesis/Testcases/testcases/synthetic/"
        result_path = p
        summary_path = "summary/"
            
        file_auth_analyzed = open(common_path+summary_path+result_path+'Auth_analyzed.txt', 'w')
        file_auth_analyzed.write("ecus\tavg_ecu_time_s\tlower\tupper\n")
        file_auth_raw = open(common_path+summary_path+result_path+'Auth_raw.txt', 'w')
        file_auth_raw.write("ecus\ttime\n")
        
        '''This comes from the shell script generating messages'''
        messageFactor = 5
    
        AuthDur_avg = dict()
        AuthDur_min = dict()
        AuthDur_max = dict()
        
        for e in range(4, 101):
    #     for e in range(4, 6):
            print("ECUs: " + str(e))
            maxAuths = dict()
            for r in range(0, 21):
                filename = "varyECUs-" + str(e) + "-run-" + str(r) + ".csv"
                print("file: "+result_path + filename)
                try:
                    reader = csv.reader(open(common_path + result_path + filename), delimiter=";")
                except:
                    print("not found")
                    continue
    
                readerList = list(reader)
                
                AuthStart = [i[0] for i in readerList if i[3] == "MonitorTags.CP_SEND_CLIENT_HELLO"][0]
                AuthEnd = [[i[0], i[1]] for i in readerList if i[3] == "MonitorTags.CP_SERVER_AUTHENTICATED"]
                
                AuthEnd = sorted(AuthEnd, key=operator.itemgetter(0), reverse=False)
                
                print(AuthStart)
                print(AuthEnd)
                
                '''find the times for all ECUs'''
#                 ECUAuthVals = dict()
#                 for f in AuthEnd:
#                     ECUAuthVals[f[1]] = float(f[0]) - float(AuthStart)
                '''find the last ECU completed'''
#                 for m in ECUAuthVals:
#                     if not r in maxAuths:
#                         maxAuths[r] = ECUAuthVals[m]
#                     elif (ECUAuthVals[m] > maxAuths[r]):
#                         maxAuths[r] = ECUAuthVals[m]      
                for m in AuthEnd:
                    time = float(m[0]) - float(AuthStart)
                    if not r in maxAuths:
                        maxAuths[r] = time
                    elif (time > maxAuths[r]):
                        maxAuths[r] = time
                        
                file_auth_raw.write(str(e) + "\t" + str(maxAuths[r]) + "\n")
    
            '''average, min, max over all the longest ECU runs and save for number of ECUs'''
            s = 0
            minimum = sys.float_info.max
            maximum = 0
            for m in maxAuths:
                s += maxAuths[m]
                if (maxAuths[m] > maximum):
                    maximum = maxAuths[m]
                if (maxAuths[m] < minimum):
                    minimum = maxAuths[m]
            AuthDur_avg[e] = s / len(maxAuths)
            AuthDur_min[e] = AuthDur_avg[e] - minimum
            AuthDur_max[e] = maximum - AuthDur_avg[e]
            
        for d in AuthDur_avg:
            print(str(d) + ": " + str(AuthDur_avg[d]))
            file_auth_analyzed.write(str(d) + "\t" + str(AuthDur_avg[d]) + "\t" +str(AuthDur_min[d]) + "\t" + str(AuthDur_max[d]) + "\n")
            
        file_auth_analyzed.close()
        file_auth_raw.close()
if __name__ == '__main__':
    main(sys.argv[1:])
