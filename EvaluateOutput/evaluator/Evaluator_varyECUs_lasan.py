'''
Created on 1 Jul, 2015

@author: philipp.mundhenk
'''

import csv
import operator
import sys


def main(argv):

    paths_authorized={"lw_auth/CyaSSL/True/", "lw_auth/Crypto_Lib_HW/True/"}
    paths_unauthorized={"lw_auth/CyaSSL/False/", "lw_auth/Crypto_Lib_HW/False/"}
    
    for p in paths_authorized | paths_unauthorized: 
        common_path = "/home/cladmin/workspacemasterthesis/Testcases/testcases/synthetic/"
        result_path = p
        summary_path = "summary/"
        if p in paths_unauthorized:
            ECUAuth = True
            StreamAuth = True
        elif p in paths_authorized:
            ECUAuth = False
            StreamAuth = True
            
        if(ECUAuth):
            file_ecuAuth_analyzed = open(common_path+summary_path+result_path+'ECUAuth_analyzed.txt', 'w')
            file_ecuAuth_analyzed.write("ecus\tavg_ecu_time_s\tlower\tupper\n")
            file_ecuAuth_raw = open(common_path+summary_path+result_path+'ECUAuth_raw.txt', 'w')
            file_ecuAuth_raw.write("ecus\ttime\n")
        if(StreamAuth):    
            file_streamAuth_analyzed = open(common_path+summary_path+result_path+'StreamAuth_analyzed.txt', 'w')
            file_streamAuth_analyzed.write("streams\tavg_stream_time_s\tlower\tupper\n")
            file_streamAuth_raw = open(common_path+summary_path+result_path+'StreamAuth_raw.txt', 'w')
            file_streamAuth_raw.write("streams\ttime\n")
        
            file_streamAuthRelative_raw = open(common_path+summary_path+result_path+'StreamAuthRelative_raw.txt', 'w')
            file_streamAuthRelative_raw.write("streams\ttime\n")
        
        '''This comes from the shell script generating messages'''
        messageFactor = 5
    
        ECUAuthDur_avg = dict()
        ECUAuthDur_min = dict()
        ECUAuthDur_max = dict()
        StreamAuthDur_avg = dict()
        StreamAuthDur_min = dict()
        StreamAuthDur_max = dict()
        
        for e in range(4, 101):
    #     for e in range(4, 6):
            print("ECUs: " + str(e))
            maxECUAuths = dict()
            maxStreamAuths = dict()
            for r in range(0, 21):
                filename = "varyECUs-" + str(e) + "-run-" + str(r) + ".csv"
                print("file: "+result_path + filename)
                reader = csv.reader(open(common_path + result_path + filename), delimiter=";")
    
                readerList = list(reader)
                
                if(ECUAuth | StreamAuth):
                    ECUAuthStart = [i[0] for i in readerList if i[3] == "MonitorTags.CP_SEC_INIT_AUTHENTICATION"][0]
                if(ECUAuth):
                    ECUAuthEnd = [[i[0], i[1]] for i in readerList if i[3] == "MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE"]
                if(StreamAuth):
                    StreamAuthStart = [[i[0], i[6], i[1]] for i in readerList if i[3] == "MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE"]
                    StreamAuthEnd = [[i[0], i[6], i[1]] for i in readerList if i[3] == "MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE"]
                
                if(ECUAuth):
                    ECUAuthEnd = sorted(ECUAuthEnd, key=operator.itemgetter(0), reverse=False)
                if(StreamAuth):
                    StreamAuthStart = sorted(StreamAuthStart, key=operator.itemgetter(0), reverse=False)
                    StreamAuthEnd = sorted(StreamAuthEnd, key=operator.itemgetter(0), reverse=False)
                
                if(ECUAuth):
                    '''find the times for all ECUs'''
                    ECUAuthVals = dict()
                    for f in ECUAuthEnd:
                        ECUAuthVals[f[1]] = float(f[0]) - float(ECUAuthStart)
                    '''find the last ECU completed'''
                    for m in ECUAuthVals:
                        if not r in maxECUAuths:
                            maxECUAuths[r] = ECUAuthVals[m]
                        elif (ECUAuthVals[m] > maxECUAuths[r]):
                            maxECUAuths[r] = ECUAuthVals[m]
                            
                    file_ecuAuth_raw.write(str(e) + "\t" + str(maxECUAuths[r]) + "\n")
    
                if(StreamAuth):
                    '''find stream ECUAuth values'''
                    StreamAuthVals = dict()
                    for start in StreamAuthStart:
                        for end in StreamAuthEnd:
                            if (end[2] == start[2]):
                                '''end is the sender receiving the grant msg'''
        #                         StreamAuthVals[end[2]] = float(end[0]) - float(start[0]) #This one considers from start of stream
                                StreamAuthVals[end[2]] = float(end[0]) - float(ECUAuthStart) #This one considers from start of system
                                
                                file_streamAuthRelative_raw.write(str(e*messageFactor) + "\t" + str(float(end[0]) - float(start[0])) + "\n")
                                
                    '''find the last stream completed'''
                    for m in StreamAuthVals:
                        if not r in maxStreamAuths:
                            maxStreamAuths[r] = StreamAuthVals[m]
                        elif (StreamAuthVals[m] > maxStreamAuths[r]):
                            maxStreamAuths[r] = StreamAuthVals[m]
                            
                    file_streamAuth_raw.write(str(e*messageFactor) + "\t" + str(maxStreamAuths[r]) + "\n")
    
            if(ECUAuth):
                '''average, min, max over all the longest ECU runs and save for number of ECUs'''
                s = 0
                minimum = sys.float_info.max
                maximum = 0
                for m in maxECUAuths:
                    s += maxECUAuths[m]
                    if (maxECUAuths[m] > maximum):
                        maximum = maxECUAuths[m]
                    if (maxECUAuths[m] < minimum):
                        minimum = maxECUAuths[m]
                ECUAuthDur_avg[e] = s / len(maxECUAuths)
                ECUAuthDur_min[e] = ECUAuthDur_avg[e] - minimum
                ECUAuthDur_max[e] = maximum - ECUAuthDur_avg[e]
            
            if(StreamAuth):
                '''average, min, max over all the longest stream runs and save for number of ECUs'''
                s = 0
                minimum = sys.float_info.max
                maximum = 0
                for m in maxStreamAuths:
                    s += maxStreamAuths[m]
                    if (maxStreamAuths[m] > maximum):
                        maximum = maxStreamAuths[m]
                    if (maxStreamAuths[m] < minimum):
                        minimum = maxStreamAuths[m]
                StreamAuthDur_avg[e] = s / len(maxStreamAuths)
                StreamAuthDur_min[e] = StreamAuthDur_avg[e] - minimum
                StreamAuthDur_max[e] = maximum - StreamAuthDur_avg[e]
            
        if(ECUAuth):
            for d in ECUAuthDur_avg:
                print(str(d) + ": " + str(ECUAuthDur_avg[d]))
                file_ecuAuth_analyzed.write(str(d) + "\t" + str(ECUAuthDur_avg[d]) + "\t" +str(ECUAuthDur_min[d]) + "\t" + str(ECUAuthDur_max[d]) + "\n")
            
        if(StreamAuth):
            for d in StreamAuthDur_avg:
                print(str(d*messageFactor) + ": " + str(StreamAuthDur_avg[d]))
                file_streamAuth_analyzed.write(str(d*messageFactor) + "\t" + str(StreamAuthDur_avg[d]) + "\t" +str(StreamAuthDur_min[d]) + "\t" + str(StreamAuthDur_max[d]) + "\n")
    
        if(ECUAuth):
            file_ecuAuth_analyzed.close()
            file_ecuAuth_raw.close()
        if(StreamAuth):
            file_streamAuth_analyzed.close()
            file_streamAuth_raw.close()
if __name__ == '__main__':
    main(sys.argv[1:])
