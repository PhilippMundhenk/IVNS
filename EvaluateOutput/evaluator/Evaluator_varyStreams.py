'''
Created on 1 Jul, 2015

@author: philipp.mundhenk
'''

from _collections import defaultdict
import csv
import operator
import sys


def main(argv):

    path = "/home/cladmin/workspacemasterthesis/Testcases/testcases/synthetic/"
    file = open(path + 'systemStartOverStreamPerECU.txt', 'w')
    file.write("streams\tavg\tmin\tmax\n")

    average = dict()
    minimal = dict()
    maximal = dict()
    collectedTimes = defaultdict(list)
#     for e in range(0, 1):
    for e in range(0, 11):
        print("senderCoeff: " + str(e / 10))
        for r in range(0, 21):
            coeff = e / 10

            filename = "varyStreams-" + str(coeff) + "-run-" + str(r) + ".csv"
            reader = csv.reader(open(path + filename), delimiter=";")

            sortedlist = sorted(reader, key=operator.itemgetter(0), reverse=False)

            ECUAuthStart = [i[0] for i in sortedlist if i[3] == "MonitorTags.CP_SEC_INIT_AUTHENTICATION"][0]
            ECUAuthEnd = [[i[0], i[1]] for i in sortedlist if i[3] == "MonitorTags.CP_ECU_DECRYPTED_CONF_MESSAGE"]
            StreamAuthStart = [[i[0], i[6], i[1]] for i in sortedlist if i[3] == "MonitorTags.CP_ECU_START_CREATE_REQ_MESSAGE"]
            StreamAuthEnd = [[i[0], i[6], i[1]] for i in sortedlist if i[3] == "MonitorTags.CP_ECU_DECRYPTED_GRANT_MESSAGE"]

            '''find number of streams per ECU'''
            streamsPerECU = dict()
            for ecu in StreamAuthStart:
                if not ecu[2] in streamsPerECU:
                    streamsPerECU[ecu[2]] = 1
                else:
                    streamsPerECU[ecu[2]] = streamsPerECU[ecu[2]] + 1

#             for x in streamsPerECU:
#                 print(x + ":" + str(streamsPerECU[x]))

            '''find last grant message per ECU'''
            ecuSetupTime = dict()
            for ecu in streamsPerECU:
                for end in StreamAuthEnd:
                    if(ecu == end[2]):
                        if not ecu in ecuSetupTime:
                            ecuSetupTime[ecu] = end[0]
#                             print(str(end[0]))
                        elif (end[0] > ecuSetupTime[ecu]):
                            ecuSetupTime[ecu] = end[0]
#                             print(str(end[0]))

#             for x in StreamAuthStart:
#                 ecuSetupTime[x[2]] = float(ecuSetupTime[x[2]]) - float(x[0])

#             for x in ecuSetupTime:
#                 print(x+":"+str(streamsPerECU[x]) + ":" + str(ecuSetupTime[x]))

            for x in ecuSetupTime:
                collectedTimes[streamsPerECU[x]].append(ecuSetupTime[x])
#                 print("numberOfStreams[x]="+str(numberOfStreams[x]))
#                 print("streamSetupTime[x]="+str(streamSetupTime[x]))

    for x in collectedTimes:
        s = 0
        minimal[x] = sys.float_info.max
        maximal[x] = 0
        for y in collectedTimes[x]:
            b = float(y)
            s = s + b
            if(b > maximal[x]):
                maximal[x] = b
            if(b < minimal[x]):
                minimal[x] = b
        average[x] = s / len(collectedTimes[x])

    for d in average:
        print(str(d) + "\t" + str(average[d]) + "\t" + str(minimal[d]) + "\t" + str(maximal[d]))
        file.write(str(d) + "\t" + str(average[d]) + "\t" + str(minimal[d]) + "\t" + str(maximal[d]) + "\n")

    file.close()

if __name__ == '__main__':
    main(sys.argv[1:])
