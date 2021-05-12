import os
import re
import sys
import argparse
from option import hlog, pcap
from geolite import mmdb

# GeoLite DataBase
reader = mmdb.reader

# for Parse pcap-log
savePacket = None

desc = """ #研究用 #WOWHoneypot #HTTP #HTTPS #PCAP"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('-l','--logch',nargs=1,type=str,help="python3 hpot.py -l sample_log/8_https_1208")
    parser.add_argument('-ll','--logch_limited',nargs="+",type=str,help="python3 hpot.py -ll sample_log/8_https_1208 ...")
    parser.add_argument('-lf','--logch_find',nargs="+",type=str,help="python3 hpot.py -lf sample_log/8_https_1208 ...")
    parser.add_argument('-ln','--logchnum',nargs="+",type=str,help="python3 hpot.py -ln sample_log/8_https_1208 ...")
    parser.add_argument('-m','--make',nargs="+",type=str,help="python3 hpot.py -m sample_log/8_https_1208 ...")
    parser.add_argument('-i','--integrate',nargs='+',type=str,help="python3 hpot.py -i 8_https_1208_request 7_https_1208_request ...")
    parser.add_argument('-d','--diff',nargs=2,help="python3 hpot.py -d 8_https_1208_request 8_http_1208_request ")
    parser.add_argument('-p','--pcapch',nargs=1,type=str,help="python3 hpot.py -p sample_log/6_https_1208.pcap")
    parser.add_argument('-cia','--c_ip_all',nargs='+',type=str,help="python3 hpot.py -cia sample_log/8_https_1208 ...")
    parser.add_argument('-cip','--c_ip_particular',nargs='+',type=str,help="python3 hpot.py -cip sample_log/8_https_1208 ...")
    parser.add_argument('-cpp','--c_pcapch_particular',nargs='+',type=str,help="python3 hpot.py -cpp sample_log/8_https_1208.pcap ...")
    parser.add_argument('-cppp','--c_pcapch_particular_plus',nargs='+',type=str,help="python3 hpot.py -cppp sample_log/8_https_1208.pcap ...")
    args = parser.parse_args()

    if args.logch:
        path = args.logch
        hlog.logch(path[0])
    elif args.logch_limited:
        args = args.logch_limited
        for i in range(0,len(args)):
            hlog.logch_limited(args[i])
    elif args.logch_find:
        args = args.logch_find
        flag = input("ip or req -> ")
        if flag == "ip" or flag == "req":
            s = input("Input target you want to find : ")
            for i in range(0,len(args)):
                hlog.logch_find(args[i],s,flag)
        else:
            print("Input_Error!")
            exit()
    elif args.logchnum:
        args = args.logchnum
        access = 0
        time = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
        address = []
        c_list = {}
        c_all = 0
        for i in range(0,len(args)):
            ret,address = hlog.logchnum(args[i])
            #　時間帯別とアクセス総計
            for j in range(0,len(ret)):
                time[j] += ret[j]
            #print(args[i]," : %d" % sum(ret))
            access += sum(ret)
            #　各日ごとの送信元国の集計
            for i in range(0,len(address)):
                c = reader.city(address[i])
                try:
                    c = c.country.names["ja"]
                except:
                    c = c.registered_country.names["ja"]
                if c not in c_list.keys():
                    c_list[c] = 1
                else:
                    c_list[c] += 1
                c_all += 1
        c_list = sorted(c_list.items(),key=lambda x:x[1],reverse=True)
        print(c_all)
        for c in c_list:
            key, value = c
            print("{0}\t{1}\t{2}%".format(key,value,round(value/c_all,2)*100))
        """print("All: ",access)
        for i in range(0,len(time)):
            print("{0} : {1}".format(i+1,time[i]))
        """
    elif args.make:
        args = args.make
        for i in range(0,len(args)):
            hlog.make(args[i])
    elif args.integrate:
        args = args.integrate
        hlog.integrate(args)
    elif args.diff:
        args = args.diff
        hlog.diff(args[0],args[1])
    elif args.pcapch:
        args = args.pcapch
        pcap.pcapch(args[0])
    elif args.c_ip_all:
        args = args.c_ip_all
        hlog.c_ip_all(args)
    elif args.c_ip_particular:
        args = args.c_ip_particular
        hlog.c_ip_particular(args)
    elif args.c_pcapch_particular:
        args = args.c_pcapch_particular
        nation = input("Input Country:")
        p = re.compile("[亜-熙ァ-ヶ]+")
        if p.findall(nation):
            pcap.c_pcapch_particular(args,nation)
        else:
            print("No country\n")
            exit()
    elif args.c_pcapch_particular_plus:
        args = args.c_pcapch_particular_plus
        nation = input("Input Country:")
        p = re.compile("[亜-熙ァ-ヶ]+")
        if p.findall(nation):
            pcap.c_pcapch_particular_plus(args,nation)
        else:
            print("No country\n")
            exit()
