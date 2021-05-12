import base64
import re
import time
from datetime import datetime
from geolite import mmdb
from tcpclass import layer

# GeoLite DataBase
reader = mmdb.reader

def logch(path):
    #　ゲットリクエストリスト
    request = {}
    print(path)

    #　メソッド一覧
    get_c = 0
    post_c = 0
    head_c = 0
    options_c = 0
    put_c = 0
    delete_c = 0
    other_c = 0

    #　base64デコード
    decode = lambda str: base64.b64decode(str).decode()

    #　アクセスログのデコード
    with open(path) as f:
        i = 0

        for log in f:
            #　HTTPリクエストの分割
            #　注：ハニポのログのseparateを'\t'にする必要がある
            #　r''はエスケープシーケンスを無効化
            l = log.split(r'\t')

            while True:
              if l[3].endswith('"'):
                  break
              else:
                  l[3] = l[3]+r"\t"+l[4]
                  l[4] = l[5]
                  l[5] = l[6]
                  l[6] = l[7]

            """
            #スプリットされたアクセスログの例
            ['[2020-09-17 14:08:35+0900]', '193.118.53.194', '192.168.0.7:443', '"GET / HTTP/1.1"', '404', 'False', 'R0VUIC8gSFRUUC8xLjEKSG9zdDogMTMzLjE0LjE0LjI0NwpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNjAuMC4zMTEyLjExMyBTYWZhcmkvNTM3LjM2IApBY2NlcHQ6ICovKgpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAKCg==\n']
            """

            #　表示対象の作成
            head = l[0]+" "+l[1]+" "+l[2]+" "+l[3]+" "+l[4]+" "+l[5]
            body = decode(l[6])
            if l[3] in request.keys():
              request[l[3]] += 1
            else:
              request[l[3]] = 1


            #　メソッドの取得
            method = l[3]

            #　メソッドごとのカウント
            if "GET" in method:
              get_c+=1
            elif "POST" in method:
              post_c+=1
            elif "HEAD" in method:
              head_c+=1
            elif "OPTIONS" in method:
              options_c+=1
            elif "PUT" in method:
              put_c+=1
            elif "DELETE" in method:
              delete_c+=1
            else:
              other_c+=1

            #　表示
            print("/",i+1,"/")
            print(head)
            print(body,"\n")

            i+=1

        #　ログ合計とメソッドごとの合計表示
        print("------------------------------\nALL LOG = %d\nGET = %d, POST = %d, HEAD = %d\nOPTIONS = %d, PUT = %d, DELETE = %d\nOTHER = %d\n" % (i,get_c,post_c,head_c,options_c,put_c,delete_c,other_c))

def logch_limited(path):
    #　ゲットリクエストリスト
    print(path)

    #　base64デコード
    decode = lambda str: base64.b64decode(str).decode()

    #　アクセスログのデコード
    with open(path) as f:
        i = 0

        for log in f:
            #　HTTPリクエストの分割
            #　注：ハニポのログのseparateを'\t'にする必要がある
            #　r''はエスケープシーケンスを無効化
            l = log.split(r'\t')

            while True:
              if l[3].endswith('"'):
                  break
              else:
                  l[3] = l[3]+r"\t"+l[4]
                  l[4] = l[5]
                  l[5] = l[6]
                  l[6] = l[7]

            """
            #スプリットされたアクセスログの例
            ['[2020-09-17 14:08:35+0900]', '193.118.53.194', '192.168.0.7:443', '"GET / HTTP/1.1"', '404', 'False', 'R0VUIC8gSFRUUC8xLjEKSG9zdDogMTMzLjE0LjE0LjI0NwpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNjAuMC4zMTEyLjExMyBTYWZhcmkvNTM3LjM2IApBY2NlcHQ6ICovKgpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAKCg==\n']
            """

            #　表示
            print("\t{0:<0}\t: {1}".format(l[1],l[3][1:-9]))

        print("")

def logch_find(path,s,flag):
    #　アクセスログのデコード
    with open(path) as f:
        i = 0

        for log in f:
            #　HTTPリクエストの分割
            #　注：ハニポのログのseparateを'\t'にする必要がある
            #　r''はエスケープシーケンスを無効化
            l = log.split(r'\t')

            while True:
              if l[3].endswith('"'):
                  break
              else:
                  l[3] = l[3]+r"\t"+l[4]
                  l[4] = l[5]
                  l[5] = l[6]
                  l[6] = l[7]

            """
            #スプリットされたアクセスログの例
            ['[2020-09-17 14:08:35+0900]', '193.118.53.194', '192.168.0.7:443', '"GET / HTTP/1.1"', '404', 'False', 'R0VUIC8gSFRUUC8xLjEKSG9zdDogMTMzLjE0LjE0LjI0NwpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNjAuMC4zMTEyLjExMyBTYWZhcmkvNTM3LjM2IApBY2NlcHQ6ICovKgpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAKCg==\n']
            """

            #　発見、表示
            if flag == "req":
                if s in l[3]:
                    print(path)
                    print("\tfound! -> {0} : {1}".format(l[1],l[3][1:-9]))
            if flag == "ip":
                if s == l[1]:
                    print(path)
                    print("\tfound! -> {0} : {1}".format(l[1],l[3][1:-9]))

def logchnum(path):
    #　時間
    time = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

    #　IPアドレス
    address = []

    #　base64デコード
    decode = lambda str: base64.b64decode(str).decode()

    #　アクセスログのデコード
    with open(path) as f:
        i = 0

        for log in f:
            #　HTTPリクエストの分割
            #　注：ハニポのログのseparateを'\t'にする必要がある
            #　r''はエスケープシーケンスを無効化
            l = log.split(r'\t')

            while True:
              if l[3].endswith('"'):
                  break
              else:
                  l[3] = l[3]+r"\t"+l[4]
                  l[4] = l[5]
                  l[5] = l[6]
                  l[6] = l[7]

            """
            #スプリットされたアクセスログの例
            ['[2020-09-17 14:08:35+0900]', '193.118.53.194', '192.168.0.7:443', '"GET / HTTP/1.1"', '404', 'False', 'R0VUIC8gSFRUUC8xLjEKSG9zdDogMTMzLjE0LjE0LjI0NwpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0KSBBcHBsZVdlYktpdC81MzcuMzYgKEtIVE1MLCBsaWtlIEdlY2tvKSBDaHJvbWUvNjAuMC4zMTEyLjExMyBTYWZhcmkvNTM3LjM2IApBY2NlcHQ6ICovKgpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAKCg==\n']
            """
            #　時間取得
            dt = datetime.strptime(l[0],"[%Y-%m-%d %H:%M:%S%z]")
            dt = int(dt.hour)
            time[dt] += 1

            #　IP取得
            ip = l[1]
            #if ip not in address:
            address.append(ip)

            #　表示対象の作成
            #head = l[0]+" "+l[1]+" "+l[2]+" "+l[3]+" "+l[4]+" "+l[5]
            #body = decode(l[6])

            i+=1

        return time, address

def c_ip_all(args):
    total = "cia.txt"

    get={}
    get1={}
    get2={}
    get3={}
    post={}
    other={}

    for p in args:
        with open(p,'r') as f:
            for log in f:
                l = log.split(r'\t')
                if len(l) > 7:
                    l[3] = l[3]+r"\t"+l[4]
                request = l[3]
                ip = l[1]

                if 'GET' in request:
                    if len(request) <= 20:
                        if request in get.keys():
                            if ip not in get[request]:
                                get[request].append(ip)
                        else:
                            get[request] = []
                            get[request].append(ip)
                    elif len(request) <= 45:
                        if request in get1.keys():
                            if ip not in get1[request]:
                                get1[request].append(ip)
                        else:
                            get1[request] = []
                            get1[request].append(ip)
                    elif len(request) <= 70:
                        if request in get2.keys():
                            if ip not in get2[request]:
                                get2[request].append(ip)
                        else:
                            get2[request] = []
                            get2[request].append(ip)
                    else:
                        if request in get3.keys():
                            if ip not in get3[request]:
                                get3[request].append(ip)
                        else:
                            get3[request] = []
                            get3[request].append(ip)
                elif 'POST' in request:
                    if request in post.keys():
                        if ip not in post[request]:
                            post[request].append(ip)
                    else:
                        post[request] = []
                        post[request].append(ip)
                else:
                    if request in other.keys():
                        if ip not in other[request]:
                            other[request].append(ip)
                    else:
                        other[request] = []
                        other[request].append(ip)
            f.close()

    for key, value in sorted(get.items()):
        #total.write(f'{key}\n')
        print(key)
        for v in value:
            vc = reader.city(v)
            try:
                vc = vc.country.names["ja"]
            except:
                vc = vc.registered_country.names["ja"]
            #total.write(f'\t{v}\t{vc}\n')
            print("\t%s\t%s\n" % (v,vc),end="")
    for key, value in sorted(get1.items()):
        #total.write(f'{key}\n')
        print(key)
        for v in value:
            vc = reader.city(v)
            try:
                vc = vc.country.names["ja"]
            except:
                vc = vc.registered_country.names["ja"]
            #total.write(f'\t{v}\t{vc}\n')
            print("\t%s\t%s\n" % (v,vc),end="")
    for key, value in sorted(get2.items()):
        #total.write(f'{key}\n')
        print(key)
        for v in value:
            vc = reader.city(v)
            try:
                vc = vc.country.names["ja"]
            except:
                vc = vc.registered_country.names["ja"]
            #total.write(f'\t{v}\t{vc}\n')
            print("\t%s\t%s\n" % (v,vc),end="")
    for key, value in sorted(get3.items()):
        #total.write(f'{key}\n')
        print(key)
        for v in value:
            vc = reader.city(v)
            try:
                vc = vc.country.names["ja"]
            except:
                vc = vc.registered_country.names["ja"]
            #total.write(f'\t{v}\t{vc}\n')
            print("\t%s\t%s\n" % (v,vc),end="")
    for key, value in sorted(post.items()):
        #total.write(f'{key}\n')
        print(key)
        for v in value:
            vc = reader.city(v)
            try:
                vc = vc.country.names["ja"]
            except:
                vc = vc.registered_country.names["ja"]
            #total.write(f'\t{v}\t{vc}\n')
            print("\t%s\t%s\n" % (v,vc),end="")
    for key, value in sorted(other.items()):
        #total.write(f'{key}\n')
        print(key)
        for v in value:
            vc = reader.city(v)
            try:
                vc = vc.country.names["ja"]
            except:
                vc = vc.registered_country.names["ja"]
            #total.write(f'\t{v}\t{vc}\n')
            print("\t%s\t%s\n" % (v,vc),end="")

def c_ip_particular(args):
    print("input country: ",end="")
    raw = input()
    total = "cip_" + raw + ".txt"
    print("make out in current directory as %s\n" % total)

    # カタカナと漢字が入っているかどうか
    if re.findall("[ァ-ン]", raw) == 0 and re.findall("[一-龥]", raw) == 0:
        print("国を入力してください！")
        exit()

    get={}
    get1={}
    get2={}
    get3={}
    post={}
    other={}

    for p in args:
        with open(p,'r') as f:
            i = 0
            for log in f:
                i = i+1
                l = log.split(r'\t')
                if len(l) > 7:
                    l[3] = l[3]+r"\t"+l[4]
                request = l[3]
                ip = l[1]

                if 'GET' in request:
                    if len(request) <= 20:
                        if request in get.keys():
                            get[request].append(ip)
                        else:
                            get[request] = []
                            get[request].append(ip)
                    elif len(request) <= 45:
                        if request in get1.keys():
                            get1[request].append(ip)
                        else:
                            get1[request] = []
                            get1[request].append(ip)
                    elif len(request) <= 70:
                        if request in get2.keys():
                            get2[request].append(ip)
                        else:
                            get2[request] = []
                            get2[request].append(ip)
                    else:
                        if request in get3.keys():
                            get3[request].append(ip)
                        else:
                            get3[request] = []
                            get3[request].append(ip)
                elif 'POST' in request:
                    if request in post.keys():
                        post[request].append(ip)
                    else:
                        post[request] = []
                        post[request].append(ip)
                else:
                    if request in other.keys():
                        other[request].append(ip)
                    else:
                        other[request] = []
                        other[request].append(ip)
            f.close()

    with open(total, 'w') as total:
        for key, value in sorted(get.items()):
            target_list = []
            for v in value:
                vc = reader.city(v)
                try:
                    vc = vc.country.names["ja"]
                except:
                    vc = vc.registered_country.names["ja"]
                if vc == raw:
                    target_list.append(v)

            if target_list:
                total.write(f'{key}\n')
                print(key," : ",len(target_list))
                time.sleep(0.1)
                for v in target_list:
                    total.write(f'\t{v}\t{raw}\n')
        for key, value in sorted(get1.items()):
            target_list = []
            for v in value:
                vc = reader.city(v)
                try:
                    vc = vc.country.names["ja"]
                except:
                    vc = vc.registered_country.names["ja"]
                if vc == raw:
                    target_list.append(v)

            if target_list:
                total.write(f'{key}\n')
                print(key," : ",len(target_list))
                time.sleep(0.1)
                for v in target_list:
                    total.write(f'\t{v}\t{raw}\n')
        for key, value in sorted(get2.items()):
            target_list = []
            for v in value:
                vc = reader.city(v)
                try:
                    vc = vc.country.names["ja"]
                except:
                    vc = vc.registered_country.names["ja"]
                if vc == raw:
                    target_list.append(v)

            if target_list:
                total.write(f'{key}\n')
                print(key," : ",len(target_list))
                time.sleep(0.1)
                for v in target_list:
                    total.write(f'\t{v}\t{raw}\n')
        for key, value in sorted(get3.items()):
            target_list = []
            for v in value:
                vc = reader.city(v)
                try:
                    vc = vc.country.names["ja"]
                except:
                    vc = vc.registered_country.names["ja"]
                if vc == raw:
                    target_list.append(v)

            if target_list:
                total.write(f'{key}\n')
                print(key," : ",len(target_list))
                time.sleep(0.1)
                for v in target_list:
                    total.write(f'\t{v}\t{raw}\n')
        for key, value in sorted(post.items()):
            target_list = []
            for v in value:
                vc = reader.city(v)
                try:
                    vc = vc.country.names["ja"]
                except:
                    vc = vc.registered_country.names["ja"]
                if vc == raw:
                    target_list.append(v)

            if target_list:
                total.write(f'{key}\n')
                print(key," : ",len(target_list))
                time.sleep(0.1)
                for v in target_list:
                    total.write(f'\t{v}\t{raw}\n')
        for key, value in sorted(other.items()):
            target_list = []
            for v in value:
                vc = reader.city(v)
                try:
                    vc = vc.country.names["ja"]
                except:
                    vc = vc.registered_country.names["ja"]
                if vc == raw:
                    target_list.append(v)

            if target_list:
                total.write(f'{key}\n')
                print(key," : ",len(target_list))
                time.sleep(0.1)
                for v in target_list:
                    total.write(f'\t{v}\t{raw}\n')
        total.close()

def make(path):
    if 'http' in path:
        if '/' in path:
            fdr = path.rfind('/')
            file = path[fdr+1:]
        file += "_request"
    else:
        printf("FILE NAME ERROR!")
        exit(1)

    print("make out in current directory as %s\n" % file)

    #　リスト {GET 20,45,70,71~ / POST / OTHER}
    get={}
    get1={}
    get2={}
    get3={}
    post={}
    other={}

    #　ログファイルの読み込み
    with open(path,'r') as f:
        for log in f:
            l = log.split(r'\t')
            if len(l) > 7:
                l[3] = l[3]+r"\t"+l[4]
            request = l[3]

            if 'GET' in request:
                if len(request) <= 20:
                    if request in get.keys():
                        get[request] += 1
                    else:
                        get[request] = 1
                elif len(request) <= 45:
                    if request in get1.keys():
                        get1[request] += 1
                    else:
                        get1[request] = 1
                elif len(request) <= 70:
                    if request in get2.keys():
                        get2[request] += 1
                    else:
                        get2[request] = 1
                else:
                    if request in get3.keys():
                        get3[request] += 1
                    else:
                        get3[request] = 1
            elif 'POST' in request:
                if request in post.keys():
                    post[request] += 1
                else:
                    post[request] = 1
            else:
                if request in other.keys():
                    other[request] += 1
                else:
                    other[request] = 1
        f.close()

    #　リクエストヘッダテキストの作成
    with open(file, 'w') as f:
        for key, value in sorted(get.items()):
            f.write(f'{key}%%%%{value}\n')
        for key, value in sorted(get1.items()):
            f.write(f'{key}%%%%{value}\n')
        for key, value in sorted(get2.items()):
            f.write(f'{key}%%%%{value}\n')
        for key, value in sorted(get3.items()):
            f.write(f'{key}%%%%{value}\n')
        for key, value in sorted(post.items()):
            f.write(f'{key}%%%%{value}\n')
        for key, value in sorted(other.items()):
            f.write(f'{key}%%%%{value}\n')
        f.close()

def integrate(path):
    if 'https' in path[0]:
        for p in path:
            if 'https' not in p:
                print("args error!!\n")
                exit(1)
            else:
                pass
        file = "https_integrate_request"
    else:
        for p in path:
            if 'https' in p:
                print("args error!!\n")
                exit(1)
            else:
                pass
        file = "http_integrate_request"

    print("make out in current directory as %s" % file)

    #　リスト {GET 20,45,70,71~ / POST / OTHER}
    get={}
    get1={}
    get2={}
    get3={}
    post={}
    other={}

    for p in path:
        with open(p,'r') as f:
            for s in f:
                request, value = s.split("%%%%")
                value = int(value)

                if 'GET' in request[:7]:
                    if len(request) <= 20:
                        if request in get.keys():
                            get[request] += value
                        else:
                            get[request] = value
                    elif len(request) <= 45:
                        if request in get1.keys():
                            get1[request] += value
                        else:
                            get1[request] = value
                    elif len(request) <= 70:
                        if request in get2.keys():
                            get2[request] += value
                        else:
                            get2[request] = value
                    else:
                        if request in get3.keys():
                            get3[request] += value
                        else:
                            get3[request] = value
                elif 'POST' in request[:7]:
                    if request in post.keys():
                        post[request] += value
                    else:
                        post[request] = value
                else:
                    if request in other.keys():
                        other[request] += value
                    else:
                        other[request] = value
            f.close()

    with open(file, 'w') as total:
        #　HTTPリクエストの統計を更新
        for key, value in sorted(get.items()):
            total.write(f'{key}%%%%{value}\n')
        for key, value in sorted(get1.items()):
            total.write(f'{key}%%%%{value}\n')
        for key, value in sorted(get2.items()):
            total.write(f'{key}%%%%{value}\n')
        for key, value in sorted(get3.items()):
            total.write(f'{key}%%%%{value}\n')
        for key, value in sorted(post.items()):
            total.write(f'{key}%%%%{value}\n')
        for key, value in sorted(other.items()):
            total.write(f'{key}%%%%{value}\n')
        total.close()

def diff(a, b):
    diff = "diff"
    http_req1 = a
    http_req2 = b

    print("make out in current directory as %s\n%s - %s = %s\n" % (diff,b,a,diff))

    #　リスト {GET 20,45,70,71~ / POST / OTHER}
    get=[]
    get1=[]
    get2=[]
    get3=[]
    post=[]
    other=[]

    #　HTTPSのリクエストヘッダテキストの読み込み(total-s.txt)
    try:
        with open(http_req1, 'r') as http:
            for s in http:
                key, value = s.split("%%%%")

                #　ヘッダのメソッドと長さで仕分け
                if 'GET' in key:
                    if len(key) <= 20:
                        get.append(key)
                    elif len(key) <= 45:
                        get1.append(key)
                    elif len(key) <= 70:
                        get2.append(key)
                    else:
                        get3.append(key)
                elif 'POST' in key:
                    post.append(key)
                else:
                    other.append(key)
            http.close()

        #　書き込み用ファイルを開く
        with open(diff,'w') as f:
            #　HTTPSのリクエストヘッダテキストの読み込み(total-s.txt)
            with open(http_req2,'r') as https:
                for s in https:
                    key, value = s.split("%%%%")

                    if 'GET' in key:
                        if len(key) <= 20:
                            if key not in get:
                                f.write(f'{key}\n')
                        elif len(key) <= 45:
                            if key not in get1:
                                f.write(f'{key}\n')
                        elif len(key) <= 70:
                            if key not in get2:
                                f.write(f'{key}\n')
                        else:
                            if key not in get3:
                                f.write(f'{key}\n')
                    elif 'POST' in key:
                        if key not in post:
                            f.write(f'{key}\n')
                    else:
                        if key not in other:
                            f.write(f'{key}\n')
                https.close()
            f.close()
    except:
        print("need total.txt and total-s.txt\n")
        exit()
