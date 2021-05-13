import time
from datetime import datetime
from geolite import mmdb
from tcpclass import layer

# GeoLite DataBase
reader = mmdb.reader

def pcapch(args):
    # global reader
    pc = layer.PcapClass
    new = "pcapch.txt"
    server = ["192.168.0.6","192.168.0.7","192.168.0.8"]

    # パケットの番号、pcapヘッダの長さ、パケットヘッダの長さ
    pck_count = 0
    pcap_hdr = 24
    pck_hdr = 16

    # ethernetデータ部の標準長、ipデータ部の標準長、tcpデータ部の標準長
    ethernet_data = 14
    ip_data = 20
    tcp_data = 20

    # SYNの数
    access = 0
    tls_access = 0

    # クライアントリスト、カントリーリスト, 時間別アクセス数リスト
    cl_list = {}
    country_list = {}
    access_time_list = {"0-1":0, "1-2":0, "2-3":0, "3-4":0, "4-5":0, "5-6":0, "6-7":0, "7-8":0,
                        "8-9":0, "9-10":0, "10-11":0, "11-12":0, "12-13":0, "13-14":0, "14-15":0, "15-16":0,
                        "16-17":0, "17-18":0, "18-19":0, "19-20":0, "20-21":0, "21-22":0, "22-23":0, "23-24":0}

    # クライアント一時保存
    cl_temp = ""

    # pcapファイル解析のスタート
    with open(new,'w') as n:
        with open(args,'rb') as f:
            # pcapファイルヘッダの解析
            buf = f.read(pcap_hdr)
            pc.pcap_header(buf)

            # パケット解析のスタート
            while True:
                pck_count += 1
                tls_rec = ""

                # debug
                if pck_count > 430:
                    print("{}: ".format(pck_count), end=" ")

                # -%- パケットヘッダ -%-
                buf = f.read(pck_hdr)
                # パケットがないなら終了
                if len(buf) == 0:
                    break
                # パケットヘッダ解析（pck_t:時間、pck_cl:パケットに記録されているパケット長）
                pck_t, pck_cl = pc.packet_header(buf)

                # -%- パケットデータ -%-
                # Ethernetデータ部解析
                buf = f.read(ethernet_data)
                pc.ethernet(buf)
                # パケット長からEthernetデータ分消す
                pck_cl -= ethernet_data

                # IPデータ部解析
                ip_opt = 0
                buf = f.read(ip_data)
                ip_l, ip_opt, ip_src, ip_dst = pc.ip(buf, ip_opt)
                # IPオプションがあるなら
                if ip_opt != 0:
                    buf = f.read(ip_opt)
                    pc.ip(buf, ip_opt)
                # パケット長からIPデータ分消す
                pck_cl -= ip_data + ip_opt

                # TCPデータ部解析
                tcp_opt = 0
                buf = f.read(tcp_data)
                tcp_l, tcp_opt, tcp_src, tcp_dst, flags = pc.tcp(buf, tcp_opt)
                # TCPオプションがあるなら
                if tcp_opt != 0:
                    buf = f.read(tcp_opt)
                    pc.tcp(buf, tcp_opt)
                # パケット長からTCPデータ分消す
                pck_cl -= tcp_data + tcp_opt


                # パケットの中身が空なら
                if pck_cl == 0:
                    pass
                # パケットの中身があるなら
                else:
                    buf = f.read(pck_cl)

                    # 残りサイズが6以下ならパディングである？
                    if len(buf) <= 6:
                        pass
                    # TLS\SSLの場合
                    elif tcp_src == 443 or tcp_dst == 443:
                        #tls_rec, tls_access, tls_res = pc.tls(buf)
                        tls_rec, tls_access = pc.tls(buf,ip_src)
                    # HTTPの場合
                    else:
                        try:
                            temp = hex(buf[:2]).replace("0x","")
                        except:
                            continue
                        http = ["4854","4745","504f","4845","4f50","434f","5055","4445"]
                        if temp in http:
                            tls_rec = "HTTP_Data"
                        elif "FIN" in flags:
                                tls_rec = "HTTP_Data"

                # SYN時の処理
                if "SYN" in flags and "ACK" not in flags:
                    # 連続アクセス判定
                    if ip_src == cl_temp:
                        # 連続アクセスなら数が増加
                        num += 1
                    else:
                        # リセット
                        num = 0

                    # 表示
                    pck_t = datetime.fromtimestamp(pck_t)
                    if num == 0:
                        n.write("\nNo.%d %s(%d)  [%s]\n" % (pck_count, ip_src, tcp_src, pck_t))
                    else:
                        n.write("\nNo.%d %s(%d)/%d  [%s]\n" % (pck_count, ip_src, tcp_src, num+1, pck_t))

                    if ip_src not in server:
                        # 時間別アクセス数カウント
                        hour = pck_t.hour
                        if hour == 0:
                            access_time_list["0-1"] += 1
                        elif hour == 1:
                            access_time_list["1-2"] += 1
                        elif hour == 2:
                            access_time_list["2-3"] += 1
                        elif hour == 3:
                            access_time_list["3-4"] += 1
                        elif hour == 4:
                            access_time_list["4-5"] += 1
                        elif hour == 5:
                            access_time_list["5-6"] += 1
                        elif hour == 6:
                            access_time_list["6-7"] += 1
                        elif hour == 7:
                            access_time_list["7-8"] += 1
                        elif hour == 8:
                            access_time_list["8-9"] += 1
                        elif hour == 9:
                            access_time_list["9-10"] += 1
                        elif hour == 10:
                            access_time_list["10-11"] += 1
                        elif hour == 11:
                            access_time_list["11-12"] += 1
                        elif hour == 12:
                            access_time_list["12-13"] += 1
                        elif hour == 13:
                            access_time_list["13-14"] += 1
                        elif hour == 14:
                            access_time_list["14-15"] += 1
                        elif hour == 15:
                            access_time_list["15-16"] += 1
                        elif hour == 16:
                            access_time_list["16-17"] += 1
                        elif hour == 17:
                            access_time_list["17-18"] += 1
                        elif hour == 18:
                            access_time_list["18-19"] += 1
                        elif hour == 19:
                            access_time_list["19-20"] += 1
                        elif hour == 20:
                            access_time_list["20-21"] += 1
                        elif hour == 21:
                            access_time_list["21-22"] += 1
                        elif hour == 22:
                            access_time_list["22-23"] += 1
                        elif hour == 23:
                            access_time_list["23-24"] += 1

                        # クライアントリストの作成
                        if not ip_src in cl_list.keys():
                            cl_list[ip_src] = [0,0,0]
                        # SYNの数を増やす
                        cl_list[ip_src][0] += 1

                    # 連続アクセス判定用のクライアント一時保存
                    cl_temp = ip_src

                    # ポート番号一時保存
                    syn_port = tcp_src

                # TCPフラグ表示（クライアントからのものには目印をつける）
                if ip_src not in server:
                    n.write("> %s" % flags)
                    # SYN以降でポートが変化していたらの処理
                    if syn_port != tcp_src:
                        n.write("  '%s(%d)'" % (ip_src,tcp_src))
                else:
                    n.write("  %s" % flags)

                # TLSデータ部の表示
                if tls_rec:
                    n.write("  ### %s###" % tls_rec)
                    # ClientHelloの数を増やす
                    if tls_access != 0:
                        cl_list[ip_src][1] += tls_access
                    #if tls_res != 0:
                    #    cl_list[ip_src][2] += tls_res
                n.write("\n")
            f.close()
        n.close()

    # ファイルのクローズ後
    print("")
    tls_access=0
    #tls_res=0
    for cl in cl_list.keys():
        access += cl_list[cl][0]
        tls_access += cl_list[cl][1]
        print("%s\t%d  %d" % (cl,cl_list[cl][0],cl_list[cl][1]))

        # 国のカウント
        c = reader.city(cl)
        try:
            c = c.country.names["ja"]
        except:
            c = c.registered_country.names["ja"]
        if c not in country_list.keys():
            country_list[c] = 1
        else:
            country_list[c] += 1

        # Client_Key_Exchangeの数を表示
        #tls_res += cl_list[cl][2]
        #print("%s\t%d  %d/%d" % (cl,cl_list[cl][0],cl_list[cl][1],cl_list[cl][2]))

    print()
    print("Access: %d\tTLS_Access: %d" % (access, tls_access))
    print("#"*20)
    for i in access_time_list.keys():
        print("%s:\t%d\n" % (i, access_time_list[i]),end="")
    print("#"*20)
    country_list = sorted(country_list.items())
    country_list = dict(country_list)
    for i in country_list.keys():
        print("%s: %d\n" % (i, country_list[i]),end="")
    #print("\nAccess: %d\tTLS_Access: %d --> %d" % (access, tls_access, tls_res))
    print("#"*20)
    print("make out in current directory as %s\n" % new)

def c_pcapch_particular(args,nation):
    # global reader
    pc = layer.PcapClass
    server = ["192.168.0.6","192.168.0.7","192.168.0.8"]

    # パケットの番号、pcapヘッダの長さ、パケットヘッダの長さ
    cpall = 0
    pcap_hdr = 24
    pck_hdr = 16

    # ethernetデータ部の標準長、ipデータ部の標準長、tcpデータ部の標準長
    ethernet_data = 14
    ip_data = 20
    tcp_data = 20

    # 時間別アクセス数リスト
    access_time_list = {"0-1":0, "1-2":0, "2-3":0, "3-4":0, "4-5":0, "5-6":0, "6-7":0, "7-8":0,
                        "8-9":0, "9-10":0, "10-11":0, "11-12":0, "12-13":0, "13-14":0, "14-15":0, "15-16":0,
                        "16-17":0, "17-18":0, "18-19":0, "19-20":0, "20-21":0, "21-22":0, "22-23":0, "23-24":0}

    for file in args:
        pck_count = 0
        # 特定国の数と１ファイルごとのクライアントリスト
        cpnum=0
        cl_list = []

        # pcapファイル解析のスタート
        with open(file,'rb') as f:
            # pcapファイルヘッダの解析
            buf = f.read(pcap_hdr)
            pc.pcap_header(buf)

            # パケット解析のスタート
            while True:
                pck_count += 1
                tls_rec = ""

                # -%- パケットヘッダ -%-
                buf = f.read(pck_hdr)
                # パケットがないなら終了
                if len(buf) == 0:
                    break
                # パケットヘッダ解析（pck_t:時間、pck_cl:パケットに記録されているパケット長）
                pck_t, pck_cl = pc.packet_header(buf)

                # -%- パケットデータ -%-
                # Ethernetデータ部解析
                buf = f.read(ethernet_data)
                pc.ethernet(buf)
                # パケット長からEthernetデータ分消す
                pck_cl -= ethernet_data

                # IPデータ部解析
                ip_opt = 0
                buf = f.read(ip_data)
                ip_l, ip_opt, ip_src, ip_dst = pc.ip(buf, ip_opt)
                # IPオプションがあるなら
                if ip_opt != 0:
                    buf = f.read(ip_opt)
                    pc.ip(buf, ip_opt)
                # パケット長からIPデータ分消す
                pck_cl -= ip_data + ip_opt

                # TCPデータ部解析
                tcp_opt = 0
                buf = f.read(tcp_data)
                tcp_l, tcp_opt, tcp_src, tcp_dst, flags = pc.tcp(buf, tcp_opt)
                # TCPオプションがあるなら
                if tcp_opt != 0:
                    buf = f.read(tcp_opt)
                    pc.tcp(buf, tcp_opt)
                # パケット長からTCPデータ分消す
                pck_cl -= tcp_data + tcp_opt


                # パケットの中身が空なら
                if pck_cl == 0:
                    pass
                # パケットの中身があるなら
                else:
                    buf = f.read(pck_cl)

                    if len(buf) <= 6:
                        pass
                    # TLS\SSLとHTTP
                    elif tcp_src == 443 or tcp_dst == 443:
                        #tls_rec, tls_access, tls_res = pc.tls(buf)
                        tls_rec, tls_access = pc.tls(buf,ip_src)
                    else:
                        try:
                            temp += hex(buf[:2]).replace("0x","")
                        except:
                            continue

                        http = ["4854","4745","504f","4845","4f50","434f","5055","4445"]

                        if temp in http:
                            tls_rec = "HTTP_Data"
                        elif "FIN" in flags:
                            tls_rec = "HTTP_Data"

                # SYN時の処理
                if "SYN" in flags and "ACK" not in flags:

                    if ip_src not in server:
                        c = reader.city(ip_src)
                        try:
                            c = c.country.names["ja"]
                        except:
                            c = c.registered_country.names["ja"]

                        if c == nation:
                            #print(ip_src)
                            if ip_src not in cl_list:
                                cl_list.append(ip_src)

                            # 時間取得
                            pck_t = datetime.fromtimestamp(pck_t)

                            # 時間別アクセス数カウント
                            hour = pck_t.hour
                            if hour == 0:
                                access_time_list["0-1"] += 1
                            elif hour == 1:
                                access_time_list["1-2"] += 1
                            elif hour == 2:
                                access_time_list["2-3"] += 1
                            elif hour == 3:
                                access_time_list["3-4"] += 1
                            elif hour == 4:
                                access_time_list["4-5"] += 1
                            elif hour == 5:
                                access_time_list["5-6"] += 1
                            elif hour == 6:
                                access_time_list["6-7"] += 1
                            elif hour == 7:
                                access_time_list["7-8"] += 1
                            elif hour == 8:
                                access_time_list["8-9"] += 1
                            elif hour == 9:
                                access_time_list["9-10"] += 1
                            elif hour == 10:
                                access_time_list["10-11"] += 1
                            elif hour == 11:
                                access_time_list["11-12"] += 1
                            elif hour == 12:
                                access_time_list["12-13"] += 1
                            elif hour == 13:
                                access_time_list["13-14"] += 1
                            elif hour == 14:
                                access_time_list["14-15"] += 1
                            elif hour == 15:
                                access_time_list["15-16"] += 1
                            elif hour == 16:
                                access_time_list["16-17"] += 1
                            elif hour == 17:
                                access_time_list["17-18"] += 1
                            elif hour == 18:
                                access_time_list["18-19"] += 1
                            elif hour == 19:
                                access_time_list["19-20"] += 1
                            elif hour == 20:
                                access_time_list["20-21"] += 1
                            elif hour == 21:
                                access_time_list["21-22"] += 1
                            elif hour == 22:
                                access_time_list["22-23"] += 1
                            elif hour == 23:
                                access_time_list["23-24"] += 1

                            cpnum += 1

            print(file," : ",cpnum)
            cpall += cpnum
            f.close()

    # ファイルのクローズ後
    print("#"*20)
    for i in access_time_list.keys():
        print("%s:\t%d\n" % (i, access_time_list[i]),end="")
    print("#"*20)
    print(cpall)

def c_pcapch_particular_plus(args,nation):
    # global reader
    pc = layer.PcapClass
    server = ["192.168.0.6","192.168.0.7","192.168.0.8"]

    # パケットの番号、pcapヘッダの長さ、パケットヘッダの長さ
    cpall = 0
    pcap_hdr = 24
    pck_hdr = 16

    # ethernetデータ部の標準長、ipデータ部の標準長、tcpデータ部の標準長
    ethernet_data = 14
    ip_data = 20
    tcp_data = 20

    # 特定国の数, 時間別アクセス数リスト
    access_time_list = {"0-1":0, "1-2":0, "2-3":0, "3-4":0, "4-5":0, "5-6":0, "6-7":0, "7-8":0,
                        "8-9":0, "9-10":0, "10-11":0, "11-12":0, "12-13":0, "13-14":0, "14-15":0, "15-16":0,
                        "16-17":0, "17-18":0, "18-19":0, "19-20":0, "20-21":0, "21-22":0, "22-23":0, "23-24":0}
    
    # 特定国のIPリスト
    p_list = []

    for file in args:
        cpnum=0
        pck_count = 0
        # pcapファイル解析のスタート
        with open(file,'rb') as f:
            # pcapファイルヘッダの解析
            buf = f.read(pcap_hdr)
            pc.pcap_header(buf)

            # パケット解析のスタート
            while True:
                pck_count += 1
                tls_rec = ""

                # -%- パケットヘッダ -%-
                buf = f.read(pck_hdr)
                # パケットがないなら終了
                if len(buf) == 0:
                    break
                # パケットヘッダ解析（pck_t:時間、pck_cl:パケットに記録されているパケット長）
                pck_t, pck_cl = pc.packet_header(buf)

                # -%- パケットデータ -%-
                # Ethernetデータ部解析
                buf = f.read(ethernet_data)
                pc.ethernet(buf)
                # パケット長からEthernetデータ分消す
                pck_cl -= ethernet_data

                # IPデータ部解析
                ip_opt = 0
                buf = f.read(ip_data)
                ip_l, ip_opt, ip_src, ip_dst = pc.ip(buf, ip_opt)
                # IPオプションがあるなら
                if ip_opt != 0:
                    buf = f.read(ip_opt)
                    pc.ip(buf, ip_opt)
                # パケット長からIPデータ分消す
                pck_cl -= ip_data + ip_opt

                # TCPデータ部解析
                tcp_opt = 0
                buf = f.read(tcp_data)
                tcp_l, tcp_opt, tcp_src, tcp_dst, flags = pc.tcp(buf, tcp_opt)
                # TCPオプションがあるなら
                if tcp_opt != 0:
                    buf = f.read(tcp_opt)
                    pc.tcp(buf, tcp_opt)
                # パケット長からTCPデータ分消す
                pck_cl -= tcp_data + tcp_opt


                # パケットの中身が空なら
                if pck_cl == 0:
                    pass
                # パケットの中身があるなら
                else:
                    buf = f.read(pck_cl)

                    if len(buf) <= 6:
                        pass
                    # TLS\SSLとHTTP
                    else:
                        if tcp_src == 443 or tcp_dst == 443:
                            #tls_rec, tls_access, tls_res = pc.tls(buf)
                            tls_rec, tls_access = pc.tls(buf,ip_src)
                        else:
                            try:
                                temp += hex(buf[1]).replace("0x","")
                            except:
                                continue
                            http = ["4854","4745","504f","4845","4f50","434f","5055","4445"]
                            if temp in http:
                                tls_rec = "HTTP_Data"
                            elif "FIN" in flags:
                                    tls_rec = "HTTP_Data"

                # SYN時の処理
                if "SYN" in flags and "ACK" not in flags:

                    if ip_src not in server:
                        c = reader.city(ip_src)
                        try:
                            c = c.country.names["ja"]
                        except:
                            c = c.registered_country.names["ja"]

                        if c == nation:
                            if ip_src not in p_list:
                                p_list.append(ip_src)
                            else:
                                pass

                            """# 時間取得
                            pck_t = datetime.fromtimestamp(pck_t)

                            # 時間別アクセス数カウント
                            hour = pck_t.hour
                            if hour == 0:
                                access_time_list["0-1"] += 1
                            elif hour == 1:
                                access_time_list["1-2"] += 1
                            elif hour == 2:
                                access_time_list["2-3"] += 1
                            elif hour == 3:
                                access_time_list["3-4"] += 1
                            elif hour == 4:
                                access_time_list["4-5"] += 1
                            elif hour == 5:
                                access_time_list["5-6"] += 1
                            elif hour == 6:
                                access_time_list["6-7"] += 1
                            elif hour == 7:
                                access_time_list["7-8"] += 1
                            elif hour == 8:
                                access_time_list["8-9"] += 1
                            elif hour == 9:
                                access_time_list["9-10"] += 1
                            elif hour == 10:
                                access_time_list["10-11"] += 1
                            elif hour == 11:
                                access_time_list["11-12"] += 1
                            elif hour == 12:
                                access_time_list["12-13"] += 1
                            elif hour == 13:
                                access_time_list["13-14"] += 1
                            elif hour == 14:
                                access_time_list["14-15"] += 1
                            elif hour == 15:
                                access_time_list["15-16"] += 1
                            elif hour == 16:
                                access_time_list["16-17"] += 1
                            elif hour == 17:
                                access_time_list["17-18"] += 1
                            elif hour == 18:
                                access_time_list["18-19"] += 1
                            elif hour == 19:
                                access_time_list["19-20"] += 1
                            elif hour == 20:
                                access_time_list["20-21"] += 1
                            elif hour == 21:
                                access_time_list["21-22"] += 1
                            elif hour == 22:
                                access_time_list["22-23"] += 1
                            elif hour == 23:
                                access_time_list["23-24"] += 1"""

                            cpnum += 1

            #print(file," : ",cpnum)
            #cpall += cpnum
            f.close()

    # ファイルのクローズ後
    i = 0
    for ip in p_list:
        i+=1
        print("\"%s\" " % ip,end="")
        if i % 200 == 0:
            print("")
    """print("#"*20)
    for i in access_time_list.keys():
        print("%s:\t%d\n" % (i, access_time_list[i]),end="")
    print("#"*20)
    print(cpall)"""

