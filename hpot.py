from datetime import datetime
import os
import sys
import binascii
import argparse
import base64
import re
import geoip2.database
import time
#import datetime

reader = geoip2.database.Reader('GeoLite2-City_20201027/GeoLite2-City.mmdb')
save = None

class PcapClass:
    def pcap_header(buf):
        lead = ""
        #major_ver = ""
        #minor_ver = ""
        #timezone = ""
        #sigfigs = ""
        #snaplen = ""
        #linktype = ""

        #　ファイルの先頭を取得
        #　16進数のstr型
        lead = hex(buf[0]) + hex(buf[1]) + hex(buf[2]) + hex(buf[3])
        #　16進数の「0x」を文字列から排除
        lead = lead.replace("0x","")
        #　Little Endien --> OK / Big Endien --> No
        if lead == "d4c3b2a1":
            pass
        else:
            print("Big Endien?\n%s" % lead,end="")
            exit()

        """#　ファイルフォーマットのバージョン情報を取得
        #　major versionを取得
        for i in range(6,4,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                major_ver += "0"+temp
            else:
                major_ver+= temp
        #　minor versionを取得
        for i in range(8,6,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                minor_ver += "0"+temp
            else:
                minor_ver += temp
        #　タイムゾーン情報を取得
        for i in range(12,8,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                timezone += "0"+temp
            else:
                timezone += temp
        #　タイムスタンプの精度を取得
        for i in range(16,12,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                sigfigs += "0"+temp
            else:
                sigfigs += temp
        #　キャプチャできるパケット長の最大長
        for i in range(20,16,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                snaplen += "0"+temp
            else:
                snaplen += temp
        #　データリンク層のヘッダタイプ
        for i in range(24,20,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                linktype += "0"+temp
            else:
                linktype += temp"""

    def packet_header(buf):
        pck_t = ""
        #pck_micro = ""
        pck_cl = ""
        #pck_l = ""

        #　-%- パケットの受信時刻を取得 -%-
        for i in range(4,0,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                pck_t += "0"+temp
            else:
                pck_t += temp
        #　16進数文字列を10進数のint型へ変換
        pck_t = int(pck_t, 16)

        """#　-%- パケットの受信時刻のマイクロ秒を取得 -%-
        for i in range(8,4,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                pck_micro += "0"+temp
            else:
                pck_micro += temp
        #　16進数文字列を10進数のint型へ変換
        pck_micro = int(pck_micro, 16)"""

        #　-%- ファイルに記録されているパケット長を取得 -%-
        for i in range(12,8,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                pck_cl += "0"+temp
            else:
                pck_cl += temp
        #　16進数文字列を10進数のint型へ変換
        pck_cl = int(pck_cl,16)

        """#　-%- 実際のパケット長を取得 -%-
        for i in range(16,12,-1):
            #　16進数のstr型
            temp = hex(buf[i-1])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                pck_l += "0"+temp
            else:
                pck_l += temp
        #　16進数文字列を10進数のint型へ変換
        pck_l = int(pck_l,16)"""

        return (pck_t, pck_cl)

    def ethernet(buf):
        #　Ethernet処理
        #dst_mac = ""
        #src_mac = ""
        #ethernet_type = ""

        """#　送信先MACアドレスを取得
        for i in range(0,6):
            #　16進数のstr型
            temp = hex(buf[i])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                dst_mac += "0"+temp
            else:
                dst_mac += temp

        #　送信元MACアドレスを取得
        for i in range(6,12):
            #　16進数のstr型
            temp = hex(buf[i])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                src_mac += "0"+temp
            else:
                src_mac += temp

        #　タイプを取得
        for i in range(12,14):
            #　16進数のstr型
            temp = hex(buf[i])
            #　16進数の「0x」を文字列から排除
            temp = temp.replace("0x","")
            #　文字列の連結
            if len(temp) == 1:
                ethernet_type += "0"+temp
            else:
                ethernet_type += temp"""

        pass

    def ip(buf, p):
        # IP処理
        ip_opt = p

        if ip_opt == 0:
            #ip_ver = ""
            ip_l = ""
            #ip_dsf = ""
            #ip_tl = ""
            #ip_idt = ""
            #ip_flags = ""
            #ip_ttl = ""
            #ip_proto = ""
            #ip_chksum = ""
            ip_src = ""
            ip_dst = ""

            #　IPバージョンとIPデータ部の長さ
            temp = hex(buf[0])
            temp = temp.replace("0x","")
            #ip_ver = int(temp[0],16)
            ip_l = int(temp[1],16) * 4

            #　IPオプションズの有無
            if ip_l != 20:
                ip_opt = ip_l - 20

            """#　DiffServ
            temp = hex(buf[1])
            temp = temp.replace("0x","")
            if len(temp) == 1:
                ip_dsf += "0"+temp

            #　Total Length
            for i in range(2,4):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    ip_tl += "0"+temp
                else:
                    ip_tl += temp
            ip_tl = int(ip_tl, 16)

            #　Identification
            for i in range(4,6):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    ip_idt += "0"+temp
                else:
                    ip_idt += temp

            #　Flags
            for i in range(6,8):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    ip_flags += "0"+temp
                else:
                    ip_flags += temp

            #　Time To Live
            temp = hex(buf[8])
            ip_ttl = temp.replace("0x","")
            ip_ttl = int(ip_ttl, 16)

            #　プロトコル
            temp = hex(buf[9])
            ip_proto = temp.replace("0x","")
            ip_proto = int(ip_proto, 16)

            #　チェックサム
            for i in range(10,12):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    ip_chksum += "0"+temp
                else:
                    ip_chksum += temp"""

            #　送信元IPアドレス
            ip_src = map(str, [buf[12], buf[13], buf[14], buf[15]])
            ip_src = '.'.join(ip_src)

            #　送信先IPアドレス
            ip_dst = map(str, [buf[16], buf[17], buf[18], buf[19]])
            ip_dst = '.'.join(ip_dst)

            return(ip_l, ip_opt, ip_src, ip_dst)

        #　IPオプション処理
        else:
            pass

    def tcp(buf, p):
        tcp_opt = p
        if tcp_opt == 0:
            tcp_src = ""
            tcp_dst = ""
            #seq = ""
            #ack = ""
            tcp_l = ""
            flags = ""
            #window_size = ""
            #tcp_chksum = ""
            #tcp_urg = ""

            #　送信元ポート
            tcp_src = (hex(buf[0])+hex(buf[1])).replace("0x","")
            tcp_src = int(tcp_src,16)

            #　送信先ポート
            tcp_dst = (hex(buf[2])+hex(buf[3])).replace("0x","")
            tcp_dst = int(tcp_dst,16)

            """#　Sequence
            for i in range(4,8):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    seq += "0"+temp
                else:
                    seq += temp
            seq = int(seq, 16)

            #　Acknowledgment
            for i in range(8,12):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    ack += "0"+temp
                else:
                    ack += temp
            ack = int(ack, 16)"""

            #　TCPデータ部の長さ
            temp = hex(buf[12])
            temp = temp.replace("0x","")
            tcp_l = int(temp[0],16) * 4
            # Flags
            flags = temp[1]
            temp = hex(buf[13])
            temp = temp.replace("0x","")
            if len(temp) == 1:
                flags += "0" + temp
            else:
                flags += temp
            flags = int(flags,16)
            flags = PcapClass.tcp_flags(flags)

            #　TCPオプションズの有無
            if tcp_l != 20:
                tcp_opt = tcp_l - 20

            """#　Window size
            for i in range(14,16):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    window_size += "0"+temp
                else:
                    window_size += temp
            window_size = int(window_size, 16)

            #　チェックサム
            for i in range(16,18):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    tcp_chksum += "0"+temp
                else:
                    tcp_chksum += temp

            #　Urgent pointer
            for i in range(18,20):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    tcp_urg += "0"+temp
                else:
                    tcp_urg += temp
            tcp_urg = int(tcp_urg, 16)"""

            return(tcp_l, tcp_opt, tcp_src, tcp_dst, flags)

        #　TCPオプション処理
        else:
            pass

    def tcp_flags(flag):
        ret = []
        d=[0,0,0,0,0,0,0,0,0,0,0,0]

        for i in range(12):
            d[i] = flag % 2
            flag = flag // 2

        if d[0] == 1:
            ret.append("FIN")
        if d[1] == 1:
            ret.append("SYN")
        if d[2] == 1:
            ret.append("RST")
        if d[3] == 1:
            ret.append("PSH")
        if d[4] == 1:
            ret.append("ACK")
        if d[5] == 1:
            ret.append("URG")
        if d[6] == 1:
            ret.append("ECN")
        if d[7] == 1:
            ret.append("CWR")
        if d[8] == 1:
            ret.append("NON")
        if d[9] == 1 or d[10] == 1 or d[11] == 1:
            ret.append(" RES")

        #　List型からStr型へ
        ret = " ".join(ret)

        return ret

    def tls(buf,ip_src):
        #　TLSハンドシェイクのデータが分割されていた場合の対処
        global save

        if save is None:
            pass
        else:
            if ip_src == save[1]:
                buf = save[0] + buf
                save = None

        all_len = len(buf)
        j = 0
        tls_access = 0
        #tls_res = 0
        tls_rec = ""
        content = ""

        while True:
            #tls_ver = ""
            tls_l = ""
            message = ""

            #　コンテンツタイプ
            temp = hex(buf[j]).replace("0x","")
            content = int(temp, 16)

            j = j + 1

            """#　バージョン
            for i in range(j,j+2):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    tls_ver += "0"+temp
                else:
                    tls_ver += temp"""

            j = j + 2

            #　TLSデータ部の長さ
            for i in range(j,j+2):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    tls_l += "0"+temp
                else:
                    tls_l += temp
            tls_l = int(tls_l, 16)

            j = j + 2

            #　TLSハンドシェイクのデータが途中で切れているかの判定
            try:
                if tls_l == 0:
                    break
                buf[tls_l+j-1]
            except:
                #　残りを保存
                if content == 22:
                    save = [buf[(j-5):all_len],ip_src]
                else:
                    tls_rec += "Continuation_Data "
                break

            #　TLSデータ
            for i in range(j, tls_l+j):
                temp = hex(buf[i])
                temp = temp.replace("0x","")
                if len(temp) == 1:
                    message += "0"+temp
                else:
                    message += temp

            j = j + tls_l

            if content == 21:
                tls_rec += "Alert "
            elif content == 22:
                if message[:2] == "01":
                    tls_access += 1
                    if message[8:12] == "0303":
                        tls_rec += "ClientHello (TLSv1.2) "
                    elif message[8:12] == "0302":
                        tls_rec += "ClientHello (TLSv1.1) "
                    elif message[8:12] == "0301":
                        tls_rec += "ClientHello (TLSv1.0)"
                    elif message[8:12] == "0300":
                        tls_rec += "ClientHello (SSLv3) "
                    else:
                        tls_rec += "Unknown_ClientHello "
                        tls_access = tls_access - 1
                elif message[:2] == "02":
                    tls_rec += "Server_Hello "
                elif message[:2] == "04":
                    tls_rec += "New_Session_Ticket "
                elif message[:2] == "10":
                    #tls_res += 1
                    tls_rec += "Client_Key_Exchange "
                elif message[:2] == "0b":
                    tls_rec += "Certificate "
                elif message[:2] == "0c":
                    tls_rec += "Server_Key_Exchange "
                elif message[:2] == "0e":
                    tls_rec += "Server_Hello_Done "
                else:
                    tls_rec += "Encrypted_Handshake_Message "
            elif content == 23:
                tls_rec += "Application_Data "
            elif content == 20:
                tls_rec += "Change_Cipher_Spec "
            else:
                #　SSLv2の場合
                temp = hex(buf[2])+hex(buf[3])+hex(buf[4])
                temp = temp.replace("0x","")
                if temp == "102":
                    tls_access += 1
                    tls_rec += "ClientHello (SSLv2) "
                    save = None
                    break
                else:
                    tls_rec += "Unknown_TLS_Record "

            #　ループ終了処理
            if all_len == j:
                break

        #eturn tls_rec, tls_access, tls_res
        return tls_rec,tls_access

def pcapch(args):
    global reader
    pc = PcapClass
    new = "pcapch.txt"
    server = ["192.168.0.6","192.168.0.7","192.168.0.8"]

    #　パケットの番号、pcapヘッダの長さ、パケットヘッダの長さ
    pck_count = 0
    pcap_hdr = 24
    pck_hdr = 16

    #　ethernetデータ部の標準長、ipデータ部の標準長、tcpデータ部の標準長
    ethernet_data = 14
    ip_data = 20
    tcp_data = 20

    #　SYNの数
    access = 0
    tls_access = 0

    #　クライアントリスト、カントリーリスト, 時間別アクセス数リスト
    cl_list = {}
    country_list = {}
    access_time_list = {"0-1":0, "1-2":0, "2-3":0, "3-4":0, "4-5":0, "5-6":0, "6-7":0, "7-8":0,
                        "8-9":0, "9-10":0, "10-11":0, "11-12":0, "12-13":0, "13-14":0, "14-15":0, "15-16":0,
                        "16-17":0, "17-18":0, "18-19":0, "19-20":0, "20-21":0, "21-22":0, "22-23":0, "23-24":0}

    #　クライアント一時保存
    cl_temp = ""

    #　pcapファイル解析のスタート
    with open(new,'w') as n:
        with open(args,'rb') as f:
            #　pcapファイルヘッダの解析
            buf = f.read(pcap_hdr)
            pc.pcap_header(buf)

            #　パケット解析のスタート
            while True:
                pck_count += 1
                tls_rec = ""

                #　-%- パケットヘッダ -%-
                buf = f.read(pck_hdr)
                #　パケットがないなら終了
                if len(buf) == 0:
                    break
                #　パケットヘッダ解析（pck_t:時間、pck_cl:パケットに記録されているパケット長）
                pck_t, pck_cl = pc.packet_header(buf)

                #　-%- パケットデータ -%-
                #　Ethernetデータ部解析
                buf = f.read(ethernet_data)
                pc.ethernet(buf)
                #　パケット長からEthernetデータ分消す
                pck_cl -= ethernet_data

                #　IPデータ部解析
                ip_opt = 0
                buf = f.read(ip_data)
                ip_l, ip_opt, ip_src, ip_dst = pc.ip(buf, ip_opt)
                # IPオプションがあるなら
                if ip_opt != 0:
                    buf = f.read(ip_opt)
                    pc.ip(buf, ip_opt)
                #　パケット長からIPデータ分消す
                pck_cl -= ip_data + ip_opt

                #　TCPデータ部解析
                tcp_opt = 0
                buf = f.read(tcp_data)
                tcp_l, tcp_opt, tcp_src, tcp_dst, flags = pc.tcp(buf, tcp_opt)
                # TCPオプションがあるなら
                if tcp_opt != 0:
                    buf = f.read(tcp_opt)
                    pc.tcp(buf, tcp_opt)
                #　パケット長からTCPデータ分消す
                pck_cl -= tcp_data + tcp_opt


                #　パケットの中身が空なら
                if pck_cl == 0:
                    pass
                #　パケットの中身があるなら
                else:
                    buf = f.read(pck_cl)
                    temp = hex(buf[0])
                    temp = temp.replace("0x","")
                    #　パディングかContinuation_DataはPass
                    """if temp == "0" and "PSH" not in flags:
                        pass
                    elif temp == "1" and "PSH" not in flags:"""
                    if len(buf) <= 6:
                        pass
                    #　TLS\SSLとHTTP
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
                        else:
                            if "FIN" in flags:
                                tls_rec = "HTTP_Data"
                            else:
                                pass
                                #tls_rec = "continuation"

                #　SYN時の処理
                if "SYN" in flags and "ACK" not in flags:
                    #　連続アクセス判定
                    if ip_src == cl_temp:
                        #　連続アクセスなら数が増加
                        num += 1
                    else:
                        #　リセット
                        num = 0

                    #　表示
                    pck_t = datetime.fromtimestamp(pck_t)
                    if num == 0:
                        n.write("\nNo.%d %s(%d)  [%s]\n" % (pck_count, ip_src, tcp_src, pck_t))
                    else:
                        n.write("\nNo.%d %s(%d)/%d  [%s]\n" % (pck_count, ip_src, tcp_src, num+1, pck_t))

                    if ip_src not in server:
                        #　時間別アクセス数カウント
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

                        #　クライアントリストの作成
                        if not ip_src in cl_list.keys():
                            cl_list[ip_src] = [0,0,0]
                        #　SYNの数を増やす
                        cl_list[ip_src][0] += 1

                    #　連続アクセス判定用のクライアント一時保存
                    cl_temp = ip_src

                    #　ポート番号一時保存
                    syn_port = tcp_src

                #　TCPフラグ表示（クライアントからのものには目印をつける）
                if ip_src not in server:
                    n.write("> %s" % flags)
                    #　SYN以降でポートが変化していたらの処理
                    if syn_port != tcp_src:
                        n.write("  '%s(%d)'" % (ip_src,tcp_src))
                else:
                    n.write("  %s" % flags)

                #　TLSデータ部の表示
                if tls_rec:
                    n.write("  ### %s###" % tls_rec)
                    #　ClientHelloの数を増やす
                    if tls_access != 0:
                        cl_list[ip_src][1] += tls_access
                    #if tls_res != 0:
                    #    cl_list[ip_src][2] += tls_res
                n.write("\n")
            f.close()
        n.close()

    #　ファイルのクローズ後
    print("")
    tls_access=0
    #tls_res=0
    for cl in cl_list.keys():
        access += cl_list[cl][0]
        tls_access += cl_list[cl][1]
        print("%s\t%d  %d" % (cl,cl_list[cl][0],cl_list[cl][1]))

        #　国のカウント
        c = reader.city(cl)
        try:
            c = c.country.names["ja"]
        except:
            c = c.registered_country.names["ja"]
        if c not in country_list.keys():
            country_list[c] = 1
        else:
            country_list[c] += 1

        #　Client_Key_Exchangeの数を表示
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

def c_pcapch_particular(args,nation):
    global reader
    pc = PcapClass
    server = ["192.168.0.6","192.168.0.7","192.168.0.8"]

    #　パケットの番号、pcapヘッダの長さ、パケットヘッダの長さ
    cpall = 0
    pcap_hdr = 24
    pck_hdr = 16

    #　ethernetデータ部の標準長、ipデータ部の標準長、tcpデータ部の標準長
    ethernet_data = 14
    ip_data = 20
    tcp_data = 20

    #　時間別アクセス数リスト
    access_time_list = {"0-1":0, "1-2":0, "2-3":0, "3-4":0, "4-5":0, "5-6":0, "6-7":0, "7-8":0,
                        "8-9":0, "9-10":0, "10-11":0, "11-12":0, "12-13":0, "13-14":0, "14-15":0, "15-16":0,
                        "16-17":0, "17-18":0, "18-19":0, "19-20":0, "20-21":0, "21-22":0, "22-23":0, "23-24":0}

    for file in args:
        pck_count = 0
        #　特定国の数と１ファイルごとのクライアントリスト
        cpnum=0
        cl_list = []

        #　pcapファイル解析のスタート
        with open(file,'rb') as f:
            #　pcapファイルヘッダの解析
            buf = f.read(pcap_hdr)
            pc.pcap_header(buf)

            #　パケット解析のスタート
            while True:
                pck_count += 1
                tls_rec = ""

                #　-%- パケットヘッダ -%-
                buf = f.read(pck_hdr)
                #　パケットがないなら終了
                if len(buf) == 0:
                    break
                #　パケットヘッダ解析（pck_t:時間、pck_cl:パケットに記録されているパケット長）
                pck_t, pck_cl = pc.packet_header(buf)

                #　-%- パケットデータ -%-
                #　Ethernetデータ部解析
                buf = f.read(ethernet_data)
                pc.ethernet(buf)
                #　パケット長からEthernetデータ分消す
                pck_cl -= ethernet_data

                #　IPデータ部解析
                ip_opt = 0
                buf = f.read(ip_data)
                ip_l, ip_opt, ip_src, ip_dst = pc.ip(buf, ip_opt)
                # IPオプションがあるなら
                if ip_opt != 0:
                    buf = f.read(ip_opt)
                    pc.ip(buf, ip_opt)
                #　パケット長からIPデータ分消す
                pck_cl -= ip_data + ip_opt

                #　TCPデータ部解析
                tcp_opt = 0
                buf = f.read(tcp_data)
                tcp_l, tcp_opt, tcp_src, tcp_dst, flags = pc.tcp(buf, tcp_opt)
                # TCPオプションがあるなら
                if tcp_opt != 0:
                    buf = f.read(tcp_opt)
                    pc.tcp(buf, tcp_opt)
                #　パケット長からTCPデータ分消す
                pck_cl -= tcp_data + tcp_opt


                #　パケットの中身が空なら
                if pck_cl == 0:
                    pass
                #　パケットの中身があるなら
                else:
                    buf = f.read(pck_cl)
                    temp = hex(buf[0])
                    temp = temp.replace("0x","")
                    #　パディングかContinuation_DataはPass
                    """if temp == "0" and "PSH" not in flags:
                        pass
                    elif temp == "1" and "PSH" not in flags:"""
                    if len(buf) <= 6:
                        pass
                    #　TLS\SSLとHTTP
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
                            else:
                                if "FIN" in flags:
                                    tls_rec = "HTTP_Data"
                                else:
                                    pass
                                    #tls_rec = "continuation"

                #　SYN時の処理
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
                            else:
                                pass

                            #　時間取得
                            pck_t = datetime.fromtimestamp(pck_t)

                            #　時間別アクセス数カウント
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

    #　ファイルのクローズ後
    print("#"*20)
    for i in access_time_list.keys():
        print("%s:\t%d\n" % (i, access_time_list[i]),end="")
    print("#"*20)
    print(cpall)

def c_pcapch_particular_plus(args,nation):
    global reader
    pc = PcapClass
    server = ["192.168.0.6","192.168.0.7","192.168.0.8"]

    #　パケットの番号、pcapヘッダの長さ、パケットヘッダの長さ
    cpall = 0
    pcap_hdr = 24
    pck_hdr = 16

    #　ethernetデータ部の標準長、ipデータ部の標準長、tcpデータ部の標準長
    ethernet_data = 14
    ip_data = 20
    tcp_data = 20

    #　特定国の数, 時間別アクセス数リスト
    access_time_list = {"0-1":0, "1-2":0, "2-3":0, "3-4":0, "4-5":0, "5-6":0, "6-7":0, "7-8":0,
                        "8-9":0, "9-10":0, "10-11":0, "11-12":0, "12-13":0, "13-14":0, "14-15":0, "15-16":0,
                        "16-17":0, "17-18":0, "18-19":0, "19-20":0, "20-21":0, "21-22":0, "22-23":0, "23-24":0}
    
    #　特定国のIPリスト
    p_list = []

    for file in args:
        cpnum=0
        pck_count = 0
        #　pcapファイル解析のスタート
        with open(file,'rb') as f:
            #　pcapファイルヘッダの解析
            buf = f.read(pcap_hdr)
            pc.pcap_header(buf)

            #　パケット解析のスタート
            while True:
                pck_count += 1
                tls_rec = ""

                #　-%- パケットヘッダ -%-
                buf = f.read(pck_hdr)
                #　パケットがないなら終了
                if len(buf) == 0:
                    break
                #　パケットヘッダ解析（pck_t:時間、pck_cl:パケットに記録されているパケット長）
                pck_t, pck_cl = pc.packet_header(buf)

                #　-%- パケットデータ -%-
                #　Ethernetデータ部解析
                buf = f.read(ethernet_data)
                pc.ethernet(buf)
                #　パケット長からEthernetデータ分消す
                pck_cl -= ethernet_data

                #　IPデータ部解析
                ip_opt = 0
                buf = f.read(ip_data)
                ip_l, ip_opt, ip_src, ip_dst = pc.ip(buf, ip_opt)
                # IPオプションがあるなら
                if ip_opt != 0:
                    buf = f.read(ip_opt)
                    pc.ip(buf, ip_opt)
                #　パケット長からIPデータ分消す
                pck_cl -= ip_data + ip_opt

                #　TCPデータ部解析
                tcp_opt = 0
                buf = f.read(tcp_data)
                tcp_l, tcp_opt, tcp_src, tcp_dst, flags = pc.tcp(buf, tcp_opt)
                # TCPオプションがあるなら
                if tcp_opt != 0:
                    buf = f.read(tcp_opt)
                    pc.tcp(buf, tcp_opt)
                #　パケット長からTCPデータ分消す
                pck_cl -= tcp_data + tcp_opt


                #　パケットの中身が空なら
                if pck_cl == 0:
                    pass
                #　パケットの中身があるなら
                else:
                    buf = f.read(pck_cl)
                    temp = hex(buf[0])
                    temp = temp.replace("0x","")
                    #　パディングかContinuation_DataはPass
                    """if temp == "0" and "PSH" not in flags:
                        pass
                    elif temp == "1" and "PSH" not in flags:"""
                    if len(buf) <= 6:
                        pass
                    #　TLS\SSLとHTTP
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
                            else:
                                if "FIN" in flags:
                                    tls_rec = "HTTP_Data"
                                else:
                                    pass
                                    #tls_rec = "continuation"

                #　SYN時の処理
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

                            """#　時間取得
                            pck_t = datetime.fromtimestamp(pck_t)

                            #　時間別アクセス数カウント
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

    #　ファイルのクローズ後
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
        logch(path[0])
    elif args.logch_limited:
        args = args.logch_limited
        for i in range(0,len(args)):
            logch_limited(args[i])
    elif args.logch_find:
        args = args.logch_find
        flag = input("ip or req -> ")
        if flag == "ip" or flag == "req":
            s = input("Input target you want to find : ")
            for i in range(0,len(args)):
                logch_find(args[i],s,flag)
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
            ret,address = logchnum(args[i])
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
            make(args[i])
    elif args.integrate:
        args = args.integrate
        integrate(args)
    elif args.diff:
        args = args.diff
        diff(args[0],args[1])
    elif args.pcapch:
        args = args.pcapch
        pcapch(args[0])
    elif args.c_ip_all:
        args = args.c_ip_all
        c_ip_all(args)
    elif args.c_ip_particular:
        args = args.c_ip_particular
        c_ip_particular(args)
    elif args.c_pcapch_particular:
        args = args.c_pcapch_particular
        nation = input("Input Country:")
        p = re.compile("[亜-熙ァ-ヶ]+")
        if p.findall(nation):
            c_pcapch_particular(args,nation)
        else:
            print("No country\n")
            exit()
    elif args.c_pcapch_particular_plus:
        args = args.c_pcapch_particular_plus
        nation = input("Input Country:")
        p = re.compile("[亜-熙ァ-ヶ]+")
        if p.findall(nation):
            c_pcapch_particular_plus(args,nation)
        else:
            print("No country\n")
            exit()
