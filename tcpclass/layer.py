import hpot
savePacket = hpot.savePacket

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
        global savePacket

        if savePacket is None:
            pass
        else:
            if ip_src == savePacket[1]:
                buf = savePacket[0] + buf
                savePacket = None

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
                    savePacket = [buf[(j-5):all_len],ip_src]
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
                    savePacket = None
                    break
                else:
                    tls_rec += "Unknown_TLS_Record "

            #　ループ終了処理
            if all_len == j:
                break

        # return tls_rec, tls_access, tls_res
        return tls_rec,tls_access
