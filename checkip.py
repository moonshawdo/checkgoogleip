#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'moonshawdo@gamil.com'
"""
验证哪些IP可以用在gogagent中
主要是检查这个ip是否可以连通，并且证书是否为google.com
"""

import os
import sys
import threading
import socket
import ssl
import re
import select
import traceback
import logging
import random
from operator import itemgetter
import shutil

PY3 = False
if sys.version_info[0] == 3:
    from queue import Queue, Empty
    PY3 = True
    try:
        from functools import reduce
    finally:
        pass
    try:
        xrange
    except NameError:
        xrange = range
else:
    from Queue import Queue, Empty
import time
from time import sleep
 
g_useOpenSSL = 1
g_usegevent = 1
if g_usegevent == 1:
    try:
        from gevent import monkey
        monkey.patch_all()
        g_useOpenSSL = 0
        from gevent import sleep
    except ImportError:
        g_usegevent = 0

if g_useOpenSSL == 1:
    try:
        import OpenSSL.SSL

        SSLError = OpenSSL.SSL.WantReadError
        g_usegevent = 0
    except ImportError:
        g_useOpenSSL = 0
        SSLError = ssl.SSLError
else:
    SSLError = ssl.SSLError
    

#最大IP延时，单位毫秒
g_maxhandletimeout = 1500
#最大可用IP数量
g_maxhandleipcnt = 50
#检查IP的线程数
g_maxthreads = 60
#是否立即检查上一次的google ip列表
g_checklastgoogleipfirst = 1
#结束时是否需要对ip_tmpok.txt里面的结果进行排序
g_needsorttmpokfile = 1

"连接超时设置"
g_conntimeout = 5
g_handshaketimeout = 7

g_filedir = os.path.dirname(__file__)
g_cacertfile = os.path.join(g_filedir, "cacert.pem")
g_ipfile = os.path.join(g_filedir, "ip.txt")
g_tmpnofile = os.path.join(g_filedir, "ip_tmpno.txt")
g_tmpokfile = os.path.join(g_filedir, "ip_tmpok.txt")
g_tmperrorfile = os.path.join(g_filedir, "ip_tmperror.txt")
g_googleipfile = os.path.join(g_filedir,"googleip.txt")


# gevent socket cnt must less than 1024
if g_usegevent == 1 and g_maxthreads > 1000:
    g_maxthreads = 128

g_ssldomain = ("google.com",)
g_excludessdomain=()
#检查组织是否为google，如果有其他名称，需要添加，暂时只发现一个
g_organizationName = ("Google Inc",)


"是否自动删除记录查询成功的非google的IP文件，方便下次跳过连接，0为不删除，1为删除"
"文件名：ip_tmpno.txt，格式：ip 连接与握手时间 ssl域名"
g_autodeltmpnofile = 0
"是否自动删除记录查询失败的IP文件，0为不删除，1为删除"
"ip_tmperror.txt，格式：ip"
g_autodeltmperrorfile = 0
    
if g_usegevent == 1:
    # Re-add sslwrap to Python 2.7.9
    import inspect
    __ssl__ = __import__('ssl')
    
    try:
        _ssl = __ssl__._ssl
    except AttributeError:
        _ssl = __ssl__._ssl2
        
    def new_sslwrap(sock, server_side=False, keyfile=None, certfile=None, cert_reqs=__ssl__.CERT_NONE, ssl_version=__ssl__.PROTOCOL_SSLv23, ca_certs=None, ciphers=None):
        context = __ssl__.SSLContext(ssl_version)
        context.verify_mode = cert_reqs or __ssl__.CERT_NONE
        if ca_certs:
            context.load_verify_locations(ca_certs)
        if certfile:
            context.load_cert_chain(certfile, keyfile)
        if ciphers:
            context.set_ciphers(ciphers)
            
        caller_self = inspect.currentframe().f_back.f_locals['self']
        return context._wrap_socket(sock, server_side=server_side, ssl_sock=caller_self)
    
    if not hasattr(_ssl, 'sslwrap'):
        _ssl.sslwrap = new_sslwrap


"""
ip_str_list为需要查找的IP地址，第一组的格式：
1.xxx.xxx.xxx.xxx-xx.xxx.xxx.xxx
2.xxx.xxx.xxx.xxx/xx
3.xxx.xxx.xxx.
4 xxx.xxx.xxx.xxx
5 xxx.xxx.xxx.xxx-xxx

组与组之间可以用换行相隔开,第一行中IP段可以用'|'或','
获取随机IP是每组依次获取随机个数量的，因此一组的IP数越少，越有机会会检查，当然获取随机IP会先排除上次查询失败的IP
"""
ip_str_list = '''
218.189.25.166-218.189.25.187|121.78.74.80-121.78.74.88|178.45.251.84-178.45.251.123|210.61.221.148-210.61.221.187
61.219.131.84-61.219.131.251|202.39.143.84-202.39.143.123|203.66.124.148-203.66.124.251|203.211.0.20-203.211.0.59
60.199.175.18-60.199.175.187|218.176.242.20-218.176.242.251|203.116.165.148-203.116.165.251|203.117.34.148-203.117.34.187
210.153.73.20-210.153.73.123|106.162.192.148-106.162.192.187|106.162.198.84-106.162.198.123|106.162.216.20-106.162.216.123
210.139.253.20-210.139.253.251|111.168.255.20-111.168.255.187|203.165.13.210-203.165.13.251
61.19.1.30-61.19.1.109|74.125.31.33-74.125.31.60|210.242.125.20-210.242.125.59|203.165.14.210-203.165.14.251
216.239.32.0/19
64.233.160.0/19
66.249.80.0/20
72.14.192.0/18
209.85.128.0/17
66.102.0.0/20
74.125.0.0-74.125.31.255
74.125.32.0-74.125.63.255
74.125.64.0-74.125.95.255
74.125.96.0-74.125.127.255
74.125.128.0-74.125.159.255
74.125.160.0-74.125.191.255
74.125.192.0-74.125.223.255
74.125.224.0-74.125.255.255
64.18.0.0/20
207.126.144.0/20
173.194.0.0-173.194.31.255
173.194.32.0-173.194.63.255
173.194.64.0-173.194.95.255
173.194.96.0-173.194.127.255
173.194.128.0-173.194.159.255
173.194.160.0-173.194.191.255
173.194.192.0-173.194.223.255
173.194.224.0-173.194.255.255
1.179.248.0-255
106.162.192.148-187
108.166.34.0-255
118.174.24.0-255
118.174.25.0-255
118.174.26.0-255
118.174.27.0-255
121.195.178.0-255
121.78.74.68-123
123.205.250.0-255
123.205.251.68-123
124.160.89.0-255
130.211.115.0-255
130.211.76.0-255
130.211.78.0-255
130.211.82.0-255
146.148.16.0-255
146.148.24.0-255
146.148.34.0-255
146.148.8.0-255
146.148.9.0-255
178.60.128.1-63
193.120.166.64-127
193.92.133.0-63
194.78.20.16-31
194.78.99.0-255
195.249.20.192-255
202.106.93.0-255
202.39.143.1-123
202.69.26.0-255
203.66.124.129-251
208.117.224.0-208.117.229.255
208.117.230.0-208.117.239.55
208.117.240.0-208.117.255.255
209.85.228.0-255
210.242.125.20-59
212.188.15.0-255
213.186.229.0-63
213.240.44.0-31
218.176.242.0-255
24.156.131.0-255
41.206.96.0-255
62.116.207.0-63
62.197.198.193-251
64.15.112.0-64.15.117.255
64.15.119.0-64.15.126.255
64.233.160.0-255
64.233.168.0-255
64.233.171.0-255
66.102.133.0-255
66.102.136.0-255
66.102.255.0-255
80.228.65.128-191
81.175.29.128-191
84.235.77.0-255
85.182.250.0-255
86.127.118.128-191
93.183.211.192-255
93.94.217.0-31
93.94.218.0-31
94.200.103.64-71
94.40.70.0-63
'''




logging.basicConfig(format="[%(threadName)s]%(message)s",level=logging.INFO)


evt_ipramdomstart = threading.Event()
evt_ipramdomend = threading.Event()

def PRINT(strlog):
    logging.info(strlog)
    
def isgoolgledomain(domain):
    lowerdomain = domain.lower()
    if lowerdomain in g_ssldomain:
        return 1
    if lowerdomain in g_excludessdomain:
        return 0
    return 2

def isgoogleserver(svrname):
    lowerdomain = svrname.lower()
    if lowerdomain == "gws":
        return True
    else:
        return False

def checkvalidssldomain(domain,svrname):
    ret = isgoolgledomain(domain)
    if ret == 1:
        return True
    elif ret == 0:
        return False
    elif len(svrname) > 0 and isgoogleserver(svrname):
        return True
    else:
        return False

prekey="\nServer:"
def getgooglesvrnamefromheader(header):
    begin = header.find(prekey)
    if begin != -1: 
        begin += len(prekey)
        end = header.find("\n",begin)
        if end == -1:
            end = len(header)
        gws = header[begin:end].strip(" \t")
        return gws
    return ""

g_NAtimeout = 1000000
def getcosttime(costtime):
    if costtime.startswith("NA_"):
        return g_NAtimeout
    else:
        return int(costtime)

class TCacheResult(object):
    __slots__ = ["oklist","failiplist","oklock","errlock","okfile","errorfile","notfile","validipcnt","filegwsipset","okfilelinecnt"]
    def __init__(self):
        self.oklist = list()
        self.failiplist = list()
        self.oklock = threading.Lock()
        self.errlock = threading.Lock()
        self.okfile = None
        self.errorfile = None
        self.notfile = None
        self.validipcnt = 0
        self.filegwsipset = set()
        self.okfilelinecnt = 0
    
    def addOKIP(self,costtime,ip,ssldomain,gwsname):
        bOK = False
        try:
            self.oklock.acquire()
            if checkvalidssldomain(ssldomain,gwsname):
                bOK = True
                self.oklist.append((costtime,ip,ssldomain,gwsname))
            if not bOK:
                if self.notfile is None:
                    self.notfile = open(g_tmpnofile,"a+",0)
                self.notfile.seek(0,2)
                line = "%s %d %s %s\n" % (ip, costtime, ssldomain,gwsname)
                self.notfile.write(line)
            else:
                if self.okfile is None:
                    self.okfile = open(g_tmpokfile,"a+",0)
                self.okfile.seek(0,2)
                line = "%s %d %s %s\n" % (ip, costtime, ssldomain,gwsname)
                self.okfile.write(line)
            if bOK and costtime <= g_maxhandletimeout:
                self.validipcnt += 1
                return bOK,self.validipcnt
            else:
                return bOK,0
        finally:
            self.oklock.release()
            
    def addFailIP(self,ip):
        try:
            self.errlock.acquire()
            #如果之前是google ip,不需要记录到失败文件，下次启动可以继续尝试该 ip
            if ip not in self.filegwsipset:
                if self.errorfile is None:
                    self.errorfile = open(g_tmperrorfile,"a+",0)
                self.errorfile.seek(0,2)
                self.errorfile.write(ip+"\n")
            self.failiplist.append(ip)
            if len(self.failiplist) > 128:
                self.flushFailIP()
        finally:
            self.errlock.release() 
    
    def close(self):
        def closefile(fileobj):
            if fileobj:
                fileobj.close()
                fileobj = None
        closefile(self.okfile)
        closefile(self.notfile)
        closefile(self.errorfile)
       
    def getIPResult(self):
        return self.oklist
    
    def flushFailIP(self):
        nLen = len(self.failiplist)
        if nLen > 0 :
            self.failiplist = list()
            PRINT( "%d ip timeout" % nLen )

    def loadLastResult(self):
        okresult  = set()
        errorresult = set()
        if os.path.exists(g_tmpnofile):
            with open(g_tmpnofile,"r") as fd:
                for line in fd:
                    ips = line.strip("\r\n").split(" ")
                    ipint = from_string(ips[0])
                    okresult.add(ipint)
        if os.path.exists(g_tmpokfile):
            with open(g_tmpokfile,"r") as fd:
                self.okfilelinecnt = 0
                for line in fd:
                    self.okfilelinecnt += 1
                    ips = line.strip("\r\n").split(" ")
                    if len(ips) < 3:
                        continue
                    gwsname = ""
                    if len(ips) > 3:
                        gwsname = ips[3]
                    ipint = from_string(ips[0])
                    # 如果为google ip,每次都需要检查，如果不是，则跳过检查
                    if not checkvalidssldomain(ips[2],gwsname):
                        okresult.add(ipint)
                    else:
                        self.filegwsipset.add(ips[0])
                        if ipint in okresult:
                            okresult.remove(ipint)
        if os.path.exists(g_tmperrorfile):
            with open(g_tmperrorfile,"r") as fd:
                for line in fd:
                    ips = line.strip("\r\n").split(" ")
                    for item in ips:
                        errorresult.add(from_string(item))
        return okresult,errorresult
    
    def clearFile(self):
        self.close()
        if g_autodeltmpnofile and os.path.exists(g_tmpnofile):
            os.remove(g_tmpnofile)
            PRINT("remove file %s" % g_tmpokfile)
        if g_autodeltmperrorfile and os.path.exists(g_tmperrorfile):
            os.remove(g_tmperrorfile)
            PRINT("remove file %s" % g_tmperrorfile)
            
    def queryfinish(self):
        try:
            self.oklock.acquire()
            return self.validipcnt >= g_maxhandleipcnt
        finally:
            self.oklock.release()

class my_ssl_wrap(object):
    ssl_cxt = None
    ssl_cxt_lock = threading.Lock()
    httpreq = "GET / HTTP/1.1\r\nAccept: */*\r\nHost: %s\r\nConnection: Keep-Alive\r\n\r\n"

    def __init__(self):
        pass

    @staticmethod
    def initsslcxt():
        if my_ssl_wrap.ssl_cxt is not None:
            return
        try:
            my_ssl_wrap.ssl_cxt_lock.acquire()
            if my_ssl_wrap.ssl_cxt is not None:
                return
            my_ssl_wrap.ssl_cxt = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            my_ssl_wrap.ssl_cxt.set_timeout(g_handshaketimeout)
            PRINT("init ssl context ok")
        except Exception:
            raise
        finally:
            my_ssl_wrap.ssl_cxt_lock.release()

    def getssldomain(self, threadname, ip):
        time_begin = time.time()
        s = None
        c = None
        haserror = 1
        timeout = 0
        domain = None
        gwsname = ""
        ssl_orgname = ""
        try:
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if g_useOpenSSL:
                my_ssl_wrap.initsslcxt()
                s.settimeout(g_conntimeout)
                s.connect((ip, 443))
                c = OpenSSL.SSL.Connection(my_ssl_wrap.ssl_cxt, s)
                c.set_connect_state()
                s.setblocking(0)
                while True:
                    try:
                        c.do_handshake()
                        break
                    except SSLError:
                        infds, outfds, errfds = select.select([s, ], [], [], g_handshaketimeout)
                        if len(infds) == 0:
                            raise SSLError("do_handshake timed out")
                        else:
                            costtime = int(time.time() - time_begin)
                            if costtime > g_handshaketimeout:
                                raise SSLError("do_handshake timed out")
                            else:
                                pass
                    except OpenSSL.SSL.SysCallError as e:
                        raise SSLError(e.args)
                time_end = time.time()
                cert = c.get_peer_certificate()
                costtime = int(time_end * 1000 - time_begin * 1000)
                for subject in cert.get_subject().get_components():
                    if subject[0] == "CN":
                        domain = subject[1]
                        haserror = 0
                    elif subject[0] == "O":
                        ssl_orgname = subject[1]
                if domain is None:
                    PRINT("%s can not get CN: %s " % (ip, cert.get_subject().get_components()))
                if ssl_orgname == "" or ssl_orgname not in g_organizationName:
                    return domain, costtime,timeout,gwsname,ssl_orgname
                #尝试发送http请求，获取回应头部的Server字段
                #if domain is None or isgoolgledomain(domain) == 2:
                if True:
                    cur_time = time.time()
                    gwsname = self.getgooglesvrname(c,s,ip)
                    time_end = time.time()
                    costtime += int(time_end * 1000 - cur_time * 1000)
                    if domain is None and len(gwsname) > 0:
                        domain = "null"
                return domain, costtime,timeout,gwsname,ssl_orgname
            else:
                s.settimeout(g_conntimeout)
                c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=g_cacertfile,
                                    do_handshake_on_connect=False)
                c.settimeout(g_conntimeout)
                c.connect((ip, 443))
                c.settimeout(g_handshaketimeout)
                c.do_handshake()
                time_end = time.time()
                cert = c.getpeercert()
                costtime = int(time_end * 1000 - time_begin * 1000)
                if 'subject' in cert:
                    subjectitems = cert['subject']
                    for mysets in subjectitems:
                        for item in mysets:
                            if item[0] == "commonName":
                                if not isinstance(item[1], str):
                                    domain = item[1].encode("utf-8")
                                else:
                                    domain = item[1]
                                haserror = 0
                            elif item[0] == "organizationName":
                                if not isinstance(item[1], str):
                                    ssl_orgname = item[1].encode("utf-8")
                                else:
                                    ssl_orgname = item[1]
                    if domain is None:
                        PRINT("%s can not get commonName: %s " % (ip, subjectitems))
                # 如果组织不在g_organizationName，可能不是google的IP，不能使用
                if ssl_orgname == "" or ssl_orgname not in g_organizationName:
                    return domain, costtime,timeout,gwsname,ssl_orgname
                #尝试发送http请求，获取回应头部的Server字段
                #if domain is None or isgoolgledomain(domain) == 2:
                if True:
                    cur_time = time.time()
                    gwsname = self.getgooglesvrname(c,s,ip)
                    time_end = time.time()
                    costtime += int(time_end * 1000 - cur_time * 1000)
                    if domain is None and len(gwsname) > 0:
                        domain = "null"
                return domain, costtime,timeout,gwsname,ssl_orgname
        except SSLError as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            if str(e).endswith("timed out"):
                timeout = 1
            else:
                PRINT("SSL Exception(%s): %s, times:%d ms " % (ip, e, costtime))
            return domain, costtime,timeout,gwsname,ssl_orgname
        except IOError as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            if str(e).endswith("timed out"):
                timeout = 1
            else:
                PRINT("Catch IO Exception(%s): %s, times:%d ms " % (ip, e, costtime))
            return domain, costtime,timeout,gwsname,ssl_orgname
        except Exception as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            PRINT("Catch Exception(%s): %s, times:%d ms " % (ip, e, costtime))
            return domain, costtime,timeout,gwsname,ssl_orgname
        finally:
            if g_useOpenSSL:
                if c:
                    if haserror == 0:
                        c.shutdown()
                        c.sock_shutdown(2)
                    c.close()
                if s:
                    s.close()
            else:
                if c:
                    if haserror == 0:
                        c.shutdown(2)
                    c.close()
                elif s:
                    s.close()
                    
    def getgooglesvrname(self,conn,sock,ip):
        try:
            myreq = my_ssl_wrap.httpreq % ip
            conn.write(myreq)
            data=""
            sock.setblocking(0)
            trycnt = 0
            begin = time.time()
            conntimeout = g_conntimeout if g_usegevent == 0 else 0.001
            while True:
                end = time.time()
                costime = int(end-begin)
                if costime >= g_conntimeout:
                    PRINT("get http response timeout(%ss),ip:%s,try:%d" % (costime,ip,trycnt) )
                    return ""
                trycnt += 1
                infds, outfds, errfds = select.select([sock, ], [], [], conntimeout)
                if len(infds) == 0:
                    if g_usegevent == 1:
                        sleep(0.5)
                    continue
                timeout = 0
                try:
                    d = conn.read(1024)
                except SSLError as e:
                    sleep(0.5)
                    continue
                readlen = len(d)
                if readlen == 0:
                    sleep(0.5)
                    continue
                data = data + d.replace("\r","")
                index = data.find("\n\n")
                if index != -1:
                    gwsname = getgooglesvrnamefromheader(data[0:index])
                    return gwsname
                elif readlen <= 64:
                    sleep(0.01)
            return ""
        except Exception as e:
            info = "%s" % e
            if len(info) == 0:
                info = type(e)
            PRINT("Catch Exception(%s) in getgooglesvrname: %s" % (ip, info))
            return ""


class Ping(threading.Thread):
    ncount = 0
    ncount_lock = threading.Lock()
    __slots__=["checkqueue","cacheResult"]
    def __init__(self,checkqueue,cacheResult):
        threading.Thread.__init__(self)
        self.queue = checkqueue
        self.cacheResult = cacheResult

    def runJob(self):
        while not evt_ipramdomstart.is_set():
            evt_ipramdomstart.wait(5)
        while not self.cacheResult.queryfinish():
            try:
                if self.queue.qsize() == 0 and evt_ipramdomend.is_set():
                    break
                addrint = self.queue.get(True,2)
                ipaddr = to_string(addrint)
                self.queue.task_done()
                ssl_obj = my_ssl_wrap()
                (ssldomain, costtime,timeout,gwsname,ssl_orgname) = ssl_obj.getssldomain(self.getName(), ipaddr)
                if ssldomain is not None:
                    gwsip,cnt = self.cacheResult.addOKIP(costtime, ipaddr, ssldomain,gwsname)
                    if cnt != 0:
                        PRINT("ip: %s,CN: %s,O:%s,svr: %s,ok:1,cnt:%d" % (ipaddr, ssldomain,ssl_orgname,gwsname,cnt))
                    elif gwsip:
                        PRINT("ip: %s,CN: %s,O:%s,svr: %s,t:%dms,ok:0" % (ipaddr, ssldomain,ssl_orgname,gwsname,costtime))
                    else:
                        PRINT("ip: %s,CN: %s,O:%s,svr: %s,not gae" % (ipaddr, ssldomain,ssl_orgname,gwsname))
                elif ssldomain is None:
                    self.cacheResult.addFailIP(ipaddr)
            except Empty:
                pass

    def run(self):
        try:
            Ping.ncount_lock.acquire()
            Ping.ncount += 1
            Ping.ncount_lock.release()
            self.runJob()
        except Exception:
            raise
        finally:
            Ping.ncount_lock.acquire()
            Ping.ncount -= 1
            Ping.ncount_lock.release()
    
    @staticmethod 
    def getCount():
        try:
            Ping.ncount_lock.acquire()
            return Ping.ncount
        finally:
            Ping.ncount_lock.release()
            
            
class RamdomIP(threading.Thread):
    def __init__(self,checkqueue,cacheResult,cacheip):
        threading.Thread.__init__(self)
        self.ipqueue = checkqueue
        self.cacheResult = cacheResult
        self.hadaddipcnt = 0
        self.cacheip = cacheip
        
    def ramdomip(self):
        iplineslist = []
        skipokcnt = 0
        skiperrocnt = 0
        iplinelist = []
        totalipcnt = 0
        loaddefaultip = False
        if os.path.exists(g_googleipfile):
            try:
                fp = open(g_googleipfile,"r")
                linecnt = 0
                for line in fp:
                    data = line.strip("\r\n")
                    if data == '@default':
                        iplineslist.extend(re.split("\r|\n", ip_str_list.strip("\r\n")))
                        loaddefaultip = True
                    else:
                        iplineslist.append(data)
                        linecnt += 1
                fp.close()
                PRINT("load extra ip ok,line:%d,load default ip: %d" % (linecnt,loaddefaultip))
            except Exception as e:
                PRINT("load extra ip file error:%s " % str(e) )
                sys.exit(1)
        else:
            iplineslist.extend(re.split("\r|\n", ip_str_list.strip("\r\n")))
        for iplines in iplineslist:
            if len(iplines) == 0 or iplines[0] == '#':
                continue
            singlelist = []
            ips = re.split(",|\|", iplines)
            for line in ips:
                if len(line) == 0 or line[0] == '#':
                    continue
                begin, end = splitip(line)
                if checkipvalid(begin) == 0 or checkipvalid(end) == 0:
                    PRINT("ip format is error,line:%s, begin: %s,end: %s" % (line, begin, end))
                    continue
                nbegin = from_string(begin)
                nend = from_string(end)
                iplinelist.append([nbegin,nend])
        
        if g_checklastgoogleipfirst:
            num = 0
            for ip in self.cacheResult.filegwsipset:
                ip_int = from_string(ip)
                self.ipqueue.put(ip_int)
                self.cacheip.add(ip_int)
                num += 1
            if num:
                self.hadaddipcnt += num
                PRINT("load last gae ip cnt: %d" % num)
                evt_ipramdomstart.set()
                
        hadIPData = True
        putdata = False
        while hadIPData:
            if evt_ipramdomend.is_set():
                break
            hadIPData = False
            index = -1
            emptyindexlist=[]
            #PRINT("ramdom ip array: % d" % len(iplinelist))
            for itemlist in iplinelist:
                begin = itemlist[0]
                end = itemlist[1]
                itemlen = end - begin + 1
                index += 1
                if itemlen <= 0:
                    continue
                if self.cacheResult.queryfinish():
                    break
                if itemlen > 1000:
                    selectcnt = 5
                elif itemlen <= 2:
                    selectcnt = itemlen
                else:
                    selectcnt = 2
                for i in xrange(0,selectcnt):
                    k = random.randint(begin,end)
                    first = True
                    findOK = True
                    checkcnt = 0
                    checkend = k
                    # try get next index in circle
                    while k in self.cacheip:
                        checkcnt += 1
                        if k < end:
                            k += 1
                        else:
                            k = begin
                        # if met itself,nee break
                        if k == checkend :
                            findOK = False
                            break
                    #if checkcnt > 1:
                    #    PRINT("[%d]total cnt: %d,index:%d,ramdom checkcnt:%d,found:%d" % (index,itemlen,checkend-begin,checkcnt,findOK))
                    if findOK:
                        hadIPData = True
                        self.ipqueue.put(k)
                        self.cacheip.add(k)
                        self.hadaddipcnt += 1
                        if not putdata:
                            evt_ipramdomstart.set()
                            putdata = True
                    if evt_ipramdomend.is_set():
                        break
                    # not found,no need to ramdom next index
                    if not findOK:
                        emptyindexlist.insert(0,index)
                        break
            if self.ipqueue.qsize() >= 500:
                sleep(1)
            for empytindex in emptyindexlist:
                iplinelist.pop(empytindex)
                #PRINT("remote index: %d" % empytindex )
        if not evt_ipramdomstart.is_set():
            evt_ipramdomstart.set()
        
    def run(self):
        PRINT("begin to get ramdom ip")
        self.ramdomip()
        evt_ipramdomend.set()
        self.cacheip.clear()
        qsize = self.ipqueue.qsize()
        PRINT("ramdom ip thread stopped.had check ip: %d,rest ip queue size: %d" % (self.hadaddipcnt - qsize,qsize))

def from_string(s):
    """Convert dotted IPv4 address to integer."""
    return reduce(lambda a, b: a << 8 | b, map(int, s.split(".")))


def to_string(ip):
    """Convert 32-bit integer to dotted IPv4 address."""
    return ".".join(map(lambda n: str(ip >> n & 0xFF), [24, 16, 8, 0]))


g_ipcheck = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')


def checkipvalid(ip):
    """检查ipv4地址的合法性"""
    ret = g_ipcheck.match(ip)
    if ret is not None:
        "each item range: [0,255]"
        for item in ret.groups():
            if int(item) > 255:
                return 0
        return 1
    else:
        return 0


def splitip(strline):
    """从每组地址中分离出起始IP以及结束IP"""
    begin = ""
    end = ""
    if "-" in strline:
        "xxx.xxx.xxx.xxx-xxx.xxx.xxx.xxx"
        begin, end = strline.split("-")
        if 1 <= len(end) <= 3:
            prefix = begin[0:begin.rfind(".")]
            end = prefix + "." + end
    elif strline.endswith("."):
        "xxx.xxx.xxx."
        begin = strline + "0"
        end = strline + "255"
    elif "/" in strline:
        "xxx.xxx.xxx.xxx/xx"
        (ip, bits) = strline.split("/")
        if checkipvalid(ip) and (0 <= int(bits) <= 32):
            orgip = from_string(ip)
            end_bits = (1 << (32 - int(bits))) - 1
            begin_bits = 0xFFFFFFFF ^ end_bits
            begin = to_string(orgip & begin_bits)
            end = to_string(orgip | end_bits)
    else:
        "xxx.xxx.xxx.xxx"
        begin = strline
        end = strline

    return begin, end


def dumpstacks():
    code = []
    for threadId, stack in sys._current_frames().items():
        code.append("\n# Thread: %d" % (threadId))
        for filename, lineno, name, line in traceback.extract_stack(stack):
            code.append('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                code.append("  %s" % (line.strip()))
    PRINT("\n".join(code))
    
def checksingleprocess(ipqueue,cacheResult,max_threads):
    threadlist = []
    threading.stack_size(96 * 1024)
    PRINT('need create max threads count: %d' % (max_threads))
    for i in xrange(1, max_threads + 1):
        ping_thread = Ping(ipqueue,cacheResult)
        ping_thread.setDaemon(True)
        try:
            ping_thread.start()
        except threading.ThreadError as e:
            PRINT('start new thread except: %s,work thread cnt: %d' % (e, Ping.getCount()))
            break
        threadlist.append(ping_thread)
    try:
        for p in threadlist:
            p.join(5)
    except KeyboardInterrupt:
        PRINT("try to interrupt process")
        ipqueue.queue.clear()
        evt_ipramdomend.set()
    cacheResult.close()
    

def sort_tmpokfile(nLastOKFileLineCnt):
    if os.path.exists(g_tmpokfile):
        ipdict = dict()
        tmpfile = g_tmpokfile + ".tmp"
        bsortok = False
        needsortip = False
        lastcostime = 0
        ncurline = 0
        with open(g_tmpokfile,"r") as fd:
            for line in fd:
                ncurline += 1
                ips = line.strip("\r\n").split(" ")
                if len(ips) < 3:
                    continue
                ipint = from_string(ips[0])
                # 把当次查询出来的IP放在最前面，因为有一些IP可能上一次的时间少，并且这次又没有查询出来，应该排在新IP后面
                oldIP = True if ncurline <= nLastOKFileLineCnt else False
                if oldIP == True:
                    costime = g_NAtimeout + ncurline
                else:
                    costime = int(ips[1])
                    if lastcostime > costime:
                        needsortip = True 
                lastcostime = costime
                ipdict[ipint] = (costime,ips)
            if needsortip:
                iplist = sorted(ipdict.iteritems(),key = itemgetter(1))
                with open(tmpfile,"w") as wfd:
                    for item in iplist:
                        costime = item[1][0]
                        ips = item[1][1]
                        if costime >= g_NAtimeout and ips[1][0] != 'N':
                            ips[1] = "NA_" + ips[1]
                        wfd.write(" ".join(ips))
                        wfd.write("\n")
                        bsortok = True
        if bsortok:
            shutil.move(tmpfile,g_tmpokfile)
            PRINT("sort %s file ok" % g_tmpokfile)
        else:
            PRINT("file %s no need sort" % g_tmpokfile)


def list_ping():
    if g_useOpenSSL == 1:
        PRINT("support PyOpenSSL")
    if g_usegevent == 1:
        PRINT("support gevent")

    checkqueue = Queue()
    cacheResult = TCacheResult()
    lastokresult,lasterrorresult = cacheResult.loadLastResult()
    oklen = len(lastokresult)
    errorlen = len(lasterrorresult)
    totalcachelen = oklen + errorlen
    if totalcachelen != 0:
        PRINT("load last result,ok cnt:%d,ok file line:%d,error cnt: %d" % (oklen,cacheResult.okfilelinecnt,errorlen) )
    
    ramdomip_thread = RamdomIP(checkqueue,cacheResult,lastokresult|lasterrorresult)
    ramdomip_thread.setDaemon(True)
    ramdomip_thread.start()
    checksingleprocess(checkqueue,cacheResult,g_maxthreads)
    
    lastokresult.clear()
    lasterrorresult.clear()
    
    cacheResult.flushFailIP()
    ip_list = cacheResult.getIPResult()
    ip_list.sort()

    PRINT('try to collect ssl result')
    op = 'wb'
    if sys.version_info[0] == 3:
        op = 'w'
    ff = open(g_ipfile, op)
    ncount = 0
    for ip in ip_list:
        domain = ip[2]
        if ip[0] > g_maxhandletimeout :
            break        
        PRINT("[%s] %d ms,domain: %s,svr:%s" % (ip[1], ip[0], domain,ip[3]))
        if domain is not None:
            if ncount != 0:
                ff.write("|")
            ff.write(ip[1])
            ncount += 1
    PRINT("write to file %s ok,count:%d " % (g_ipfile, ncount))
    ff.close()
    nLastOKFileLineCnt = cacheResult.okfilelinecnt
    cacheResult.clearFile()
    if g_needsorttmpokfile:
        sort_tmpokfile(nLastOKFileLineCnt)


def checkip(ip):
    if g_useOpenSSL == 1:
        print "use PyOpenSSL to check ",ip
        sslcontext = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
        sslcontext.set_timeout(30)
        s = socket.socket()
        s.connect((ip, 443))
        c = OpenSSL.SSL.Connection(sslcontext, s)
        c.set_connect_state()
        print "%s try to handshake " % ( ip )
        c.do_handshake()
        cert = c.get_peer_certificate()
        print "ssl subject: ",cert.get_subject().get_components()
        c.shutdown()
        s.close()
    elif g_usegevent == 1:
        print "use gevent to check ",ip
        s = socket.socket()
        s.settimeout(10)
        c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=g_cacertfile)
        c.settimeout(10)
        print( "try connect to %s" % (ip))
        c.connect((ip, 443))
        cert = c.getpeercert()
        if 'subject' in cert:
            print "ssl subject: ",cert['subject']
        else:
            print "ssl key: ",cert
        c.close()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        checkip(sys.argv[1])
    else:
        list_ping()
