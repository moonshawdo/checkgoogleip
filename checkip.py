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

if sys.version_info[0] == 3:
    from queue import Queue, Empty

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

g_useOpenSSL = 1
g_usegevent = 1
if g_usegevent == 1:
    try:
        from gevent import monkey
        monkey.patch_all()
        g_useOpenSSL = 0
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


g_useprocess = 0

"""
ip_str_list为需要查找的IP地址，第一组的格式：
1.xxx.xxx.xxx.xxx-xx.xxx.xxx.xxx
2.xxx.xxx.xxx.xxx/xx
3.xxx.xxx.xxx.
4 xxx.xxx.xxx.xxx

组与组之间可以用换行、'|'或','相隔开
"""
ip_str_list = '''
216.239.32.0/19
64.233.160.0/19
66.249.80.0/20
72.14.192.0/18
209.85.128.0/17
66.102.0.0/20
74.125.0.0/16
64.18.0.0/20
207.126.144.0/20
173.194.0.0/16
'''

#查询随机的IP列表，为0表示所有IP随机排列，如果非0，表示只取指定数量的随机IP查询
g_ramdomipcnt = 700

"连接超时设置"
g_conntimeout = 5
g_handshaketimeout = 7

g_filedir = os.path.dirname(__file__)
g_cacertfile = os.path.join(g_filedir, "cacert.pem")
g_ipfile = os.path.join(g_filedir, "ip.txt")
g_tmpokfile = os.path.join(g_filedir, "ip_tmpok.txt")
g_tmperrorfile = os.path.join(g_filedir, "ip_tmperror.txt")

g_maxthreads = 128
if g_usegevent == 1:
    "must set g_useprocess = 0"
    g_useprocess = 0

if g_useprocess > 1:
    try:
        import multiprocessing
        from multiprocessing import Process,JoinableQueue as Queue
    except ImportError:
        g_useprocess = 0

# gevent socket cnt must less than 1024
if g_usegevent == 1 and g_maxthreads > 1000:
    g_maxthreads = 768


g_ssldomain = ("google.com",)
g_excludessdomain=()


"是否自动删除记录查询成功的IP文件，0为不删除，1为删除"
"文件名：ip_tmpok.txt，格式：ip 连接与握手时间 ssl域名"
g_autodeltmpokfile = 1
"是否自动删除记录查询失败的IP文件，0为不删除，1为删除"
"ip_tmperror.txt，格式：ip"
g_autodeltmperrorfile = 0

logging.basicConfig(format="[%(process)d][%(threadName)s]%(message)s",level=logging.INFO)

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

class TCacheResult(object):
    def __init__(self):
        self.okqueue = Queue()
        self.failipqueue = Queue()
        if g_useprocess > 1:
            self.oklock = multiprocessing.Lock()
            self.errlock = multiprocessing.Lock()
        else:
            self.oklock = threading.Lock()
            self.errlock = threading.Lock()
        self.okfile = None
        self.errorfile = None
    
    def addOKIP(self,costtime,ip,ssldomain,gwsname):
        if checkvalidssldomain(ssldomain,gwsname):
            self.okqueue.put((costtime,ip,ssldomain,gwsname))
        try:
            self.oklock.acquire()
            if self.okfile is None:
                self.okfile = open(g_tmpokfile,"a+",0)
            self.okfile.seek(0,2)
            line = "%s %d %s %s\n" % (ip, costtime, ssldomain,gwsname)
            self.okfile.write(line)
        finally:
            self.oklock.release()
            
    def addFailIP(self,ip):
        try:
            self.errlock.acquire()
            if self.errorfile is None:
                self.errorfile = open(g_tmperrorfile,"a+",0)
            self.errorfile.seek(0,2)
            self.errorfile.write(ip+"\n")
            self.failipqueue.put(ip)
            if self.failipqueue.qsize() > 128:
                self.flushFailIP()
        finally:
            self.errlock.release() 
    
    def close(self):
        if self.okfile:
            self.okfile.close()
            self.okfile = None
        if self.errorfile:
            self.errorfile.close()
            self.errorfile = None
       
    def getIPResult(self):
        return self._queuetolist(self.okqueue)
        
    def _queuetolist(self,myqueue):
        result = []
        try:
            qsize = myqueue.qsize()
            while qsize > 0:
                result.append(myqueue.get_nowait())
                myqueue.task_done()
                qsize -= 1
        except Empty:
            pass
        return result

    def _cleanqueue(self,myqueue):
        try:
            qsize = myqueue.qsize()
            while qsize > 0:
                myqueue.get_nowait()
                myqueue.task_done()
                qsize -= 1
        except Empty:
            pass
    
    def flushFailIP(self):
        if self.failipqueue.qsize() > 0 :
            qsize = self.failipqueue.qsize()
            self._cleanqueue(self.failipqueue)
            logging.info( str(qsize) + " ip timeout")


    def loadLastResult(self):
        okresult  = set()
        errorresult = set()
        if os.path.exists(g_tmpokfile):
            with open(g_tmpokfile,"r") as fd:
                for line in fd:
                    ips = line.strip("\r\n").split(" ")
                    if len(ips) < 3:
                        continue
                    gwsname = ""
                    if len(ips) > 3:
                        gwsname = ips[3]
                    okresult.add(ips[0])
                    if checkvalidssldomain(ips[2],gwsname):
                        self.okqueue.put((int(ips[1]),ips[0],ips[2],gwsname))
        if os.path.exists(g_tmperrorfile):
            with open(g_tmperrorfile,"r") as fd:
                for line in fd:
                    ips = line.strip("\r\n").split(" ")
                    for item in ips:
                        errorresult.add(item)
        return okresult,errorresult
    
    def clearFile(self):
        self.close()
        if g_autodeltmpokfile and os.path.exists(g_tmpokfile):
            os.remove(g_tmpokfile)
            PRINT("remove file %s" % g_tmpokfile)
        if g_autodeltmperrorfile and os.path.exists(g_tmperrorfile):
            os.remove(g_tmperrorfile)
            PRINT("remove file %s" % g_tmperrorfile)

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
                cert = c.get_peer_certificate()
                time_end = time.time()
                costtime = int(time_end * 1000 - time_begin * 1000)
                for subject in cert.get_subject().get_components():
                    if subject[0] == "CN":
                        domain = subject[1]
                        haserror = 0
                if domain is None:
                    PRINT("%s can not get CN: %s " % (ip, cert.get_subject().get_components()))
                #尝试发送http请求，获取回应头部的Server字段
                if domain is None or isgoolgledomain(domain) == 2:
                    cur_time = time.time()
                    gwsname = self.getgooglesvrname(c,s,ip)
                    time_end = time.time()
                    costtime += int(time_end * 1000 - cur_time * 1000)
                    if domain is None and len(gwsname) > 0:
                        domain="defaultgws"
                if domain is not None:
                    PRINT("ip: %s,CN: %s,svr: %s" % (ip, domain,gwsname))
                return domain, costtime,timeout,gwsname
            else:
                s.settimeout(g_conntimeout)
                c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=g_cacertfile,
                                    do_handshake_on_connect=False)
                c.settimeout(g_conntimeout)
                c.connect((ip, 443))
                c.settimeout(g_handshaketimeout)
                c.do_handshake()
                cert = c.getpeercert()
                time_end = time.time()
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
                    if domain is None:
                        PRINT("%s can not get commonName: %s " % (ip, subjectitems))
                #尝试发送http请求，获取回应头部的Server字段
                if domain is None or isgoolgledomain(domain) == 2:
                    cur_time = time.time()
                    gwsname = self.getgooglesvrname(c,s,ip)
                    time_end = time.time()
                    costtime += int(time_end * 1000 - cur_time * 1000)
                    if domain is None and len(gwsname) > 0:
                        domain="defaultgws"
                if domain is not None:
                    PRINT("ip: %s,CN: %s,svr: %s" % (ip, domain,gwsname))
                return domain, costtime,timeout,gwsname
        except SSLError as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            if str(e).endswith("timed out"):
                timeout = 1
            else:
                PRINT("SSL Exception(%s): %s, times:%d ms " % (ip, e, costtime))
            return domain, costtime,timeout,gwsname
        except IOError as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            if str(e).endswith("timed out"):
                timeout = 1
            else:
                PRINT("Catch IO Exception(%s): %s, times:%d ms " % (ip, e, costtime))
            return domain, costtime,timeout,gwsname
        except Exception as e:
            time_end = time.time()
            costtime = int(time_end * 1000 - time_begin * 1000)
            PRINT("Catch Exception(%s): %s, times:%d ms " % (ip, e, costtime))
            return domain, costtime,timeout,gwsname
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
            while True:
                infds, outfds, errfds = select.select([sock, ], [], [], g_conntimeout)
                if len(infds) == 0:
                    break
                while True:
                    try:
                        d = conn.read(1024)
                        break
                    except SSLError:
                        time.sleep(0.5)
                        pass
                data = data + d.replace("\r","")
                index = data.find("\n\n")
                if index != -1:
                    gwsname = getgooglesvrnamefromheader(data[0:index])
                    return gwsname
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

    def __init__(self,checkqueue,cacheResult,evt_finish,evt_ready):
        threading.Thread.__init__(self)
        self.queue = checkqueue
        self.cacheResult = cacheResult
        self.evt_finish = evt_finish
        self.evt_ready = evt_ready

    def runJob(self):
        if not self.evt_ready.is_set():
            self.evt_ready.set()
        while not self.evt_finish.is_set() and self.queue.qsize() > 0:
            try:
                addrint = self.queue.get(True,5)
                ipaddr = to_string(addrint)
                self.queue.task_done()
                ssl_obj = my_ssl_wrap()
                (ssldomain, costtime,timeout,gwsname) = ssl_obj.getssldomain(self.getName(), ipaddr)
                if ssldomain is None and timeout == 1:
                    # try again
                    (ssldomain, costtime,timeout,gwsname) = ssl_obj.getssldomain(self.getName(), ipaddr)
                if ssldomain is not None:
                    self.cacheResult.addOKIP(costtime, ipaddr, ssldomain,gwsname)
                elif ssldomain is None:
                    self.cacheResult.addFailIP(ipaddr)
            except Empty:
                break

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
    evt_finish = threading.Event()
    evt_ready = threading.Event()    
    qsize = ipqueue.qsize()
    maxthreads = qsize if qsize < max_threads else max_threads
    PRINT('need create max threads count: %d,total ip cnt: %d ' % (maxthreads, qsize))
    for i in xrange(1, maxthreads + 1):
        ping_thread = Ping(ipqueue,cacheResult,evt_finish,evt_ready)
        ping_thread.setDaemon(True)
        try:
            ping_thread.start()
        except threading.ThreadError as e:
            PRINT('start new thread except: %s,work thread cnt: %d' % (e, Ping.getCount()))
            "can not create new thread"
            break
        threadlist.append(ping_thread)
    evt_ready.wait()
    try:
        time_begin = time.time()
        logtime = time_begin
        count = Ping.getCount()
        lastcount = count
        while count > 0:
            evt_finish.wait(2)
            time_end = time.time()
            queuesize = ipqueue.qsize()
            count = Ping.getCount()
            if lastcount != count or queuesize > 0:
                time_begin = time_end
                lastcount = count
            else:
                if time_end - time_begin > g_handshaketimeout * 3:
                    dumpstacks()
                    break;
                else:
                    time_begin = time_end
            if time_end - logtime > 60:
                PRINT("has thread count:%d,ip total cnt:%d" % (Ping.getCount(),queuesize))
                logtime = time_end
            count = Ping.getCount()
        evt_finish.set()
    except KeyboardInterrupt:
        PRINT("need wait all thread end...")
        evt_finish.set()
    for p in threadlist:
        p.join()
    cacheResult.close()


def callsingleprocess(ipqueue,cacheResult,max_threads):
    PRINT("Start Process")
    checksingleprocess(ipqueue, cacheResult,max_threads)
    PRINT("End Process")
    
def checkmultiprocess(ipqueue,cacheResult):
    if ipqueue.qsize() == 0:
        return
    processlist = []
    "如果ip数小于512，只使用一个子进程，否则则使用指定进程数，每个进程处理平均值的数量ip"
    max_threads = g_maxthreads
    maxprocess = g_useprocess
    if ipqueue.qsize() < g_maxthreads:
        max_threads = ipqueue.qsize()
        maxprocess = 1
    else:
        max_threads = (ipqueue.qsize() + g_useprocess) / g_useprocess
        if max_threads > g_maxthreads:
            max_threads = g_maxthreads
    #multiprocessing.log_to_stderr(logging.DEBUG)
    for i in xrange(0,maxprocess):
        p = Process(target=callsingleprocess,args=(ipqueue,cacheResult,max_threads))
        p.daemon = True
        processlist.append(p)
        p.start()
    
    try:
        for p in processlist:
            p.join()
    except KeyboardInterrupt:
        PRINT("need wait all process end...")
        for p in processlist:
            if p.is_alive():
                p.terminate()  


def list_ping():
    if g_useOpenSSL == 1:
        PRINT("support PyOpenSSL")
    if g_usegevent == 1:
        PRINT("support gevent")
    if g_useprocess > 1:
        PRINT("support multiprocess")

    checkqueue = Queue()
    cacheResult = TCacheResult()
    lastokresult,lasterrorresult = cacheResult.loadLastResult()
    oklen = len(lastokresult)
    errorlen = len(lasterrorresult)
    totalcachelen = oklen + errorlen
    if totalcachelen != 0:
        PRINT("load last result,ok cnt:%d,error cnt: %d" % (oklen,errorlen) )
    "split ip,check ip valid and get ip begin to end"
    iplineslist = re.split("\r|\n", ip_str_list)
    skipokcnt = 0
    skiperrocnt = 0
    orglist = []
    for iplines in iplineslist:
        if len(iplines) == 0 or iplines[0] == '#':
            continue
        ips = re.split(",|\|", iplines)
        for line in ips:
            if len(line) == 0 or line[0] == '#':
                continue
            begin, end = splitip(line)
            if checkipvalid(begin) == 0 or checkipvalid(end) == 0:
                PRINT("ip format is error,line:%s, begin: %s,end: %s" % (line, begin, end))
                sys.exit(1)
            nbegin = from_string(begin)
            nend = from_string(end)
            while nbegin <= nend:
                if totalcachelen != 0:
                    ip = to_string(nbegin)
                    if ip in lastokresult:
                        #PRINT("ip:%s had check ok last" % ip)
                        skipokcnt += 1
                    elif ip in lasterrorresult:
                        #PRINT("ip:%s had check error last" % ip)
                        skiperrocnt += 1
                    else:
                        orglist.append(nbegin)
                else:
                    orglist.append(nbegin)
                nbegin += 1
    
    global g_ramdomipcnt
    orglist_len = len(orglist)
    if g_ramdomipcnt == 0:
        g_ramdomipcnt = orglist_len
    elif g_ramdomipcnt > orglist_len:
        g_ramdomipcnt = orglist_len
    # 生成随机IP队列
    for i in xrange(0,g_ramdomipcnt):
        k = random.randint(i,orglist_len - 1)
        tmp = orglist[k]
        orglist[k] = orglist[i]
        checkqueue.put(tmp)

    if skipokcnt != 0 or skiperrocnt != 0:
        PRINT("skip ok cnt:%d,skip error cnt: %d" % (skipokcnt,skiperrocnt) )

    if checkqueue.qsize() > 0:
        if g_useprocess > 1 and checkqueue.qsize() > g_maxthreads:
            checkmultiprocess(checkqueue,cacheResult)
        else:
            checksingleprocess(checkqueue,cacheResult,g_maxthreads)
    
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
        PRINT("[%s] %d ms,domain: %s,svr:%s" % (ip[1], ip[0], domain,ip[3]))
        if domain is not None:
            ff.write(ip[1])
            ff.write("|")
            ncount += 1
    PRINT("write to file %s ok,count:%d " % (g_ipfile, ncount))
    ff.close()
    cacheResult.clearFile()


if __name__ == '__main__':
    list_ping()
