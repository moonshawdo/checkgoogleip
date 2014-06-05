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

if sys.version_info[0] == 3:
    from queue import Queue,Empty
    try:
        from functools import reduce
    finally:
        pass
    try:
        xrange
    except NameError:
        xrange = range
else:
    from Queue import Queue,Empty
import time
"""
ip_str_list为需要查找的IP地址，第一组的格式：
1.xxx.xxx.xxx.xxx-xx.xxx.xxx.xxx
2.xxx.xxx.xxx.xxx/xx
3.xxx.xxx.xxx.
4 xxx.xxx.xxx.xxx

组与组之间可以用换行、'|'或','相隔开
"""
ip_str_list = '''
218.253.0.80-218.253.0.90
'''

ip_list = []
g_lock = threading.Lock()

log_lock = threading.Lock()

"连接超时设置"
g_commtimeout = 7

g_filedir = os.path.dirname(__file__)
g_cacertfile = os.path.join(g_filedir, "cacert.pem")
g_ipfile = os.path.join(g_filedir, "ip.txt")
g_ssldomain = ("google.com", "google.pk","google.co.uk")
g_maxthreads = 256
g_queue = Queue()
g_finish = threading.Event()
g_ready = threading.Event()


def PRINT(strlog):
    try:
        log_lock.acquire()
        print(strlog)
    finally:
        log_lock.release()


def testipchain(threadname, ip):
    time_begin = time.time()
    try:
        costtime = 0
        s = socket.socket()
        s.settimeout(g_commtimeout)
        "需要指定证书文件，这样才可以在握手中获取对方服务器证书信息"
        c = ssl.wrap_socket(s, cert_reqs=ssl.CERT_REQUIRED, ca_certs=g_cacertfile)
        c.settimeout(g_commtimeout)
        PRINT("[%s]try connect to %s " % (threadname, ip))
        c.connect((ip, 443))
        cert = c.getpeercert()
        time_end = time.time()
        costtime = int(time_end * 1000 - time_begin * 1000)
        '''cert format:
        {'notAfter': 'Aug 20 00:00:00 2014 GMT', 'subjectAltName': (('DNS', 'google.com'),
          ('DNS', 'youtubeeducation.com')),
          'subject': ((('countryName', u'US'),), (('stateOrProvinceName', u'California'),),
          (('localityName', u'Mountain View'),), (('organizationName', u'Google Inc'),),
          (('commonName', u'google.com'),))
        }'''
        if 'subject' in cert:
            subjectitems = cert['subject']
            for mysets in subjectitems:
                for item in mysets:
                    if item[0] == "commonName":
                        if not isinstance(item[1], str):
                            domain = item[1].encode("utf-8")
                        else:
                            domain = item[1]
                        PRINT("[%s]ip: %s,CN: %s " % (threadname, ip, domain))
                        return domain, costtime
            PRINT("[%s]%s can not get commonName: %s " % (threadname, ip, subjectitems))
        else:
            PRINT("[%s]%s can not get subject: %s " % (threadname, ip, cert))
        c.shutdown()
        s.close()
        return None, costtime
    except ssl.SSLError as e:
        time_end = time.time()
        costtime = int(time_end * 1000 - time_begin * 1000)
        PRINT("[%s]SSL Exception(%s): %s, times:%d ms " % (threadname, ip, e, costtime))
        return None, costtime
    except IOError as e:
        time_end = time.time()
        costtime = int(time_end * 1000 - time_begin * 1000)
        PRINT("[%s]Catch IO Exception(%s): %s, times:%d ms " % (threadname, ip, e, costtime))
        return None, costtime


class Ping(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        while not g_ready.is_set():
            g_ready.wait(5)
        while not g_finish.is_set():
            try:
                ipaddr = g_queue.get(True, 2)
                (ssldomain, costtime) = testipchain(self.getName(), ipaddr)
                if ssldomain is not None and ssldomain.lower() in g_ssldomain:
                    try:
                        g_lock.acquire()
                        ip_list.append((costtime, ipaddr, ssldomain))
                    finally:
                        g_lock.release()
                g_queue.task_done()
            except Empty:
                pass
            "for thread yield"
            time.sleep(0.0001)


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


def list_ping():
    threadlist = []
    iprangelist = []
    "split ip,check ip valid and get ip begin to end"
    iplineslist = re.split("\r|\n", ip_str_list)
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
                g_queue.put(to_string(nbegin))
                nbegin += 1

    qsize = g_queue.qsize()
    maxthreads = qsize if qsize < g_maxthreads else g_maxthreads
    PRINT('need create max threads count: %d,total ip cnt: %d ' % (maxthreads, qsize) )
    for i in xrange(1, maxthreads + 1):
        ping_thread = Ping()
        ping_thread.setDaemon(True)
        try:
            ping_thread.start()
        except threading.ThreadError as e:
            PRINT('start new thread except: %s  ' % (e))
            "can not create new thread"
            break
        threadlist.append(ping_thread)
    g_ready.set()
    try:
        while g_queue.unfinished_tasks != 0:
            g_finish.wait(1)
    except KeyboardInterrupt:
        g_finish.set()
        raise
    g_finish.set()

    for thread in threadlist:
        thread.join()

    ip_list.sort()

    PRINT('try to collect ssl result')
    op = 'wb'
    if sys.version_info[0] == 3:
        op = 'w'
    ff = open(g_ipfile, op)
    ncount = 0
    for ip in ip_list:
        domain = ip[2]
        PRINT("[%s] %d ms,domain: %s" % (ip[1], ip[0], domain))
        if domain is not None:
            ff.write(ip[1])
            ff.write("|")
            ncount += 1
    PRINT("write to file %s ok,count:%d " % (g_ipfile, ncount))
    ff.close()


if __name__ == '__main__':
    list_ping()
