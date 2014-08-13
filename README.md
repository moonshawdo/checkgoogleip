checkgoogleip
=============

主要是用来检查哪些IP可以用在goagent上面

检查方法
-------------
* 默认使用内置的ssl库连接到该IP,并使用cacert.pem来获取服务器证书，可以通过修改变量来支持pyOpenSSL库获取服务器证书，
* 检查该 IP是否使用google.com的证书,如果不是该域名，则发送http请求，然后检查回应头部的Server是否为gws
* 以响应时间排序，时间越少，排序就越前

注意
-------------
* IP组的格式  
  1.xxx.xxx.xxx.xxx-xx.xxx.xxx.xxx  
    如218.253.0.80-218.253.0.90  
  2.xxx.xxx.xxx.xxx/xx  
    如218.253.0.80/24  
  3.xxx.xxx.xxx.  
    如218.253.0.  
  4.xxx.xxx.xxx.xxx  
    如218.253.0.80  
组与组之间可以用换行、'|'或','相隔开
* connect超时时间可以看g_commtimeout变量，时间为5秒，握手超时请看g_handshaketimeout，时间为7秒
* 默认会尝试使用gevent及内置的ssl库查询，好处：明显优化cpu及内存使用，最大线程数量限制了128条，可以支持pyOpenSSL库，但需要设置g_usegevent为0
* 默认增加一些IP段检查，并且只随机检查700个IP 
* 默认会保存测试IP的结果到ip_tmperror.txt（失败）与ip_tmpok.txt（成功），下次运行脚本时会预先读取，并会跳过这些IP的查询，如果不想保留ip_tmperror.txt，则g_autodeltmperrorfile为1，如果不想保留ip_tmpok.txt，则需要设置g_autodeltmpokfile=1，如果程序正常运行结束，则会检查g_autodeltmperrorfile及g_autodeltmpokfile，并执行对应的操作，如果程序运行异常，需要关闭程序，则会保留这两个文件
* 增加gogotest里面的部分IP列表，特别感谢该开发者

使用方法
-------------
### windows
  可以放在把checkip.py与checkip.bat放在goagent/local目录下面，由于cacert.pem是取自goagent/local目录里面的同名文件，因此不需要复制cacert.pem到该目录，然后执行checkip.bat  
  如果执行成功，会在该目录新建一个ip.txt文件，里面的IP列表就是可用列表,ip_tmperror.txt会保留查询失败的IP，ip_tmpok.txt会保留查询成功的IP

### linux
  把checkip.py与cacert.pem放在同一个目录，然后执行
  python  checkip.py 即可


由于开发时主要用python2.7版本，暂时不支持python3版本



更新说明
-------------
### 2014.08.13
  * 支持只保留小于最大延时的IP，支持只获取指定数量的IP列表

### 2014.06.27
  * 优化查询可用IP，支持随机查询IP

### 2014.06.13
  * 使用两个临时文件来记录程序运行过程中查询成功与失败的IP地址，方便下次使用
  * 支持gevent,但只能在关闭pyOpenSSL库时使用
  * 支持多进程方式，在pyOpenSSL库下默认使用，在gevent下禁用
  
### 2014.06.07
  * 优化线程队列的使用  
  * 默认会尝试使用pyOpenSSL库，支持高并发量，并且有效地优化cpu及内存使用，程序在启动时cpu较高，几秒后会降下来
  * 设置默认线程的stack大小，减少内存消耗
  
### 2014.06.06
  * 使用队列来控制线程数量，默认改为256条线程，测试发现超过378条线程时，在windows中出现部分线程加载证书出错  
  * g_ssldomain 使用元组类型，检查多种域名的证书  

