checkgoogleip
=============

主要是用来检查哪些IP可以用在goagent上面

检查方法
-------------
* 直接用内置的ssl库连接到该IP,并使用cacert.pem来获取服务器证书
* 检查该 IP是否使用google.com的证书
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
* 由于现在只是简单处理 ，因此只有所有IP处理完后才会写文件，因此如果检查IP越多，时间越久，也有可能会失败
* 超时时间可以看g_commtimeout变量，时间为秒
* 最大线程数量限制了512条 + 每组IP的IP数量

使用方法
-------------
### windows
  可以放在把checkip.py与checkip.bat放在goagent/local目录下面，由于cacert.pem是取自goagent/local目录里面的同名文件，因此不需要复制cacert.pem到该目录，然后执行checkip.bat  
  如果执行成功，会在该目录新建一个ip.txt文件，里面的IP列表就是可用列表

### linux
  把checkip.py与cacert.pem放在同一个目录，然后执行
  python  checkip.py 即可


由于开发时主要用python2.7版本，不过好像在python3.4版本也可以执行
