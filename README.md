checkgoogleip
=============

主要是用来检查哪些IP可以用在goagent上面

检查方法
1.直接用内置的ssl库连接到该IP,并使用cacert.pem来获取服务器证书
2.检查该 IP是否使用google.com的证书
3.以响应时间排序，时间越少，排序就越前

注意
1.IP的格式请看checkip.py文件说明
2.由于现在只是简单处理 ，因此只有所有IP处理完后才会写文件，因此如果检查IP越多，时间越久，也有可能会失败
3.超时时间可以看g_commtimeout变量，时间为秒
4.最大线程数量限制了512条

使用方法
1.windows
可以放在把checkip.py放在goagent/local目录下面，由于cacert.pem是取自goagent/local目录里面的同名文件，因此不需要复制cacert.pem到该目录，然后在命令行中先切换前该目录，然后执行
python27.exe checkip.py

如果执行成功，会在该目录新建一个ip.txt文件，里面的IP列表就是可用列表

2.linux
把checkip.py与cacert.pem放在同一个目录，然后执行
python  checkip.py 即可

由于开发时主要用python2.7版本，不过好像在python3.4版本也可以执行




