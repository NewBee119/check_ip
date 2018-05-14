# check_ip
check_ip结合开源威胁情报，判断数据包中IP地址或者IP清单中的IP地址恶意性  

### 运行条件
**查询接口**  
AlienVault:https://otx.alienvault.com/api  
需要注册一个账号以得到API_KEY，添加到hot_ip.py开头的对应字段  
```  
url = 'http://ip.taobao.com/service/getIpInfo.php?ip='  
API_KEY = ''  #add API_key  
OTX_SERVER = 'https://otx.alienvault.com/'  
```   

**程序依赖包**  
pip install OTXv2  pandas dpkt  

### 运行事例 
usage: hot_ip.py --pcapfile=./out.pcap –d -c  #数据包解析模式，对目的IP地址的恶意性进行排查  
usage: hot_ip.py --IPfile=./iplist.txt -c     #IP清单文件解析模式，排查清单中的IP地址的恶意性  
![Image test](https://github.com/scu-igroup/check_ip/blob/master/image/run.png)   

### 其他项 
**中间文件**   
```   
out_IP.tx              #解析网络数据包时产生，源/目的IP列表  
ip_location.txt        #解析IP地址地理信息  
malicious_results.txt  #可疑IP地址信息  
```  
**查看结果**  
```  
f117@ubuntu:~/Downloads/IP-location$ cat malicious_results.txt  
  117.18.237.29   potentially malicious   台湾-台湾-台北   https://otx.alienvault.com/indicator/ip/117.18.237.29  
  52.230.80.159   potentially malicious   新加坡-XX-XX   https://otx.alienvault.com/indicator/ip/52.230.80.159  
  40.77.226.249   potentially malicious   爱尔兰-Dublin-XX   https://otx.alienvault.com/indicator/ip/40.77.226.249  
```  


