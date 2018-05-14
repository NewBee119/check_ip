# check_ip
check_IP is to judge whether a IP is malicious based on open threat intelligence

### requirements 
开源威胁情报平台AlienVault查询接口：   
AlienVault:https://otx.alienvault.com/api  
需要注册一个账号以得到API_KEY  
程序依赖包：    
pip install OTXv2  pandas dpkt  

### How to run  
usage: hot_ip.py --pcapfile=./out.pcap –d -c  #数据包解析模式，对目的IP地址的恶意性进行排查  
usage: hot_ip.py --IPfile=./iplist.txt -c     #IP清单文件解析模式，排查清单中的IP地址的恶意性  
![Image test](https://github.com/scu-igroup/check_ip/blob/master/image/run.png)   

### other things  
会生成几个中间文件：  
out_IP.txt             #解析网络数据包时产生，源/目的IP列表  
ip_location.txt        #解析IP地址地理信息  
malicious_results.txt  #可疑IP地址信息


