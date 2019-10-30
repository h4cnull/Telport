### Telport.py

```shell
python3 -m pip install IPy scapy

python3 Telport.py
usage: Telport.py [-h] [-t TARGETS] [-f FILE] [-p PORTS] [-sn]
                  [--pthread PTHREAD] [--hthread HTHREAD]

[+] Telport.py 通过telnet探测端口 使用nmap默认端口服务对应关系 尝试获取端口banner协助判断端口服务

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        指定主机ip、域名(支持逗号分隔IP列表、掩码网段)
  -f FILE, --file FILE  指定目标主机文件
  -p PORTS, --ports PORTS
                        指定端口(支持逗号分隔、n-m范围表示) 默认扫描常见端口
  -sn                   启用ICMP主机发现
  --pthread PTHREAD     指定扫描端口的线程数 default 200
  --hthread HTHREAD     指定扫描主机的线程数 default 10
```