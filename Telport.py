#coding=utf-8

import re
import os
import IPy
import sys
import socket
import argparse
import telnetlib
import scapy.all
from random import randint
from concurrent.futures import ThreadPoolExecutor

def get_parser():						#获取参数
	parser = argparse.ArgumentParser(description="[+] Telport.py  通过telnet探测端口  使用nmap默认端口服务对应关系  尝试获取端口banner协助判断端口服务")
	parser.add_argument("-t","--targets", help="指定主机ip、域名(支持逗号分隔IP列表、掩码网段)")
	parser.add_argument("-f","--file", help="指定目标主机文件")
	parser.add_argument("-p","--ports", help="指定端口(支持逗号分隔、n-m范围表示) 默认扫描常见端口")
	parser.add_argument("-sn", default=False, action='store_true', help="启用ICMP主机发现")
	parser.add_argument("--pthread", default=200, type=int, help="指定扫描端口的线程数 default 200")
	parser.add_argument("--hthread", default=10, type=int, help="指定扫描主机的线程数 default 10")
	return parser

def get_iplist(formathost):				#处理IP并返回IP地址列表
	iplist = []
	try:
		formathost = socket.gethostbyname(formathost)
		iplist.append(formathost)
		return iplist
	except:
		pass
	try:
		ipobj = IPy.IP(formathost, make_net=True)
		for i in ipobj:
			iplist.append(i.strNormal())
		return iplist	
	except Exception as e:
		#print(e)
		sys.stdout.write("[!] Unable to resolve host %s or Wrong target format\n" % (formathost))
		return False

def get_ipfilelist(filename):			#读取文件返回IP地址列表
	iplist = []
	try:
		with open(filename,'r') as f:
			for line in f.readlines():
				line = line.strip()
				subiplist = get_iplist(line)
				if subiplist:
					iplist += subiplist
			return iplist
	except: 
		print("[!] No such file %s" % (filename))
		return False
	
def get_portlist(ports):				#处理端口并返回端口列表 先分割 判断是否可转换为数字 否则正则匹配n-m格式 否则格式错误
	portlist = []
	for p in ports.split(","):
		try:
			port = int(p)
			if 0 <= port <= 65535:
				portlist.append(port)
			else:
				print("[!] Port %d out of range" % (port))
		except:
			r = re.match("^\d+-\d+$",p)
			if r:
				n = int(p.split("-")[0])
				m = int(p.split("-")[1])
				if 0 <= n <= m <= 65535:
					for port in range(n,m+1):
						portlist.append(port)
				else:
					print("[!] Wrong port range %s" % (p))
			else:
				print("[!] Wrong port format %s" % (p))
	if portlist:			
		return portlist
	return False

def tel_scan(host,port):          		#使用telnet探测端口 返回端口 服务 banner
	try:
		t = telnetlib.Telnet(host, port,timeout=3)
		try:							#试着获取banner 获取不成功会抛出异常 banner设置为空
			banner = t.read_until(b'impossiblestr',timeout=2)
			banner = bytes.decode(banner).strip()
		except:
			banner = ''
		t.close()
		if str(port) in default_services.keys():
			return (str(port),default_services[str(port)],banner)
		else:
			return (str(port),'unknown',banner)
	except Exception as e:
		#print(e)
		#print("[!] %s %d Failed" % (host,port))
		return False
	
def host_scan(host,ports,pthread):		#主机扫描
	sys.stdout.write("[-] Host %s scanning\n" % (host))
	portsinfo = []
	port_executor = ThreadPoolExecutor(max_workers=pthread)
	thpool = []
	for port in ports:
		th = port_executor.submit(tel_scan,host,port)
		thpool.append(th)
	for th in thpool:
		if th.result():
			portsinfo.append(th.result())
	port_executor.shutdown(wait=True)
	if not portsinfo:  				# 如果没有结果
		sys.stdout.write("[!] Don't find %s any open ports\n" % (host))
	else:
		total_result[host] = portsinfo
	sys.stdout.write("[-] Host %s finished\n" % (host))
	return True

def ping_host(host):					#ICMP 主机发现
	for i in range(3):
		id_ip = randint(1,65535)
		id_ping = randint(1,65535)
		seq_ping = randint(1,65535)
		packet = scapy.all.IP(dst=host, ttl=64, id=id_ip)/scapy.all.ICMP(id=id_ping,seq =seq_ping)/b'ICMP ping'
		result = scapy.all.sr1(packet, timeout=2, verbose=False)
		#result.show()
		if result:
			return True
	print("[!] Host %s no respond" % (host))
	return False	
	
def proc_default_service():				#将端口设置为key 相应值为服务
	try:
		with open(os.path.dirname(os.path.realpath(__file__))+"/default/nmap_default_port_services.txt",'r') as f:
			for line in f.readlines():
				line = line.strip().split()
				default_services[line[0]] = line[1]
	except:
		print("[!] Please check default/nmap_default_port_services.txt")

def main():
	global default_services				#默认端口服务 为全局变量 方便访问
	global total_result
	default_services = {}
	total_result = {}
	proc_default_service()
	
	args = get_parser().parse_args()	#获取参数
	
	if not (args.targets or args.file):
		get_parser().print_help()		
		sys.exit(0)

	ports = []
	if args.ports:						#处理-p参数
		portlist = get_portlist(args.ports)
		if portlist:
			ports += portlist
	
	if not ports:                   	#如果未设置端口或者参数端口格式错误 则读取默认端口
		try:
			with open(os.path.dirname(os.path.realpath(__file__))+"/default/default_general_ports.txt",'r') as f:
				for line in f.readlines():
					portlist = get_portlist(line.strip())
					if portlist:
						ports += portlist
			print("[-] Use default ports list")
		except Exception as e:
			#print(e)
			print("[!] Failed to read default ports file")

	targets = []
	if args.targets:  # 处理-t参数
		ipinfo = args.targets.split(",")
		for i in ipinfo:
			iplist = get_iplist(i)
			if iplist:
				targets += iplist

	if args.file:  # 处理-f参数
		iplist = get_ipfilelist(args.file)
		if iplist:
			targets += iplist
	if not (targets and ports):			#目标设置失败则退出
		sys.exit(0)						
	
	targets = list(set(targets))		#去重
	ports = list(set(ports))
	
	pthread = args.pthread if args.pthread <= len(ports) else len(ports) #设置端口扫描线程数
	hthread = args.hthread if args.hthread <= len(targets) else len(targets) #设置主机扫描线程数

#	print(targets)
#	print(ports)
#	print(pthread)
#	print(hthread)
#	print(args.sn)
	host_is_online = True
	host_executor = ThreadPoolExecutor(max_workers=hthread)
	for host in targets:				#多线程对主机扫描
		if args.sn:						#启用主机发现
			host_is_online = ping_host(host)
		if host_is_online:
			host_executor.submit(host_scan,host,ports,pthread)
	host_executor.shutdown(wait=True)

#	print(total_result)
	for key in total_result.keys():
		print("\n[+] Host %s result:\n[+] HOST  PORT  SERVICE  BANNER" % (key))
		for portinfo in total_result[key]:
			print("[+] %s | %s | %s | %s" % (key, portinfo[0], portinfo[1], portinfo[2]))

if __name__ == '__main__':
	main()