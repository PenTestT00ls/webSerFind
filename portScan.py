#!/usr/bin/env python3
"""
增强版端口扫描脚本 - 自动HTTP探测
自动探测所有开放端口的Web服务并提取网页标题
"""

import socket
import sys
import argparse
import time
from datetime import datetime
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
from bs4 import BeautifulSoup
import re

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 常见的HTTP端口列表
COMMON_HTTP_PORTS = {80, 443, 8080, 8000, 3000, 8888, 8443, 8081, 8090, 9000, 5000, 5001}
DEFAULT_PORTS = "80,443,8080,8000,3000,8888,9000,5000,8081,8090,5010,5011,8091,8085,8099,8778,8891,28001,28002,28003,28004,50078,60080,60081"

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='自动HTTP探测端口扫描器',
        usage='%(prog)s target [-p PORTS] [-t THREADS] [-o OUTPUT]',
        epilog='示例: portscan.py 39.153.159.91 -p 1-1000 -t 100 -o web_results.txt'
    )
    
    parser.add_argument('target', help='目标IP地址或域名')
    parser.add_argument('-p', '--ports', default=DEFAULT_PORTS, 
                       help=f'端口范围 (默认: {DEFAULT_PORTS})')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='扫描线程数 (默认: 50)')
    parser.add_argument('-T', '--threads-http', type=int, default=20,
                       help='HTTP探测线程数 (默认: 20)')
    parser.add_argument('-o', '--output', help='输出结果到文件')
    parser.add_argument('--timeout-scan', type=float, default=2.0,
                       help='端口扫描超时时间(秒) (默认: 2.0)')
    parser.add_argument('--timeout-http', type=float, default=5.0,
                       help='HTTP请求超时时间(秒) (默认: 5.0)')
    parser.add_argument('--no-verify', action='store_true',
                       help='不验证SSL证书 (默认不验证)')
    parser.add_argument('--force-http', action='store_true',
                       help='强制对所有端口进行HTTP探测')
    parser.add_argument('--show-all', action='store_true',
                       help='显示所有端口，包括非HTTP服务')
    
    return parser.parse_args()

def parse_port_range(port_range):
    """解析端口范围字符串"""
    try:
        if ',' in port_range:
            ports = set()
            parts = port_range.split(',')
            for part in parts:
                if '-' in part:
                    start, end = part.split('-')
                    ports.update(range(int(start), int(end) + 1))
                else:
                    ports.add(int(part))
            return sorted(ports)
        elif '-' in port_range:
            start, end = port_range.split('-')
            return list(range(int(start), int(end) + 1))
        else:
            return [int(port_range)]
    except ValueError:
        print("错误: 端口格式无效")
        sys.exit(1)

def resolve_hostname(hostname):
    """解析主机名获取IP地址"""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"错误: 无法解析主机名 '{hostname}'")
        sys.exit(1)

def tcp_connect_scan(target_ip, port, timeout):
    """TCP连接扫描端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()
        return result == 0
    except socket.error:
        return False

def extract_title_from_html(html_content):
    """从HTML内容中提取标题"""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        title = soup.title.string
        if title:
            title = title.strip()
            # 清理标题中的多余空白和换行
            title = re.sub(r'\s+', ' ', title)
            return title[:200]  # 限制标题长度
    except:
        pass
    
    # 如果BeautifulSoup失败，尝试正则表达式
    try:
        match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        if match:
            title = match.group(1).strip()
            title = re.sub(r'\s+', ' ', title)
            return title[:200]
    except:
        pass
    
    return "No Title"

def probe_http_service(target_ip, port, timeout, verify_ssl=False, force_all=False):
    """探测HTTP/HTTPS服务并获取详细信息"""
    results = []
    
    # 定义要尝试的协议
    protocols = [
        ('http', 80, 8080, 8000, 3000, 8888, 8081, 8090, 5000, 5001, 5010, 5011, 8091, 8085, 8099, 8778, 8891, 9000, 28001, 28002, 28003, 28004, 50078, 60080, 60081),
        ('https', 443, 8443)
    ]
    
    for protocol, *common_ports in protocols:
        # 如果不是常见HTTP端口且没有强制扫描，跳过
        if not force_all and port not in common_ports and protocol == 'http':
            if port not in COMMON_HTTP_PORTS:
                continue
        
        url = f"{protocol}://{target_ip}:{port}"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Upgrade-Insecure-Requests': '1'
            }
            
            response = requests.get(
                url,
                timeout=timeout,
                verify=verify_ssl,
                headers=headers,
                allow_redirects=True
            )
            
            # 获取服务器信息
            server = response.headers.get('Server', 'Unknown')
            content_type = response.headers.get('Content-Type', 'Unknown')
            status_code = response.status_code
            
            # 提取标题
            title = "No Title"
            if 'text/html' in content_type.lower():
                try:
                    title = extract_title_from_html(response.text)
                except:
                    pass
            
            # 尝试获取响应长度
            content_length = len(response.content) if response.content else 0
            
            result = {
                'url': url,
                'protocol': protocol,
                'port': port,
                'status_code': status_code,
                'title': title,
                'server': server,
                'content_type': content_type.split(';')[0],  # 只取主类型
                'content_length': content_length,
                'is_web_service': True
            }
            results.append(result)
            
        except requests.exceptions.SSLError:
            # SSL错误，可能是自签名证书，尝试HTTP
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.TooManyRedirects:
            continue
        except requests.exceptions.RequestException as e:
            continue
    
    return results

def get_service_name(port):
    """获取端口对应的服务名称"""
    try:
        return socket.getservbyport(port, 'tcp')
    except:
        return "unknown"

def port_scan_worker(target_ip, port, timeout):
    """端口扫描工作线程"""
    if tcp_connect_scan(target_ip, port, timeout):
        service = get_service_name(port)
        return {'port': port, 'service': service, 'open': True}
    return {'port': port, 'service': 'unknown', 'open': False}

def scan_ports(target_ip, ports, thread_count, timeout):
    """多线程端口扫描"""
    open_ports = []
    print(f"[*] 开始端口扫描 ({len(ports)} 个端口)...")
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_to_port = {
            executor.submit(port_scan_worker, target_ip, port, timeout): port 
            for port in ports
        }
        
        completed = 0
        for future in as_completed(future_to_port):
            try:
                result = future.result(timeout=timeout+1)
                if result['open']:
                    open_ports.append(result)
                    print(f"[+] 发现开放端口: {target_ip}:{result['port']} ({result['service']})")
            except Exception as e:
                pass
            
            completed += 1
            if completed % 10 == 0:
                sys.stdout.write(f"\r[*] 扫描进度: {completed}/{len(ports)}")
                sys.stdout.flush()
    
    print(f"\n[*] 端口扫描完成，发现 {len(open_ports)} 个开放端口")
    return open_ports

def http_probe_worker(target_ip, port_info, timeout, verify_ssl, force_all):
    """HTTP探测工作线程"""
    http_results = []
    
    # 对每个开放端口进行HTTP探测
    port = port_info['port']
    results = probe_http_service(target_ip, port, timeout, verify_ssl, force_all)
    
    if results:
        for result in results:
            http_results.append(result)
    else:
        # 如果没有HTTP服务，返回端口信息
        http_results.append({
            'url': f"http://{target_ip}:{port}",
            'protocol': 'unknown',
            'port': port,
            'status_code': 0,
            'title': 'No HTTP Service',
            'server': 'Unknown',
            'content_type': 'Unknown',
            'content_length': 0,
            'is_web_service': False,
            'original_service': port_info['service']
        })
    
    return http_results

def probe_http_services(target_ip, open_ports, thread_count, timeout, verify_ssl, force_all):
    """多线程HTTP服务探测"""
    print(f"\n[*] 开始HTTP服务探测 ({len(open_ports)} 个端口)...")
    
    all_http_results = []
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_to_port = {
            executor.submit(http_probe_worker, target_ip, port_info, timeout, verify_ssl, force_all): port_info
            for port_info in open_ports
        }
        
        completed = 0
        for future in as_completed(future_to_port):
            try:
                results = future.result(timeout=timeout+2)
                for result in results:
                    if result.get('is_web_service', False):
                        all_http_results.append(result)
                        print(f"[HTTP] {result['url']} - 状态: {result['status_code']} - 标题: {result['title']}")
            except Exception as e:
                pass
            
            completed += 1
            if completed % 5 == 0:
                sys.stdout.write(f"\r[*] HTTP探测进度: {completed}/{len(open_ports)}")
                sys.stdout.flush()
    
    print(f"\n[*] HTTP服务探测完成")
    return all_http_results

def display_results(target_ip, open_ports, http_results, show_all=False):
    """显示扫描结果"""
    print("\n" + "="*100)
    print("扫描结果汇总")
    print("="*100)
    
    web_services = [r for r in http_results if r.get('is_web_service', False)]
    non_web_ports = [p for p in open_ports if p['port'] not in [r['port'] for r in web_services]]
    
    # 显示Web服务
    if web_services:
        print("\n[Web服务发现]")
        print("-" * 100)
        for result in web_services:
            print(f"🔗 {result['url']}")
            print(f"   ├─ 状态: {result['status_code']} | 协议: {result['protocol']} | 端口: {result['port']}")
            print(f"   ├─ 标题: {result['title']}")
            print(f"   ├─ 服务器: {result['server']}")
            print(f"   ├─ 类型: {result['content_type']}")
            print(f"   └─ 大小: {result.get('content_length', 0):,} 字节")
            print()
    
    # 显示非Web服务的开放端口
    if show_all and non_web_ports:
        print("\n[非Web服务端口]")
        print("-" * 100)
        for port_info in non_web_ports:
            url = f"http://{target_ip}:{port_info['port']}"
            print(f"🔌 {url} ({port_info['service']}) - 无HTTP响应")
        print()
    
    # 显示统计信息
    print("="*100)
    print(f"统计信息:")
    print(f"  📡 开放端口总数: {len(open_ports)} 个")
    print(f"  🌐 Web服务发现: {len(web_services)} 个")
    print(f"  ⚓ 非Web服务端口: {len(non_web_ports)} 个")
    print("="*100)
    
    return len(open_ports), len(web_services), len(non_web_ports)

def save_results(target_ip, open_ports, http_results, filename, show_all=False):
    """保存结果到文件"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"HTTP服务探测扫描报告\n")
            f.write(f"目标: {target_ip}\n")
            f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            web_services = [r for r in http_results if r.get('is_web_service', False)]
            
            if web_services:
                f.write("[Web服务列表]\n")
                f.write("-"*80 + "\n")
                for result in web_services:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"状态码: {result['status_code']}\n")
                    f.write(f"协议: {result['protocol']} | 端口: {result['port']}\n")
                    f.write(f"标题: {result['title']}\n")
                    f.write(f"服务器: {result['server']}\n")
                    f.write(f"内容类型: {result['content_type']}\n")
                    f.write(f"内容长度: {result.get('content_length', 0):,} 字节\n")
                    f.write("-"*40 + "\n")
            
            if show_all:
                non_web_ports = [p for p in open_ports if p['port'] not in [r['port'] for r in web_services]]
                if non_web_ports:
                    f.write("\n[非Web服务端口]\n")
                    f.write("-"*80 + "\n")
                    for port_info in non_web_ports:
                        f.write(f"{target_ip}:{port_info['port']} ({port_info['service']})\n")
            
            f.write(f"\n[统计信息]\n")
            f.write(f"开放端口总数: {len(open_ports)} 个\n")
            f.write(f"Web服务发现: {len(web_services)} 个\n")
            f.write(f"扫描完成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        print(f"\n[✓] 结果已保存到: {filename}")
    except Exception as e:
        print(f"[!] 错误: 无法保存文件 - {e}")

def main():
    """主函数"""
    signal.signal(signal.SIGINT, lambda s, f: (print("\n[!] 扫描被用户中断"), sys.exit(0)))
    
    # 解析参数
    args = parse_arguments()
    
    # 解析目标主机
    target_ip = resolve_hostname(args.target)
    print(f"[*] 目标: {args.target} ({target_ip})")
    
    # 解析端口范围
    ports_to_scan = parse_port_range(args.ports)
    print(f"[*] 扫描端口: {len(ports_to_scan)} 个")
    print(f"[*] 端口扫描线程: {args.threads}")
    print(f"[*] HTTP探测线程: {args.threads_http}")
    print(f"[*] 强制HTTP探测: {'是' if args.force_http else '否'}")
    print(f"[*] SSL证书验证: {'启用' if not args.no_verify else '禁用'}")
    
    start_time = time.time()
    
    # 第一阶段：端口扫描
    open_ports = scan_ports(target_ip, ports_to_scan, args.threads, args.timeout_scan)
    
    if not open_ports:
        print("[!] 未发现开放端口")
        return
    
    # 第二阶段：HTTP服务探测
    http_results = probe_http_services(
        target_ip, 
        open_ports, 
        args.threads_http, 
        args.timeout_http, 
        not args.no_verify,
        args.force_http
    )
    
    # 显示结果
    open_count, web_count, non_web_count = display_results(target_ip, open_ports, http_results, args.show_all)
    
    # 计算扫描时间
    scan_duration = time.time() - start_time
    print(f"[*] 总耗时: {scan_duration:.2f} 秒")
    
    # 保存结果
    if args.output:
        save_results(target_ip, open_ports, http_results, args.output, args.show_all)
    
    # 生成可点击的链接
    print(f"\n[🔗 Web服务链接列表]")
    for result in http_results:
        if result.get('is_web_service', False):
            print(f"  {result['url']}")

if __name__ == "__main__":
    # 检查依赖
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError as e:
        print(f"[!] 缺少依赖包: {e}")
        print(f"[!] 请运行: pip install requests beautifulsoup4")
        sys.exit(1)
    
    main()
