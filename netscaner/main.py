from scapy.all import *
import requests
import tkinter as tk
from tkinter import filedialog

services = {
    7: 'Echo',
    19: 'CHARGEN',
    20: 'FTP-data',
    21: 'FTP',
    22: 'SSH/SCP/SFTP',
    23: 'Telnet',
    25: 'SMTP',
    42: 'WINS Replication',
    43: 'WHOIS',
    49: 'TACACS',
    53: 'DNS',
    70: 'Gopher',
    79: 'Finger',
    80: 'HTTP',
    88: 'Kerberos',
    102: 'Microsoft Exchange ISO-TSAP',
    110: 'POP3',
    113: 'Ident',
    119: 'NNTP (Usenet)',
    135: 'Microsoft RPC EPMAP',
    137: 'NetBIOS-ns',
    138: 'NetBIOS-dgm',
    139: 'NetBIOS-ssn',
    143: 'IMAP',
    161: 'SNMP-agents (unencrypted)',
    162: 'SNMP-trap (unencrypted)',
    177: 'XDMCP',
    179: 'BGP',
    194: 'IRC',
    201: 'AppleTalk',
    264: 'BGMP',
    318: 'TSP',
    381: 'HP Openview',
    383: 'HP Openview',
    389: 'LDAP',
    411: '(Multiple uses)',
    412: '(Multiple uses)',
    427: 'SLP',
    443: 'HTTPS (HTTP over SSL)',
    445: 'Microsoft DS SMB',
    464: 'Kerberos',
    465: 'SMTP over TLS/SSL, SSM',
    497: 'Dantz Retrospect',
    500: 'IPSec / ISAKMP / IKE',
    512: 'rexec',
    513: 'rlogin',
    514: 'syslog',
    515: 'LPD/LPR',
    520: 'RIP',
    521: 'RIPng (IPv6)',
    540: 'UUCP',
    548: 'AFP',
    554: 'RTSP',
    546: 'DHCPv6',
    547: 'DHCPv6',
    560: 'rmonitor',
    563: 'NNTP over TLS/SSL',
    587: 'SMTP',
    591: 'FileMaker',
    593: 'Microsoft DCOM',
    596: 'SMSD',
    631: 'IPP',
    636: 'LDAP over TLS/SSL',
    639: 'MSDP (PIM)',
    646: 'LDP (MPLS)',
    691: 'Microsoft Exchange',
    860: 'iSCSI',
    873: 'rsync',
    902: 'VMware Server',
    989: 'FTPS',
    990: 'FTPS',
    993: 'IMAP over SSL (IMAPS)',
    995: 'POP3 over SSL (POP3S)'
}


def port_scan(target: list[str], ports: list[int] = list(services.keys())):
    results = {}
    for ip in target:
        for port in ports:
            response = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            if response is not None:
                if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
                    # Ответ SYN-ACK, порт открыт
                    results[(ip, port)] = 'Open'
                elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
                    # Ответ RST, порт закрыт
                    results[(ip, port)] = 'Closed'
            else:
                # Нет ответа, порт фильтруется
                results[(ip, port)] = 'Filtered'
    return results


def is_server_available(ip):
    response = sr(IP(dst=ip)/ICMP(), timeout=1, verbose=0)
    if response:
        return True
    return False


def detect_services(port_results):
    service_info = {}
    for target, status in port_results.items():
        ip, port = target[0], target[1]
        if ip not in service_info:
            service_info[ip] = []

        if status == 'Open':
            if port in services:
                service_info[ip].append(services[port])
            else:
                service_info[ip].append(str(port))
    return service_info


def get_mac_address(ip_address):
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=False)[0]
    if result:
        for sent, received in result:
            mac_address = received.hwsrc
            return mac_address

    return "N/A"


def get_host_information(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        data = response.json()
        return {
            'IP Address': data['query'],
            'ISP': data['isp'],
            'Country': data['country'],
            'Region': data['regionName'],
            'City': data['city'],
            'MAC Address': get_mac_address(ip_address),
        }
    except Exception as e:
        return {
            'IP Address': ip_address,
            'ISP': 'N/A',
            'Country': 'N/A',
            'Region': 'N/A',
            'City': 'N/A',
            'MAC Address': 'N/A',
        }


def get_info(ips, ports, is_save=True, filename="info.log"):
    services = detect_services(port_scan(ips, ports))
    host_infos = [get_host_information(ip) for ip in ips]
    result = f'''Available servers: {len(host_infos)}
----------'''
    for i in range(len(host_infos)):
        ser = "\n".join(services[host_infos[i]["IP Address"]])
        result += f'''
IP Address: {host_infos[i]["IP Address"]}
IPS: {host_infos[i]["ISP"]}
Country: {host_infos[i]["Country"]}
Region: {host_infos[i]["Region"]}
City: {host_infos[i]["City"]}
MAC: {host_infos[i]["MAC Address"]}
Available services: {len(services[host_infos[i]["IP Address"]])}
{ser}
-----------'''
    if is_save:
        with open(filename, 'w') as f:
            f.write(result)

    return result



def interface_get_ips(in_ips):
    res = []
    for ip in in_ips.split(','):
        ip_spl = [i.strip() for i in ip.split('.')]
        if len(ip_spl) == 4:
            if ip_spl[-1].startswith('*'):
                start, stop = [int(i) for i in ip_spl[-1][2:-1].split('-')]
                for i in range(start, stop+1):
                    res.append(".".join(ip_spl[:3] + [str(i)]))
            else:
                res.append(".".join(ip_spl))
    return res

                
def interface_get_ports(in_ports):
    res = []
    for port in in_ports.split(","):
        res.append(int(port.strip()))
    return res


def check_ip_addresses():
    if input_ip.get():
        ips = interface_get_ips(input_ip.get())
    else:
        file_path = filedialog.askopenfilename()
        with open(file_path, 'r') as f:
            ips = interface_get_ips(f.read())
    if input_port.get():
        ports = interface_get_ports(input_port.get())
    else:
        ports = list(services.keys())

    avail_servers = list(filter(lambda ip: is_server_available(ip), ips))

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, get_info(avail_servers, ports))


if __name__ == "__main__":
    root = tk.Tk()
    root.title("IP Address Checker")

    ip_lab = tk.Label(root, text="Поле ip").pack()
    input_ip = tk.Entry(root)
    input_ip.pack()
    port_lab = tk.Label(root, text="Поле port").pack()
    input_port = tk.Entry(root)
    input_port.pack()

    check_button = tk.Button(root, text="Проверить", command=check_ip_addresses).pack()

    result_text = tk.Text(root, height=10, width=30)
    result_text.pack()

    root.mainloop()
