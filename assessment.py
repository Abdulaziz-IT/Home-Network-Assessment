#!/bin/bin/python
import scapy.layers.http
import scapy.layers.tls
from scapy.all import *
import socket
import os
import time
import re
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from datetime import datetime
from colorama import init, Fore


def protocol_statistics(pcap):
    pcap_length = len(pcap)
    global dns, http, https, smtp, telnet, ftp, ssh, icmp, dhcp, ntp, smb, unknown, protocols_stats_array, protocols_labels
    dns = 0
    http = 0
    https = 0
    smtp = 0
    telnet = 0
    ftp = 0
    ssh = 0
    icmp = 0
    dhcp = 0
    ntp = 0
    smb = 0
    unknown = 0
    for pkt in pcap:
        if detect_protocol(pkt) == 'FTP':
            ftp += 1
        elif detect_protocol(pkt) == 'HTTP':
            http += 1
        elif detect_protocol(pkt) == 'HTTPS':
            https += 1
        elif detect_protocol(pkt) == 'SMB':
            smb += 1
        elif detect_protocol(pkt) == 'SSH':
            ssh += 1
        elif detect_protocol(pkt) == 'TELNET':
            telnet += 1
        elif detect_protocol(pkt) == 'SMTP':
            smtp += 1
        elif detect_protocol(pkt) == 'DNS':
            dns += 1
        elif detect_protocol(pkt) == 'DHCP':
            dhcp += 1
        elif detect_protocol(pkt) == 'NTP':
            ntp += 1
        elif detect_protocol(pkt) == 'ICMP':
            icmp += 1
        elif detect_protocol(pkt) == 'UNKNOWN':
            unknown += 1

    http = round((http / pcap_length) * 100, 2)
    https = round((https / pcap_length) * 100, 2)
    smb = round((smb / pcap_length) * 100, 2)
    ssh = round((ssh / pcap_length) * 100, 2)
    telnet = round((telnet / pcap_length) * 100, 2)
    ftp = round((ftp / pcap_length) * 100, 2)
    smtp = round((smtp / pcap_length) * 100, 2)
    dns = round((dns / pcap_length) * 100, 2)
    dhcp = round((dhcp / pcap_length) * 100, 2)
    ntp = round((ntp / pcap_length) * 100, 2)
    icmp = round((icmp / pcap_length) * 100, 2)
    unknown = round((unknown / pcap_length) * 100, 2)

    protocols_stats_array = [dns, http, https, smtp, telnet, ftp, ssh, icmp, dhcp, ntp, smb, unknown]
    protocols_labels = ['DNS', 'HTTP', 'HTTPS', 'SMTP', 'TELNET', 'FTP', 'SSH', 'ICMP', 'DHCP', 'NTP', 'SMB', 'Others']
    if dns == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('DNS')
    if http == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('HTTP')
    if https == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('HTTPS')
    if smtp == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('SMTP')
    if telnet == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('TELNET')
    if ftp == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('FTP')
    if ssh == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('SSH')
    if icmp == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('ICMP')
    if dhcp == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('DHCP')
    if ntp == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('NTP')
    if smb == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('SMB')
    if unknown == 0:
        protocols_stats_array.remove(0)
        protocols_labels.remove('Others')

    print("Protocol Statistics:")
    print("HTTP:", str(http) + "%")
    print("HTTPS:", str(https) + "%")
    print("SMB:", str(smb) + "%")
    print("SSH:", str(ssh) + "%")
    print("TELNET:", str(telnet) + "%")
    print("FTP:", str(ftp) + "%")
    print("SMTP:", str(smtp) + "%")
    print("DNS:", str(dns) + "%")
    print("DHCP:", str(dhcp) + "%")
    print("NTP:", str(ntp) + "%")
    print("ICMP:", str(icmp) + "%")
    print("UNKNOWN:", str(unknown) + "%")


def detect_protocol(pkt):
    if pkt.haslayer(scapy.all.TCP):
        if pkt[scapy.all.TCP].dport == 21 or pkt[scapy.all.TCP].sport == 21 or pkt[scapy.all.TCP].dport == 20 or \
                pkt[scapy.all.TCP].sport == 20:
            return "FTP"
        elif pkt[scapy.all.TCP].dport == 80 or pkt[scapy.all.TCP].sport == 80:
            return "HTTP"
        elif pkt[scapy.all.TCP].dport == 25 or pkt[scapy.all.TCP].sport == 25:
            return "SMTP"
        elif pkt[scapy.all.TCP].dport == 443 or pkt[scapy.all.TCP].sport == 443:
            return "HTTPS"
        elif pkt[scapy.all.TCP].dport == 22 or pkt[scapy.all.TCP].sport == 22:
            return "SSH"
        elif pkt[scapy.all.TCP].dport == 445 or pkt[scapy.all.TCP].sport == 445:
            return "SMB"
        elif pkt[scapy.all.TCP].dport == 23 or pkt[scapy.all.TCP].sport == 23:
            return "TELNET"
    elif pkt.haslayer(scapy.all.UDP):
        if pkt[scapy.all.UDP].dport == 67 or pkt[scapy.all.UDP].sport == 67 or pkt[scapy.all.UDP].dport == 68 or \
                pkt[scapy.all.UDP].sport == 68:
            return "DHCP"
        elif pkt[scapy.all.UDP].dport == 123 or pkt[scapy.all.UDP].sport == 123:
            return "NTP"
        elif pkt[scapy.all.UDP].dport == 53 or pkt[scapy.all.UDP].sport == 53:
            return "DNS"
    elif pkt.haslayer(scapy.all.ICMP):
        return "ICMP"
    return "UNKNOWN"


def is_ftp(pkt):
    if pkt.haslayer(scapy.all.TCP) and pkt.haslayer(Raw):
        if pkt[scapy.all.TCP].dport == 21 or pkt[scapy.all.TCP].sport == 21 or pkt[scapy.all.TCP].sport == 20 or \
                pkt[scapy.all.TCP].dport == 20:
            return True
        else:
            return False

    else:
        return False


def is_http(pkt):
    if pkt.haslayer(scapy.all.TCP) and pkt.haslayer(Raw):
        if pkt[scapy.all.TCP].dport == 80 or pkt[scapy.all.TCP].sport == 80:
            return True
        else:
            return False

    else:
        return False


def is_telnet(pkt):
    if pkt.haslayer(scapy.all.TCP) and pkt.haslayer(Raw):
        if pkt[scapy.all.TCP].dport == 23 or pkt[scapy.all.TCP].sport == 23:
            return True
        else:
            return False

    else:
        return False


def extract_http_password(pkt):
    if pkt.haslayer(scapy.layers.http.HTTPRequest):  # look for http request
        if pkt.haslayer(Raw):
            data = str(pkt[Raw].load)
            for keyword in keywords:  # check if each keyword exists
                if keyword in data:  # in the raw field
                    password = data.split(keyword + '=')[1].strip()
                    password = password.replace("'", "")
                    password = re.sub('&.*', '', password)
                    return password
    return "empty"


def password_extraction(pcap):
    for pkt in pcap:
        if is_ftp(pkt):
            data = pkt[Raw].load
            data = str(data)
            if 'PASS ' in data:
                password = data.split('PASS ')[1].strip()
                password = password.replace("\\r\\n'", "")
                password_validation(pkt, password)
        elif is_http(pkt):
            password = extract_http_password(pkt)
            if password != "empty":
                password_validation(pkt, password)
        elif is_telnet(pkt):
            data = pkt[Raw].load
            data = str(data)
            print(data)
            if 'Password: ' in data:
                password = data.split('Password: ')[1].strip()
                password = password.replace("\\r\\n'", "")
                password_validation(pkt, password)


def password_validation(pkt, passwd):
    special_sym = ['$', '@', '#', '%', '!', '.']
    num_of_rules = 6
    rule_comply = 6
    global pass_text
    print("On " + str(datetime.fromtimestamp(pkt.time)) + " the following IP " + str(pkt[IP].src)
          + ' (' + str(socket.gethostbyaddr(str(pkt[IP].src))[0]) + ')' + " has entered the following password:")
    pass_text += "On " + str(datetime.fromtimestamp(pkt.time)) + " the following IP " + str(pkt[IP].src) + ' (' + str(
        socket.gethostbyaddr(str(pkt[IP].src))[0]) + ')' + " has entered the following password:\n"

    print("Validating password: ", passwd)
    pass_text += "Validating password: " + str(passwd) + "\n"
    if len(passwd) < 6:
        print('length should be at least 6')
        pass_text += '  ◉ length should be at least 6\n'
        rule_comply = rule_comply - 1
    if len(passwd) > 25:
        print('length should be not be greater than 25')
        pass_text += '  ◉ length should be not be greater than 25\n'
        rule_comply = rule_comply - 1
    if not any(char.isdigit() for char in passwd):
        print('Password should have at least one numeral')
        pass_text += '  ◉ Password should have at least one numeral\n'
        rule_comply = rule_comply - 1
    if not any(char.isupper() for char in passwd):
        print('Password should have at least one uppercase letter')
        pass_text += '  ◉ Password should have at least one uppercase letter\n'
        rule_comply = rule_comply - 1
    if not any(char.islower() for char in passwd):
        print('Password should have at least one lowercase letter')
        pass_text += '  ◉ Password should have at least one lowercase letter\n'
        rule_comply = rule_comply - 1
    if not any(char in special_sym for char in passwd):
        print('Password should have at least one of the symbols $@#!.')
        pass_text += '  ◉ Password should have at least one of the symbols $@#!.\n'
        rule_comply = rule_comply - 1
    percentage_comply = (rule_comply / num_of_rules) * 100
    percentage_comply = round(percentage_comply, 2)

    print("The password is complied with", percentage_comply, '% of the standards.')
    pass_text += "The password is complied with " + str(percentage_comply) + ' % of the standards.\n\n'


def welcome_page():
    os.system('clear')
    print("===========================================")
    print("===========================================")
    print("===========================================")
    print("")
    print("Welcome to Home Network Assessment Tool")
    print("This tool has been developed for a project in King Saud University")
    print("It was under the course of: Network Security (SEC505).")
    print("")
    input("Please click on enter so the tool can start sniffing the packets!")


def lulwa_code(sniffer):
    pcap = sniffer
    pcap_length = len(pcap)
    encrypted_packets_count = 0
    # show the encrypted packets
    load_layer("tls")  # reading the tls to filter it

    encrypted_pcap = sniff(offline=pcap, lfilter=lambda x: TLS in x)  # loop to find tls packets

    for pkt in pcap:
        if TCP in pkt:
            if pkt[TCP].sport == 22 or pkt[TCP].dport == 22:  # Get SSH packets
                encrypted_packets_count = encrypted_packets_count + 1
    for pkt in encrypted_pcap:
        if TCP in pkt:
            encrypted_packets_count += 1  # Get the TLS PCAPs and add them.
    global encrypted_percentage, unencrypted
    encrypted_percentage = (encrypted_packets_count / pcap_length) * 100
    unencrypted = 100 - encrypted_percentage
    encrypted_percentage = round(encrypted_percentage, 2)
    unencrypted = round(unencrypted, 2)
    print("encrypted packets " + str(encrypted_percentage) + "%" + "     unencrypted packets " + str(unencrypted) + "%")


# find http packet if packet is avaliable
def http_header(pkt):
    http_packet = str(pkt)
    if http_packet.find('GET'):
        sniff(iface='eth0', prn=http_header, filter="tcp port 80")  # sniffing the HTTP packets


# show the ports of the encrypted packets to be included in the encrypted packets percentage
def print_summary(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    if TCP in pkt:
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport
    print(" IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))
    print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))
    sniff(filter="ip", prn=print_summary)


def sniffing():
    interface_answer = input('Kindly enter the name of the interface, if there is not a specifc interface, then type all: ')
    if interface_answer == 'all':
        print("The script has started sniffing now on all interfaces.")
        print("Please press (CTRL+C) to stop sniffing")
        sniffer = sniff()

    else:
        interface = interface_answer
        print("The script has started sniffing now on " + interface + ' interface.')
        print("Please press (CTRL+C) to stop sniffing")
        sniffer = sniff(iface=interface)

    # sniffer = sniff(offline='/sec503/Demos/ftp-active.pcap')
    print()
    return sniffer


def clear_text_domain(pcap):
    for pkt in pcap:
        process_packet(pkt)


def process_packet(pkt):
    if pkt.haslayer(scapy.layers.http.HTTPRequest):
        url = pkt[scapy.layers.http.HTTPRequest].Host.decode() + pkt[scapy.layers.http.HTTPRequest].Path.decode()
        host_name = str(socket.gethostbyaddr(str(pkt[IP].src))[0])
        ip = pkt[IP].src
        global clear_text
        method = pkt[scapy.layers.http.HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} ({host_name}) Requested {url} with {method}{RESET}")
        clear_text += '[+] ' + ip + ' (' + host_name + ') Requested ' + url + ' with ' + method + '\n'


def reporting():
    date_now = str(datetime.now())
    pdf_name_path = r'./Home_Network_Assessment_' + date_now + r'.pdf'
    pdf_name_path = pdf_name_path.replace(' ', '_')
    with PdfPages(pdf_name_path) as export_pdf:
        plt.pie([encrypted_percentage, unencrypted], labels=['Encrypted Percentage ' + str(encrypted_percentage) +
                                                             '%', 'Unencrypted Percentage ' + str(unencrypted) + '%'],
                startangle=90)
        plt.title('Unencrypted and Encrypted Percentage', fontsize=10)
        export_pdf.savefig()
        plt.close()

        plt.bar(protocols_labels, protocols_stats_array)
        plt.title('Protocol Statistics', fontsize=10)
        text = 'Nothing seems suspicious about the network\' activity according to the protocols statistics'
        if dns > unknown and dns > http and dns > http and dns > https and dns > ftp and dns > ssh:
            text = '◉ DNS can be used for tunneling, you want to check what is being requested.' \
                   ' \n ◉ A high volume of DNS can be an indicator of exfiltration.'
        elif http > unknown and http > dns and http > dns and http > https and http > ftp and http > ssh:
            text = '◉ HTTP can be vulnerable to MITM attack, consider using HTTPS. \n' \
                   ' ◉ A high volume of DNS can be an indicator of exfiltration.'
        elif smb > unknown and smb > dns and smb > http and smb > https and smb > ftp and smb > ssh:
            text = '◉ SMB should not be opened to public, as it has huge number of vulnerabilities associated with it.'
        plt.figtext(0.5, 0.03, text, ha="center", fontsize=4, bbox={"facecolor": "orange", "alpha": 0.5, "pad": 5})
        export_pdf.savefig()
        plt.close()

        if len(pass_text) > 110:
            plt.text(0, 0, pass_text, wrap=True)
            plt.axis('off')
            export_pdf.savefig()
            plt.close()

        if len(clear_text) > 5:
            plt.text(0, 0, clear_text, wrap=True)
            plt.axis('off')
            export_pdf.savefig()
            plt.close()

    while True:
        answer = input('Do you want to open the pdf? (Type y or n): ')
        if answer == 'y':
            print(pdf_name_path)
            os.system('atril ' + pdf_name_path + ' &')
            break
        elif answer == 'n':
            break
        else:
            print("Please answer with either 'y' or 'n'.")
    print(pass_text)


def main():
    # The code start here.
    init()
    global GREEN, RED, RESET
    GREEN = Fore.GREEN
    RED = Fore.RED
    RESET = Fore.RESET
    global keywords
    keywords = ['pass', 'password', 'passwd', 'pwd', 'txtPassword']
    global pass_text, clear_text
    pass_text = ''
    clear_text = ''
    welcome_page()
    sniffed_data = sniffing()

    if len(sniffed_data) > 0:
        print('Calculating the encrypted and clear-text packets percentage....')
        lulwa_code(sniffed_data)
        print('Extracting packets\' passwords and validating them....')
        password_extraction(sniffed_data)
        pass_text += 'Kindly check NIST Special Publication 800-63B at https://www.auditboard.com/blog/nist-password-guidelines/'
        print('Calculating protocols\' statistics....')
        protocol_statistics(sniffed_data)
        print('Getting clear text domains.....')
        clear_text_domain(sniffed_data)
        print('Generating the report...')
        reporting()
    else:
        print("There are no captured traffic!")
        print("The program is terminating in 2 seconds....")
        time.sleep(2)


main()
