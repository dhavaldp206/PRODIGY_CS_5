import scapy.all as scapy
import psutil
from tkinter import *
from tkinter import ttk, messagebox
import threading

class PacketSniffer:
    def __init__(self, iface):
        self.iface = iface
        self.sniffing = False

    def start_sniffing(self, packet_callback):
        self.sniffing = True
        scapy.sniff(iface=self.iface, prn=packet_callback, stop_filter=self.should_stop_sniffing)

    def should_stop_sniffing(self, packet):
        return not self.sniffing

    def stop_sniffing(self):
        self.sniffing = False

class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.configure(bg='black')
        self.sniffer = None

        self.interface_label = Label(root, text="Select Interface:", fg='lime', bg='black', font=('Courier', 12, 'bold'))
        self.interface_label.pack(pady=10)

        self.interface_combobox = ttk.Combobox(root, values=self.get_interfaces(), font=('Courier', 12))
        self.interface_combobox.pack(pady=10)

        self.start_button = Button(root, text="Start Sniffing", command=self.start_sniffing, fg='lime', bg='black', font=('Courier', 12, 'bold'))
        self.start_button.pack(pady=10)

        self.stop_button = Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=DISABLED, fg='red', bg='black', font=('Courier', 12, 'bold'))
        self.stop_button.pack(pady=10)

        self.tree = ttk.Treeview(root, style="Custom.Treeview")
        self.tree["columns"] = ("Source", "Destination", "Protocol", "Length")
        self.tree.column("#0", width=0, stretch=NO)
        self.tree.column("Source", anchor=W, width=120)
        self.tree.column("Destination", anchor=W, width=120)
        self.tree.column("Protocol", anchor=W, width=60)
        self.tree.column("Length", anchor=W, width=60)
        
        self.tree.heading("Source", text="Source", anchor=W)
        self.tree.heading("Destination", text="Destination", anchor=W)
        self.tree.heading("Protocol", text="Protocol", anchor=W)
        self.tree.heading("Length", text="Length", anchor=W)

        self.style = ttk.Style()
        self.style.configure("Custom.Treeview", background="black", foreground="lime", fieldbackground="black", font=('Courier', 10))
        self.style.configure("Custom.Treeview.Heading", background="black", foreground="lime", font=('Courier', 12, 'bold'))

        self.tree.pack(pady=80)

    def get_interfaces(self):
        # Using psutil to list network interfaces and filter out loopback and non-physical interfaces
        interfaces = psutil.net_if_addrs()
        physical_interfaces = [iface for iface in interfaces if not iface.startswith(('lo', 'Loopback', 'br-', 'docker'))]
        return physical_interfaces

    def start_sniffing(self):
        iface = self.interface_combobox.get()
        if not iface:
            messagebox.showwarning("Interface Error", "Please select a network interface.")
            return

        self.sniffer = PacketSniffer(iface)
        self.start_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        threading.Thread(target=self.sniffer.start_sniffing, args=(self.packet_callback,)).start()

    def stop_sniffing(self):
        if self.sniffer:
            self.sniffer.stop_sniffing()
            self.start_button.config(state=NORMAL)
            self.stop_button.config(state=DISABLED)

    def packet_callback(self, packet):
        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "N/A"
        dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "N/A"
        protocol = packet[scapy.IP].proto if packet.haslayer(scapy.IP) else "N/A"
        length = len(packet)

        self.tree.insert("", "end", values=(src_ip, dst_ip, protocol, length))

if __name__ == "__main__":
    root = Tk()
    gui = SnifferGUI(root)
    root.mainloop()
