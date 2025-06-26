# --------------------------------------------------------------------
#
# Autor:       Ing. Marco Polo Silva Segovia
# Institución: Instituto Superior Tecnológico España
# Carrera:     Tecnología Universitaria en Sistemas de Información 
#              y Ciberseguridad
# Descripción: Código en Python para generar una interfaz que permite
#              escanear puertos y mostrar los servicios que se
#              ejecutan, usando los protocolos TCP, SYN y UDP.
#
# --------------------------------------------------------------------

import socket
from datetime import datetime
from scapy.all import *
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk

# Especificar la ubicación del archivo manuf (modificar según tu ruta)
conf.manufdb = "/Python/escaner/manuf"

# Función para escanear puertos TCP Connect
def scan_tcp_connect(ip, port):
    """
    Realiza un escaneo de puerto utilizando el método TCP Connect.
    Devuelve True si el puerto está abierto, de lo contrario False.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

# Función para escanear puertos SYN
def scan_syn(ip, port):
    """
    Realiza un escaneo de puerto utilizando el método SYN.
    Devuelve True si el puerto está abierto, de lo contrario False.
    """
    src_port = RandShort()
    syn_ack = sr1(IP(dst=ip)/TCP(dport=port, sport=src_port, flags='S'), timeout=1, verbose=0)
    if syn_ack and syn_ack.haslayer(TCP) and syn_ack.getlayer(TTCP).flags == 0x12:
        return True
    return False

# Función para escanear puertos UDP
def scan_udp(ip, port):
    """
    Realiza un escaneo de puerto utilizando el método UDP.
    Devuelve True si el puerto está abierto, de lo contrario False.
    """
    udp_scan_resp = sr1(IP(dst=ip)/UDP(dport=port), timeout=1, verbose=0)
    if udp_scan_resp is None:
        return True
    elif udp_scan_resp.haslayer(ICMP):
        if int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) == 3:
            return False
    return False

# Función para obtener el nombre del servicio en un puerto
def get_service_name(port, protocol):
    """
    Devuelve el nombre del servicio asociado a un puerto dado y protocolo (tcp o udp).
    Si no se encuentra el servicio, devuelve "Servicio desconocido".
    """
    try:
        return socket.getservbyport(port, protocol)
    except:
        return "Servicio desconocido"

# Clase para la interfaz gráfica
class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Escáner de Puertos")
        self.create_widgets()

    def create_widgets(self):
        """
        Crea y organiza los widgets de la interfaz gráfica.
        """
        # Etiquetas y campos de entrada
        self.target_label = tk.Label(self.root, text="Dirección IP:")
        self.target_label.grid(row=0, column=0, padx=10, pady=10)
        self.target_entry = tk.Entry(self.root)
        self.target_entry.grid(row=0, column=1, padx=10, pady=10)
        
        self.start_port_label = tk.Label(self.root, text="Puerto Inicial:")
        self.start_port_label.grid(row=1, column=0, padx=10, pady=10)
        self.start_port_entry = tk.Entry(self.root)
        self.start_port_entry.grid(row=1, column=1, padx=10, pady=10)
        
        self.end_port_label = tk.Label(self.root, text="Puerto Final:")
        self.end_port_label.grid(row=2, column=0, padx=10, pady=10)
        self.end_port_entry = tk.Entry(self.root)
        self.end_port_entry.grid(row=2, column=1, padx=10, pady=10)
        
        self.scan_type_label = tk.Label(self.root, text="Tipo de Escaneo:")
        self.scan_type_label.grid(row=3, column=0, padx=10, pady=10)
        
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        self.tcp_connect_rb = tk.Radiobutton(self.root, text="TCP Connect", variable=self.scan_type_var, value="TCP Connect")
        self.tcp_connect_rb.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        self.syn_rb = tk.Radiobutton(self.root, text="SYN", variable=self.scan_type_var, value="SYN")
        self.syn_rb.grid(row=4, column=1, padx=10, pady=5, sticky="w")
        self.udp_rb = tk.Radiobutton(self.root, text="UDP", variable=self.scan_type_var, value="UDP")
        self.udp_rb.grid(row=5, column=1, padx=10, pady=5, sticky="w")
        
        self.scan_button = tk.Button(self.root, text="Escanear", command=self.start_scan)
        self.scan_button.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

        # Botón para cerrar la aplicación
        self.close_button = tk.Button(self.root, text="Cerrar", command=self.root.quit)
        self.close_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

        # Barra de progreso
        self.progress = ttk.Progressbar(self.root, orient='horizontal', mode='determinate')
        self.progress.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky="ew")

        # Contenedor con scroll para resultados
        self.canvas = tk.Canvas(self.root)
        self.scroll_y = tk.Scrollbar(self.root, orient="vertical", command=self.canvas.yview)
        self.result_frame = tk.Frame(self.canvas)

        self.result_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.result_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scroll_y.set)

        self.canvas.grid(row=9, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.scroll_y.grid(row=9, column=2, sticky="ns")
        
        self.result_text = tk.Text(self.result_frame, state="normal", width=50, height=15)
        self.result_text.pack()

        # Configuración de la cuadrícula para permitir el cambio de tamaño
        self.root.grid_rowconfigure(9, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

    def start_scan(self):
        """
        Inicia el escaneo de puertos basado en los parámetros ingresados por el usuario.
        Actualiza la interfaz con los resultados y la barra de progreso.
        """
        ip = self.target_entry.get()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Por favor, ingresa puertos válidos")
            return
        
        scan_type = self.scan_type_var.get()
        total_ports = end_port - start_port + 1
        self.progress["value"] = 0
        self.progress["maximum"] = total_ports
        
        self.result_text.configure(state="normal")
        self.result_text.delete(1.0, tk.END)

        start_time = datetime.now()  # Registrar el tiempo de inicio del escaneo
        for i, port in enumerate(range(start_port, end_port + 1)):
            if scan_type == "TCP Connect":
                result = scan_tcp_connect(ip, port)
                protocol = "tcp"
            elif scan_type == "SYN":
                result = scan_syn(ip, port)
                protocol = "tcp"
            elif scan_type == "UDP":
                result = scan_udp(ip, port)
                protocol = "udp"
            
            if result:
                service_name = get_service_name(port, protocol)
                self.result_text.insert(tk.END, f"Puerto {port} ({service_name}): Abierto\n")
            
            self.progress["value"] = i + 1
            self.root.update_idletasks()

        end_time = datetime.now()  # Registrar el tiempo de finalización del escaneo
        duration = end_time - start_time  # Calcular la duración del escaneo
        self.result_text.insert(tk.END, f"\nTiempo total de escaneo: {duration}\n")
        
        self.result_text.configure(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
