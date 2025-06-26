# ciberseguridad
código de aplicaciones en python
1.	Importación de Módulos
•	socket: Utilizado para crear y manejar sockets de red, necesarios para los escaneos de puertos TCP Connect.
•	datetime: Utilizado para registrar y calcular el tiempo de duración del escaneo.
•	scapy.all: Librería Scapy, usada para construir y enviar/recibir paquetes de red para los escaneos SYN y UDP.
•	**tkinter y tkinter.ttk: Librerías para crear la interfaz gráfica.
2.	Funciones de Escaneo de Puertos
•	scan_tcp_connect(ip, port): Realiza un escaneo TCP Connect. Intenta establecer una conexión completa al puerto especificado. Si tiene éxito, el puerto está abierto.
•	scan_syn(ip, port): Realiza un escaneo SYN, enviando un paquete SYN y esperando una respuesta SYN-ACK. Si recibe una respuesta SYN-ACK, el puerto está abierto.
•	scan_udp(ip, port): Realiza un escaneo UDP, enviando un paquete UDP y esperando una respuesta. Si no hay respuesta o recibe un ICMP con tipo/códigos específicos, el puerto está abierto o cerrado, respectivamente.
3.	Función para Obtener el Nombre del Servicio
•	get_service_name(port, protocol): Intenta obtener el nombre del servicio que corre en el puerto especificado. Si no se encuentra, devuelve "Servicio desconocido".
4.	Clase de la Interfaz Gráfica PortScannerApp
•	__init__(self, root): Constructor de la clase, inicializa la ventana principal y llama a create_widgets para crear los componentes de la interfaz.
•	create_widgets(self): Crea y organiza los widgets (etiquetas, campos de entrada, botones, barra de progreso, y área de texto) en la interfaz.
•	start_scan(self): Función llamada al presionar el botón "Escanear". Recoge los parámetros ingresados, realiza el escaneo y actualiza la interfaz con los resultados y el tiempo de duración del escaneo.
5.	Ejecución del Programa
•	Se crea una instancia de tk.Tk() para la ventana principal.
•	Se instancia PortScannerApp con la ventana principal.
•	Se llama a mainloop() para iniciar el bucle principal de la interfaz gráfica.
6.	Detalles Adicionales
•	Barra de Progreso: Actualiza su valor conforme avanza el escaneo de puertos, proporcionando feedback visual al usuario.
•	Área de Texto con Resultados: Muestra los resultados del escaneo y el tiempo total que duró.
•	Interfaz Adaptable: La configuración de la cuadrícula permite que la interfaz se ajuste cuando se cambia el tamaño de la ventana.
