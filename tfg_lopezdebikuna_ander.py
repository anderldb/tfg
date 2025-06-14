# Departamento de IT
# Programa: Monitorización de la red informática con ayuda de la inteligencia artificial (OpenAI
# Versión: v.1.0)
# Fecha: 14/06/2025

###########################################################################################################################################################################
###########################################################################################################################################################################
#                                                         IMPORTACION DE LIBRERÍAS A UTILIZAR EN LA APLICACIÓN
###########################################################################################################################################################################
###########################################################################################################################################################################

# Estas son las librerías que importo para su utilización en Python
from pathlib import Path # Manejo de rutas de archivos multiplataforma
from constantes_red_ia import (
csv_ia, api_key, ip_names, web, vlans, path_respaldo, path_sedes, path_switches, internet_ip, zonas_puntos_acceso, back_imagen_auth) 
import openai # Importar librería de la IA OpenAI
import os # Importar librería para interacturar directamente con el sistema operativo desde Python
import csv # Librería para trabajar con ficheros CSV
import tkinter as tk # Importar librería para trabajar con interfaz gráfica
import tkinter.font as tkfont  # Permite usar y personalizar fuentes en interfaces gráficas con Tkinter.
from tkinter import messagebox, ttk, scrolledtext # Importa widgets avanzados, cuadros de diálogo y campos de texto con scroll.
import pyotp # Importar librería para generar y verificar códigos TOTP y HOTP para aplicaciones de autenticación
import requests # Librería que hace posible realizar peticiones HTTP de forma sencilla y eficiente
import socket # Librería que se utiliza para comunicación a nivel de red mediante protocolos TCP y UDP.
from PIL import Image, ImageTk # Permite abrir y mostrar imágenes en la interfaz usando Pillow y Tkinter.
import pandas as pd  # Librería para manipular y analizar datos en estructuras de tipo tabla (DataFrames)


###########################################################################################################################################################################
###########################################################################################################################################################################
#                                                            DECLARACIÓN DE VARIABLES GLOBALES 
###########################################################################################################################################################################
###########################################################################################################################################################################

# Este programa no cuenta con ninguna variable global, todo lo que se utiliza es de forma externa mediante las variables del módulo constantes_red_ia


###########################################################################################################################################################################
###########################################################################################################################################################################
#                                                              FUNCIONES PESTAÑA AUTENTICACIÓN
###########################################################################################################################################################################
###########################################################################################################################################################################


##############################################################################################################
# Funciones de autenticación de las credenciales usuario y password
##############################################################################################################

# Función que devuelve la clave local para abrir la aplicación (no usuario)
def obtener_pass_fichero():
    try:
        with open(path_respaldo["pass"], "r") as archivo:
            return archivo.read().strip() # Con Strip() elimino los saltos de línea
    except Exception as e:
        print(f"Error al leer el archivo de contraseña: {e}")
        exit()


# Función que devuelve el usuario y pass MFA para la aplicación en formato diccionario
def cargar_credenciales_totp():
    try:
        claves = {}
        with open(path_respaldo["mfa"], "r") as archivo:
            for linea in archivo:
                usuario, clave = linea.strip().split(":") # Con Strip() elimino los saltos de línea y divido cada línea con ":", para conseguir el diccionario
                claves[usuario] = clave
        return claves # Devuelvo el diccionario con los usuarios y passwords
    except Exception as e:
        print(f"Error al leer el archivo de claves TOTP: {e}")
        exit()


# Función que verifica si el código TOTP introducido por el usuario es válido en base a la clave secreta registrada
def verificar_totp(codigo_totp, usuario):
    claves_totp = cargar_credenciales_totp()
    if usuario not in claves_totp:
        resultado_label.config(
            text="Autenticación incorrecta, por favor, vuelva a intentarlo.",  # Mensaje de error
            fg="red")  # Color rojo para indicar error
        entry_pass.delete(0, 'end')     # Limpia contraseña
        entry_totp.delete(0, 'end')     # Limpia MFA
        #entry_totp.update_idletasks()  # Fuerza actualización inmediata
        entry_pass.focus_set()         # Foco en contraseña
        return  # Detiene la ejecución de la función
    totp = pyotp.TOTP(claves_totp[usuario]) # Crea un generador TOTP a partir de la clave secreta del usuario
    return totp.verify(codigo_totp) # Verifico si el código introducido por el usuario es válido en el momento exacto de logueo. 


# Función completa de validación de credenciales de usuario
def validar_credenciales():
    # Obtiene las entradas de usuario por pantalla
    contraseña_ingresada = entry_pass.get() # Recoge el pass local aplicación
    usuario = entry_usuario.get() # Recoge el usuario MFA
    codigo_totp = entry_totp.get() # Recoge el pass MFA

    # Validación de las credenciales de contraseña local
    contrasena_correcta = obtener_pass_fichero() 
    
    if contraseña_ingresada != contrasena_correcta:
        resultado_label.config(
            text="Autenticación incorrecta, por favor, vuelva a intentarlo.",  # Mensaje de error
            fg="red")  # Color rojo para indicar error
        entry_pass.delete(0, 'end')     # Limpia contraseña
        entry_totp.delete(0, 'end')     # Limpia MFA
        #entry_totp.update_idletasks()  # Fuerza actualización inmediata
        entry_pass.focus_set()         # Foco en contraseña
        return  # Detiene la ejecución de la función

    # Validación del código TOTP/MFA
    if not verificar_totp(codigo_totp, usuario):
        resultado_label.config(
            text="Autenticación incorrecta, por favor, vuelva a intentarlo.",  # Mensaje de error
            fg="red")  # Color rojo para indicar error
        entry_pass.delete(0, 'end')     # Limpia contraseña
        entry_totp.delete(0, 'end')     # Limpia MFA
        #entry_totp.update_idletasks()  # Fuerza actualización inmediata
        entry_pass.focus_set()         # Foco en contraseña
        return  # Detiene la ejecución de la función

    # Si ambas validaciones son correctas
    resultado_label.config(
        text="Conectado",  # Mensaje de éxito
        fg="green"  # Color verde para indicar mensaje de éxito
    )

    # Habilitar las pestañas superiores restantes después de la autenticación exitosa
    for i in range(1, len(tab_control.tabs())):
        tab_control.tab(i, state="normal")  # Habilitar pestañas

    tab_control.select(tab_monitorizacion)  # Cambiar a la pestaña de Monitorización de manera automática

    # Deshabilitar el botón de inicio de sesión y habilitar el de cerrar sesión
    verificar_button.config(state="disabled")  # Bloquear inicio de sesión
    btn_cerrar_sesion.config(state="normal")  # Habilitar cierre de sesión   
    tab_control.select(tab_monitorizacion)  # Cambiar a la pestaña de Monitorización



##############################################################################################################
# Función de cerrar sesión de usuario
##############################################################################################################

# Función para cerrar sesión y bloquear las pestañas
def cerrar_sesion():
    # Bloquear todas las pestañas de menú excepto la de autenticación
    for i in range(1, len(tab_control.tabs())):
        tab_control.tab(i, state="disabled")  # Deshabilito las pestañas de índice 1 hacia adelante: solo activa la pestaña "Autenticación"

    # Limpiar los campos de entrada en el menú de autenticación. Elimino el contenido del campo de texto desde el inicio hasta el final
    entry_pass.delete(0, tk.END)
    entry_totp.delete(0, tk.END)
    entry_pass.focus_set()         # Foco en contraseña

    # Restaurar mensaje inicial
    resultado_label.config(text="Sin conexión.", fg="red")

    # Volver a la pestaña de autenticación
    #tab_control.select(tab_auth)

    # Habilitar el botón de inicio de sesión y deshabilitar el de cerrar sesión
    verificar_button.config(state="normal")  # Habilitar inicio de sesión
    btn_cerrar_sesion.config(state="disabled")  # Deshabilitar cierre de sesión

    # Reseteo visual de todo lo que muestra la pestaña de monitorización con un control de errores para evitar que falle el programa
    try:
        # Elimino todas las filas de la tabla result_activos recorriendo sus IDs
        for item in result_activos.get_children(): 
            result_activos.delete(item)

        # Elimino todas las filas de la tabla result_webs recorriendo sus IDs
        for item in result_webs.get_children():
            result_webs.delete(item)

        # Restaurar estado de conexión entre sedes
        #conexion_result.config(text="Estado: Pendiente de validación por usuario")

        print("Pantalla de monitorización reiniciada correctamente.")
    except Exception as e:
        print(f"Error al reiniciar la pantalla de monitorización: {e}")
    
    try:
        vlan_result.delete("1.0", tk.END)
    except Exception as e:
        print(f"Error al limpiar el área de resultados VLANs: {e}")
  

    try:
        texto_respuesta_ia.config(state="normal")
        texto_respuesta_ia.delete("1.0", tk.END)
        texto_respuesta_ia.config(state="disabled")
    except Exception as e:
        print(f"Error al limpiar el texto de IA: {e}")



    # Vaciar el contenido del archivo de resultados consolidados
    try:
        # Abro el fichero CSV y si está completado, lo reinicia y lo cierra
        #open("resultados_consolidados.csv", 'w').close()
        open(csv_ia, 'w').close()
        print("Fichero de resultados de monitorización reiniciado correctamente.")
    except Exception as e:
        print(f"Error al reiniciar el contenido del fichero de resultados: {e}")





##############################################################################################################
# Función para que, al cerrar la aplicación, vacíe por completo el archivo CSV de la IA 
##############################################################################################################

def vaciar_csv():
    if os.path.exists(csv_ia):  # Verifica si el archivo existe antes de vaciarlo
        try:
            open(csv_ia, 'w').close()  # Vacía el archivo sin eliminarlo
            print(f"Fichero CSV de la IA '{csv_ia}' vaciado correctamente.")
        except Exception as e:
            print(f"Error al vaciar el archivo CSV de la IA '{csv_ia}': {e}")

    root.destroy()  # Cierra la ventana principal de Tkinter





###########################################################################################################################################################################
###########################################################################################################################################################################
#                                                              FUNCIONES PESTAÑA MONITORIZACIÓN
###########################################################################################################################################################################
###########################################################################################################################################################################


##############################################################################################################
# Función para realizar PING en monitorización
##############################################################################################################
#Verificación si un equipo está o no conectado
def ping_ip(ip):
    response = os.system(f"ping -n 1 {ip} >nul 2>&1") # Devuelve verdadero o falso, se realiza un ping y se omite la respuesta en pantalla
    return response == 0



##############################################################################################################
# Función que realiza la monitorización de la red informática (activos seleccionados)
##############################################################################################################
def ejecutar_monitorizacion():
    total_activos = 0 # Contador del total de activos detectados
    total_no_activos = 0 # Contador del total de no activos detectados

    #Gestión de la barra de progreso
    progress_bar["value"] = 0 # Pongo la barra de progreso en 0
    progress_bar["maximum"] = len(ip_names) + len(web) # Ajusto el máximo de la barra de progreso a cuando estén todas las IPs detectadas y servicios Web comprobados

    # Limpiar las dos tablas de la pestaña de monitorización antes de la actualización
    result_activos.delete(*result_activos.get_children())
    result_webs.delete(*result_webs.get_children())

    for ip, info in ip_names.items(): # Recorro cada IP con su información asociada
        activo = ping_ip(ip)  # Verifico si la IP está activa o no (True/False)
        estado = "Activo" if activo else "No Activo" # Clasifico los dispositivos como activos y no activos dependiendo de su verificación anterior
        color_tag = 'red' if estado == "No Activo" else 'green' # Marco con etiqueta roja los no activos

        result_activos.insert("", "end", values=(ip, info['tipo'], info['nombre'], estado), tags=(color_tag,)) # Insertar en caja de texto la información
        result_activos.tag_configure('red', foreground='red')  # Configurar los elementos 'No Activo' para que sean rojos # CUalquier fila con etiqueta roja, se muestra en rojo
        result_activos.tag_configure('green', foreground='green') # Configurar los elementos 'Activos' en color verde

        if activo:
            total_activos += 1
        else:
            total_no_activos += 1

        progress_bar["value"] += 1 # Sumo valor al avance de la barra
        root.update_idletasks()  # Actualiza la interfaz gráfica en tiempo real

      

    for servicio, url in web: # Utilizo web como una lista de tuplas en vez de diccionario porque se repiten índices
        try:
            response = requests.get(url, timeout=5)
            status = "Disponible" if response.status_code == 200 else "No disponible"
        except:
            status = "Error"

        # Definir el color según el estado
        progress_bar["value"] += 1
        root.update_idletasks()        
        
        nombre_web = url

        if status.lower() in ["error", "no disponible"]:
            result_webs.insert("", "end", values=(servicio, nombre_web, status), tags=("rojo",))
        else:
            result_webs.insert("", "end", values=(servicio, nombre_web, status), tags=("verde",))
    
    if progress_bar["value"] ==  progress_bar["maximum"]:
         messagebox.showinfo("Monitorización", "La monitorización de red ha sido finalizada con éxito.")
         progress_bar["value"] = 0



##############################################################################################################
# Función que guarda los datos de monitorización en el fichero de consolidación para posterior estudio IA
##############################################################################################################

# Función para guardar datos en el archivo consolidado para posterior funcionamiento con IA
def guardar_datos_csv(origen, datos):
    cabeceras = ["Origen", "Datos"]
    if not os.path.exists(csv_ia): # Si el archivo csv de consolidación de datos no existe, se crea
        with open(csv_ia, "w", newline="") as archivo:
            escritor = csv.writer(archivo)
            escritor.writerow(cabeceras)
            
    with open(csv_ia, "a", newline="") as archivo: # Se registran todos los resultados de la monitorización en el fichero consolidado
        escritor = csv.writer(archivo)
        for dato in datos:
            escritor.writerow([origen, dato])



##############################################################################################################
# Guardar los resultados de monitorización en fichero
##############################################################################################################

def guardar_resultados_monitorizacion():

    datos = []
    # Agregar resultados de dispositivos activos
    for child in result_activos.get_children():
        datos.append(f"Activo: {result_activos.item(child)['values']}")

    # Agregar resultados de páginas web
    for child in result_webs.get_children():
        datos.append(f"Web: {result_webs.item(child)['values']}")

    if datos:
        # Guarda el contenido de la lista "datos" en el fichero de consolidación "Monitorizacion.csv" para utilizarlo posteriormente con la inteligencia artificial
        guardar_datos_csv("Monitorización", datos)

        # Saco por pantalla el mensaje de éxito
        messagebox.showinfo("Guardado", "Los resultados de la monitorización han sido registrados con exito para su utilización con inteligencia artificial.")
    else:
        messagebox.showinfo("Error", "No se puede guardar ningun dato porque no se ha realizado la monitorización de red.")


##############################################################################################################
# Función para realizar PING y resuelva el nombre del HOST para VLANs
##############################################################################################################
def ping_and_resolve(ip):
    response = os.system(f"ping -n 1 -w 500 {ip} >nul 2>&1") # Intento de hacer PING sobre dirección IP con un único intento y timeout de 500 ms
    if response == 0:
        try:
            hostname = socket.gethostbyaddr(ip)[0] # Si el host responde, intenta devolver el nombre DNS hostname
        except socket.herror:
            hostname = "No se ha podido resolver el nombre" # Si no se puede resolver el nombre, avisa de que no se ha conseguido
        return ip, hostname
    return None


##############################################################################################################
# Función para escanear una VLAN específica
##############################################################################################################
def scan_vlan(vlan):
    
    vlan_result.delete("1.0", tk.END) 

    if vlan not in vlans: # Compruebo si la VLAN está o no configurada
        vlan_result.insert(tk.END, f"VLAN no configurada: {vlan}\n")
        return

    # Recupera los datos de la VLAN del diccionario vlans

    vlan_result.insert(tk.END, f"\nEscaneando el rango de IPs de la  {vlan}. Por favor, manténgase a la espera hasta su finalización.\n") # Inserta línea de texto en el widget vlan_result
    base_ip = vlans[vlan]["base_ip"]
    start_ip = vlans[vlan]["start_ip"]
    end_ip = vlans[vlan]["end_ip"]

    for i in range(start_ip, end_ip + 1):
        ip = f"{base_ip}{i}" # Contrucción de la IP real
        result = ping_and_resolve(ip)
        if result:
            vlan_result.insert(tk.END, f"{result[0]} está activo. Hostname: {result[1]}\n") # Inserta línea de texto en el widget vlan_result
        else:
            vlan_result.insert(tk.END, f"{ip} no responde.\n")

        vlan_result.update_idletasks()  # Actualiza la interfaz en tiempo real
        root.update_idletasks()  # Refresca la ventana para mostrar cambios

    vlan_result.see(tk.END) # Desplazo automáticamente el scroll del widget hasta el final para que el usuario vea la última línea insertada
    messagebox.showinfo("Escaneo VLAN", "La VLAN ha sido escaneada con éxito.")


###########################################################################################################################################################################
###########################################################################################################################################################################
#                                                         FUNCIONES INTEGRACIÓN CON IA
###########################################################################################################################################################################
###########################################################################################################################################################################


##############################################################################################################
# Función para cargar los archivos de infraestructura en un diccionario de consolidación de información
##############################################################################################################

def cargar_infraestructura():
    
    datos = {
        "Servidores": [],
        "Dispositivos": [],
        "Servicios": []
    }

    for ip, info in ip_names.items(): # Recorro el diccionario ip_names completo
        nombre = info.get("nombre", "Sin nombre") # Devuelve el nombre de dispositivo/servidor y vacío en el caso de que no exista
        tipo = info.get("tipo", "").lower() # Devuelve el tipo de dispositivo/servidor y vacío en el caso de que no exista
        
        if tipo == "servidor":
            datos["Servidores"].append(f"{ip} - {nombre}") # Clasifico los servidores en el diccionario de consolidación de información de los datos
        else:
            datos["Dispositivos"].append(f"{ip} - {nombre}") # Clasifico los dispositivos en el diccionario de consolidación de información de los datos

    # Añadir servicios web
    for tipo_servicio, url in web: # Recorro el diccionario web completo
        datos["Servicios"].append(f"{tipo_servicio}: {url}")  # Clasifico los servicios en el diccionario de consolidación de información de los datos
  
    # Convertir el diccionario datos con las listas a strings para trabajar bien los datos a nivel IA
    datos_str = {}

    for clave, valores in datos.items():
        if valores:
            datos_str[clave] = "\n".join(valores)
        else:
            datos_str[clave] = "Sin datos"

    return datos_str


##############################################################################################################
# Función para cargar los archivos de infraestructura en un diccionario de consolidación de información
##############################################################################################################

def realizar_consulta_ia():
    try:
        datos_infra = cargar_infraestructura()

        # Cargo los datos de monitorización y compruebo las excepciones
        if not os.path.exists(csv_ia):
            messagebox.showerror("Error", f"No existe ningún archivo de monitorización para que sea estudiados con Inteligencia Artificial.")
            return  # Salir de la función
        
        try:
            df = pd.read_csv(csv_ia, encoding="windows-1252")
        
        except pd.errors.EmptyDataError:
            messagebox.showerror("Error", "No se han guardado datos de monitorización de la red de para que sean estudiados con Inteligencia Artificial.")
            return
        
        except pd.errors.ParserError:
            messagebox.showerror("Error", "Vuelva a realizar la monitorización de la red y guardar los datos para su estudiado con Inteligencia Artificial. Formato incorrecto")
            return

        if df.empty:
            messagebox.showerror("Error", "No se han guardado datos de monitorización de la red para que sean estudiados con Inteligencia Artificial.") # Controlo si el DataFrame está vacío
            return
        
        datos_monitorizacion = df.to_string(index=False) # Convierto el DataFrame en un texto en forma de tabla sin mostrar índices

        # Reviso los puntos de acceso y registro los que no están conectados
        puntos_acceso_no_conectados = []
        for index, row in df.iterrows():
            if row.get("Tipo Dispositivo") == "Punto de Acceso" and row.get("Estado Conexión") != "Activo":
                nombre_dispositivo = row.get("Nombre Dispositivo", "Desconocido")
                zona_afectada = zonas_puntos_acceso.get(nombre_dispositivo, "Zona Desconocida")
                puntos_acceso_no_conectados.append(f"❌ {nombre_dispositivo} - Afecta a: {zona_afectada}") # Añado símbolo visual para llamar la atención rápidamente del usuario

        # Mensaje fijo para introducción del resultado de la Inteligencia Artificial
        mensaje_fijo_ia = (
            "📌 **RESUMEN DE LA MONITORIZACIÓN DE LA RED DE LA ARQUITECTURA INFORMÁTICA** \n\n\n"
            "Este informe proporciona un análisis detallado de los resultados de la monitorización de la red informática con Inteligencia Artificial.\n"
            "La monitorización incluye servidores, dispositivos de red (NAS, impresoras y puntos de acceso) y elementos web utilizados por la empresa\n\n"
        )

        # Construcción del mensaje para OpenAI
        mensaje_openai = (
            "Analiza la infraestructura de red de la empresa como si fueses un arquitecto de sistemas IT experto."
            "Elabora un informe técnico detallado utilizando los datos de monitorización, centrándote en la detección de incidencias."
            "Por cada problema detectado, relaciónalo con la jerarquía de la infraestructura para evaluar su impacto."
            "Por ejemplo, si un switch o firewall está inactivo, indica qué dispositivos o servicios podrían verse afectados."
            "Devuelve únicamente un análisis técnico de la situación de la arquitectura de red: no incluyas recomendaciones ni soluciones."
            "Utiliza un icono de exclamación ❗ al inicio de cada apartado numerado."
            "Verifica, a partir de los datos consolidados, si el Firewall está operativo y mantiene la conectividad de la red."
            "Reemplaza cualquier mención a “Problema Crítico” por “Punto Crítico”."
            "Quiero que el informe técnico después del texto fijo lo comiences con tres líneas detallado el estado real de la red e indicando "
            "que a continuación va a realizar un resumen de las vulnerabilidades detectadas \n\n"
        )

        # Dependencias en la arquitectura de la red informática
        dependencias_red = ""
        #**Dependencias y Relación entre Dispositivos:**

        # Agregar Datos de Infraestructura al mensaje de OpenAI
        for categoria, contenido in datos_infra.items():
            mensaje_openai += f"🔹 **{categoria}:**\n{contenido}\n\n"

        # Agregar Resultados de Monitorización
        mensaje_openai += "📌 **Resultados de la monitorización realizada:**\n\n"
        mensaje_openai += datos_monitorizacion + "\n\n"

        # Clasificación de los resultados (Conectados vs Incidencias)
        dispositivos_conectados = []
        dispositivos_no_conectados = []

        for index, row in df.iterrows():
            estado = row.get("Estado Conexión", "Desconocido")
            dispositivo = row.get("Nombre Dispositivo")  

            if pd.notna(dispositivo):  # Si el nombre no está vacío
                if estado == "Activo" or estado == "Disponible":
                    dispositivos_conectados.append(f"✔️ {dispositivo} ({estado})")
                else:
                    dispositivos_no_conectados.append(f"❌ {dispositivo} ({estado})")

        mensaje_openai += "📌 **Dispositivos Conectados:**\n" + "\n".join(dispositivos_conectados) + "\n\n"
        mensaje_openai += "📌 **Resultados de Incidencias:**\n" + "\n".join(dispositivos_no_conectados) + "\n\n"

        # Incluir Puntos de Acceso Desconectados
        if puntos_acceso_no_conectados:
            mensaje_openai += "❗ **Puntos de acceso desconectados y zonas afectadas:**\n" + "\n".join(puntos_acceso_no_conectados) + "\n\n"

        # Llamada a OpenAI
        response = openai.ChatCompletion.create(
            model="gpt-4o", # El trabajo en inteligencia artificial con OpenAI va a ser sobre el modelo "gpt-4o"
            messages=[
                {"role": "system", "content": "Eres un técnico experto mundialmente en análisis de redes y seguridad informática. "
                                              "Debes generar un informe técnico detallado basado en los datos proporcionados. "
                                              "No incluyas sugerencias de colaboración ni referencias a asistencia humana."}, # Role: system. Defino cómo debe comportarse el modelo
                {"role": "user", "content": mensaje_openai} # Role: user. Defino cómo le envío la información al modelo para que la estudie
            ],
            max_tokens=900,
            temperature=0.3 # Respuesta técnica, precisa y seria para realizar un informe adecuado
        )

        respuesta_ia = response["choices"][0]["message"]["content"] # Solo cojo le texto que devuelve la inteligencia artificial de OpenAI del fichero de respuesta

        # Concateno la respuesta que da OpenAI con el mensaje fijo que le paso
        respuesta_final = mensaje_fijo_ia + respuesta_ia

        # Configuración de la interfaz de inteligencia artificial
        texto_respuesta_ia.config(state="normal")  # Habilito temporalmente la interfaz
        texto_respuesta_ia.delete("1.0", tk.END)  # Borro el contenido previo
        texto_respuesta_ia.insert(tk.END, respuesta_final)  # Inserto la respuesta de OpenAI
        texto_respuesta_ia.config(state="disabled")  # Deshabilitao temporalmente la interfaz

    except FileNotFoundError as e:  # Error si no encuentra el archivo
        print(f"Error: {e}")
        messagebox.showerror("Error", str(e))
    except ValueError as e: # Error si hay un valor inesperado
        print(f"Error: {e}")
        messagebox.showerror("Error", str(e))
    except Exception as e:  # Error. Control de un error inesperado
        print(f"Error inesperado: {e}")
        messagebox.showerror("Error", f"Se produjo un error al consultar la IA:\n{e}")


###########################################################################################################################################################################
###########################################################################################################################################################################
#                                                             MAIN - Programa principal y llamada a funciones
###########################################################################################################################################################################
###########################################################################################################################################################################


###########################################
##### Creación de la interfaz gráfica #####
###########################################

# Generación del contenedor principal de la aplicación
root = tk.Tk()  # Creo el contenedor principal donde se añadirán todos los componentes gráficos
root.title("Sistema de monitorización de la red informática con Inteligencia Artificial - v.1.0")  # Título de la ventana del programa
root.state('zoomed')  # Maximizo la ventana al iniciar


###########################################
#####    Configuración clave OpenAI   #####
###########################################
openai.api_key = api_key # Clave API de OpenAI


###################################################
##### Creación de la arquitectura de pestañas #####
###################################################

# Creo un widget de pestañas dentro de la ventana principal del programa y le añado su estilo correspondiente para gestionar el tamaño de letra de las pestañas de navegación
tab_control = ttk.Notebook(root)
style = ttk.Style()
style.configure("TNotebook.Tab", font=("Helvetica", 11)) 

# Contenedor Frame 'tab_auth' asociado a la pestaña "Autenticación de usuario", donde se insertarán los widgets relacionados con el acceso a la aplicación
tab_auth = ttk.Frame(tab_control) 
tab_control.add(tab_auth, text="Autenticación de usuario")   

# Contenedor Frame 'tab_monitorizacion' asociado a la pestaña "Monitorización de la red", donde se insertarán los widgets relacionados con el estado de la red
tab_monitorizacion = ttk.Frame(tab_control)
tab_control.add(tab_monitorizacion, text="Monitorización de la red")  

# Contenedor Frame 'tab_vlans' asociado a la pestaña "Escaneo de VLANs", donde se insertarán los widgets relacionados con la posibilidad de escanear VLANs de la empresa
tab_vlans = ttk.Frame(tab_control)
tab_control.add(tab_vlans, text="Escaneo de VLANs")  # Agregar pestaña de VLANs

# Contenedor Frame 'tab_conexion' asociado a la pestaña "Conexión entre sedes", donde se insertarán los widgets relacionados con la posibilidad de conectar las conexiones entre sedes
tab_conexion = ttk.Frame(tab_control)
tab_control.add(tab_conexion, text="Estudio de la conexión entre sedes")  # Agregar pestaña de conexión entre las sedes de la empresa

# Contenedor Frame 'tab_integracion_ia' asociado a la pestaña "Supervisión avanzada con IA", donde se insertarán los widgets relacionados con la posibilidad de consultar a la Inteligencia Artificial
tab_integracion_ia = ttk.Frame(tab_control)
tab_control.add(tab_integracion_ia, text="Supervisión avanzada con IA")

# Deshabilito el acceso a todas las pestañas al comenzar, salvo la autenticación de usuario
for i in range(1, len(tab_control.tabs())):
    tab_control.tab(i, state="disabled")


###################################################################
###### Configuración de la pestaña "Autenticación de usuario" #####
###################################################################

# Añadir imagen de fondo de pantalla para la pestaña
try:
    # Cargar y redimensionar la imagen de fondo
    back_imagen_auth_var = Image.open(back_imagen_auth) # Cargo la imagen
    back_imagen_auth_var = back_imagen_auth_var.resize((1900, 1200), Image.Resampling.LANCZOS)  # Ajusto la imagen al tamaño necesario utilizando el algoritmo LANCZOS para reducir imagen sin perder nitidez
    bg_photo = ImageTk.PhotoImage(back_imagen_auth_var) # Convierto la imagen a modelo compatible con Tkinter

    # Crear una etiqueta para mostrar la imagen de fondo es la pestaña de autenticación
    bg_label = tk.Label(tab_auth, image=bg_photo) # Genero la etiqueta
    bg_label.image = bg_photo  # Asigno la imagen al atributo del Label para evitar que el recolector de basura de Python la elimine
    bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)  # Expando la imagen al tamaño de la pestaña
except Exception as e:
    print(f"Error al cargar la imagen de fondo: {e}")


# Generar el título de la pantalla 
titulo_label = tk.Label(
    tab_auth,
    text="Monitorización de la red informática con Inteligencia Artificial",
    font=("Helvetica", 30, "bold"),
    fg="black"
)
titulo_label.place(relx=0.5, rely=0.1, anchor="center")  # X e Y son las coordenadas relativas (centrado horizontal al 50% y 10% desde la parte superior)


# Frame contenedor para los botones de autenticación
frame_auth = tk.Frame(tab_auth)  # Creo un Frame contenedor en la pestaña de autenticación
frame_auth.place(relx=0.5, rely=0.65, anchor="center")  # Posiciono el Frame en el centro inferior de la pestaña

# SubFrame para organizar los botones horizontalmente dentro del frame de autenticación
frame_botones = tk.Frame(frame_auth)
frame_botones.grid(row=3, column=0, columnspan=2, pady=20)

# Botón de inicio de sesión
verificar_button = tk.Button(
    frame_botones, 
    text="Iniciar sesión", 
    font=("Helvetica", 12),  
    padx=20,  
    pady=5,  
    command=validar_credenciales
)
verificar_button.pack(side="left", padx=10)  # Alineado a la izquierda dentro del subFrame
verificar_button.config(state="normal")  # Botón de iniciar sesión activo por defecto

# Botón de cerrar sesión
btn_cerrar_sesion = tk.Button(
    frame_botones, 
    text="Cerrar Sesión", 
    font=("Helvetica", 12),  
    padx=20,  
    pady=5,  
    command=cerrar_sesion
)
btn_cerrar_sesion.pack(side="right", padx=10)  # Alineado a la derecha dentro del subFrame
btn_cerrar_sesion.config(state="disabled")  # Botón de cerrar sesión deshabilitado por defecto

# Etiqueta Usuario
tk.Label(frame_auth, text="Usuario:", font=("Helvetica", 12)).grid(row=0, column=0, padx=20, pady=20, sticky="e")
entry_usuario = tk.Entry(frame_auth, width=40, font=("Helvetica", 12))  
entry_usuario.grid(row=0, column=1, padx=20, pady=20)

# Establece el foco en la caja de texto de usuario al iniciar el programa
entry_usuario.focus()  


# Contraseña
tk.Label(frame_auth, text="Contraseña:", font=("Helvetica", 12)).grid(row=1, column=0, padx=20, pady=20, sticky="e")
entry_pass = tk.Entry(frame_auth, show="*", width=40, font=("Helvetica", 12))
entry_pass.grid(row=1, column=1, padx=20, pady=20)

# M.F.A.
tk.Label(frame_auth, text="MFA:.", font=("Helvetica", 12)).grid(row=2, column=0, padx=20, pady=20, sticky="e")
entry_totp = tk.Entry(frame_auth, show="*", width=6, font=("Helvetica", 12), validate="key", validatecommand=(root.register(lambda v: v.isdigit() and len(v) <= 6 or v == ""), "%P"))  
# entry_totp.grid(row=2, column=1, padx=20, pady=20)
entry_totp.grid(row=2, column=1, padx=20, pady=20, sticky="w") # Con sticky="w", alineo el campo a la izquierda (west)

# Etiqueta para mostrar el resultado (debajo del botón) con mensaje inicial
resultado_label = tk.Label(frame_auth, text="", font=("Helvetica", 12), fg="red")
resultado_label.grid(row=4, column=0, columnspan=2, pady=10)  
resultado_label.config(
            text="Sin conexión.",  # Mensaje de estado inicial
            fg="red")  # Color rojo para indicar error


###################################################################
###### Configuración de la pestaña "Monitorización de la red" #####
###################################################################

# Frame contenedor para la pestaña de Monitorización
main_frame = tk.Frame(tab_monitorizacion)
main_frame.pack(fill=tk.BOTH, expand=True) # Para que ocupe todo el espacio de la pestaña

# SubFrame para los botones en la pestaña Monitorización
button_frame_monitorizacion = tk.Frame(main_frame)
button_frame_monitorizacion.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky='ew')  

# Botón para ejecutar la monitorización
btn_monitorizar = tk.Button(
    button_frame_monitorizacion, 
    text="Iniciar Monitorización", 
    font=("Helvetica", 10, "bold"),
    padx=10, pady=10,
    command=ejecutar_monitorizacion
)
btn_monitorizar.grid(row=0, column=0, padx=10, pady=10)

# Botón para guardar resultados para su posterior estudio con Inteligencia Artificial
btn_guardar_monitorizacion = tk.Button(
    button_frame_monitorizacion, 
    font=("Helvetica", 10, "bold"),
    padx=10, pady=10,
    text="Guardar resultados para IA", 
    command=guardar_resultados_monitorizacion
)
btn_guardar_monitorizacion.grid(row=0, column=1, padx=10, pady=10)


##### Configuración de la tabla de dispositivos activos #####
#############################################################
main_frame.grid_rowconfigure(1, weight=1) # Configuro el ajuste dinámico de filas y columnas
main_frame.grid_columnconfigure(0, weight=1) # Permite que las tablas se expandan al redimensionar ventanas
main_frame.grid_columnconfigure(1, weight=1) # Asigno peso a fila sy columnas para expansión proporcional

frame_tabla_activos = tk.Frame(main_frame) # Crea un contenedor (frame) dentro de main_frame
frame_tabla_activos.grid(row=1, column=0, padx=10, pady=10, sticky='nsew') # Coloca el frame en la fila 1, columna 0 con márgenes
frame_tabla_activos.grid_rowconfigure(0, weight=1) # Fila 0 se expande cuando se cambia el tamaño
frame_tabla_activos.grid_columnconfigure(0, weight=1) # Columna 0 se expanda al redimensionar

# Creo la tabla (Treeview) dentro de frame_tabla_activos con las columnas especificadas
result_activos = ttk.Treeview(frame_tabla_activos, columns=("IP", "Tipo", "Nombre", "Estado"), show="headings") 

# Encabezados de la tabla de dispositivos activos
result_activos.heading("IP", text="Dirección IP", anchor="center")
result_activos.heading("Tipo", text="Tipo Dispositivo", anchor="center")
result_activos.heading("Nombre", text="Nombre Dispositivo", anchor="center")
result_activos.heading("Estado", text="Estado", anchor="center")

# Tamaño de las columnas de dispositivos activos
result_activos.column("IP", anchor="center", width=140)
result_activos.column("Tipo", anchor="w", width=120)
result_activos.column("Nombre", anchor="w", width=370)
result_activos.column("Estado", anchor="center", width=120)

# Scrollbar para ver toda la tabla de dispositivos activos
scrollbar_y_activos = ttk.Scrollbar(frame_tabla_activos, orient="vertical", command=result_activos.yview)
result_activos.configure(yscrollcommand=scrollbar_y_activos.set)
result_activos.grid(row=0, column=0, sticky='nsew')
scrollbar_y_activos.grid(row=0, column=1, sticky='ns')

#####         Configuración de los servicios Web         ####
#############################################################
frame_tabla_webs = tk.Frame(main_frame) # Crea un contenedor (frame) dentro de main_frame
frame_tabla_webs.grid(row=1, column=1, padx=10, pady=10, sticky='nsew') # Coloca el frame en la fila 1, columna 0 con márgenes
frame_tabla_webs.grid_rowconfigure(0, weight=1) # Fila 0 se expande cuando se cambia el tamaño
frame_tabla_webs.grid_columnconfigure(0, weight=1) # Columna 0 se expanda al redimensionar

# Creo la tabla (Treeview) dentro de frame_tabla_webs con las columnas especificadas
result_webs = ttk.Treeview(frame_tabla_webs, columns=("Servicio Web", "Página Web", "Estado"), show="headings") 

scrollbar_y_webs = ttk.Scrollbar(frame_tabla_webs, orient="vertical", command=result_webs.yview)
result_webs.configure(yscrollcommand=scrollbar_y_webs.set)

style = ttk.Style() # Creo un objeto de estilo para personalizar el diseño de la tabla
style.configure("Treeview", font=("Helvetica", 3), rowheight=12)
style.configure("Treeview.Heading", font=("Helvetica", 4))

# Configuración de la tabla de páginas web
result_webs = ttk.Treeview(main_frame, columns=("Servicio Web", "Página Web", "Estado"), show="headings", style="Custom.Treeview")

# Cambiar el orden de los encabezados
result_webs.heading("Servicio Web", text="Servicio Web", anchor="center")
result_webs.heading("Página Web", text="Página Web", anchor="center")
result_webs.heading("Estado", text="Estado", anchor="center")

# Ajustar el orden de las columnas
result_webs.column("Servicio Web", anchor="w", width=175)
result_webs.column("Página Web", anchor="w", width=200)
result_webs.column("Estado", anchor="center", width=150)

# Configurar estilos específicos para resaltar en rojo SOLO en la tabla de páginas web
result_webs.tag_configure("rojo", foreground="red") 
result_webs.tag_configure("verde", foreground="green")
result_webs.grid(row=1, column=1, padx=10, pady=10, sticky='nsew')# Configuración de barras de progreso y etiquetas


#####      Configuración de estilos para columnas        ####
#############################################################

def fixed_map(option):
    #Función para corregir los estilos en Tkinter 8.5.9 y superiores.
    return [elm for elm in style.map('Treeview', query_opt=option) if elm[:2] != ('!disabled', '!selected')]

style = ttk.Style()
style.configure("Treeview", font=('Helvetica', 10), rowheight=25)
style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))
style.map('Treeview', foreground=fixed_map('foreground'), background=fixed_map('background'))
style.configure("Red.Foreground.Treeview", foreground="red")  # Estilo para texto en rojo


#####      Barra de progreso de la monitorización        ####
#############################################################

progress_bar = ttk.Progressbar(tab_monitorizacion, orient="horizontal", mode="determinate", length=1600)
progress_bar.pack(padx=10, pady=10)


###################################################################
######                    Escaneo de VLANS                    #####
###################################################################

# Estilo personalizado para los botones y el área de texto
style = ttk.Style()
style.configure('My.TButton', font=('Helvetica', 10, "bold"), padding=6)
style.configure('My.TFrame', background='#f0f0f0')
style.configure('My.TLabel', font=('Helvetica', 10), background='#f0f0f0')

# Marco para los resultados del escaneo de VLANs
vlan_result_frame = ttk.Frame(tab_vlans, style='My.TFrame')
vlan_result_frame.pack(fill='both', expand=True, side='top', anchor='n', padx=(10, 100), pady=(10, 10))  # Expandir en Y

# Área de texto para mostrar resultados del escaneo
vlan_result = scrolledtext.ScrolledText(vlan_result_frame, height=40, font=tkfont.Font(family="Helvetica", size=12))
vlan_result.pack(fill='both', expand=True, padx=5, pady=5)  # Expande en Y también

# Marco para los botones
button_frame = ttk.Frame(tab_vlans, style='My.TFrame')
button_frame.pack(padx=10, pady=10, fill='x')

# Distribución de botones en varias filas si es necesario
rows = (len(vlans) + 4) // 5  # hasta 5 botones por fila
buttons_per_row = (len(vlans) + rows - 1) // rows

for idx, vlan_name in enumerate(vlans.keys()):
    btn = ttk.Button(button_frame, text=f"Escanear {vlan_name}", style='My.TButton',
                     command=lambda v=vlan_name: scan_vlan(v))
    btn.grid(row=idx // buttons_per_row, column=idx % buttons_per_row, padx=5, pady=5, sticky='ew')


button_frame.columnconfigure(tuple(range(buttons_per_row)), weight=1)  # Iguala la distribución de los botones


###################################################################
######              SUPERVISIÓN AVANZADA CON IA               #####
###################################################################

#####     Configuración de etiquetas y botón en IA       ####
#############################################################

# Etiqueta y botón en la pestaña
tk.Label(tab_integracion_ia, text="Informe con Inteligencia Artificial sobre la monitorización de la red a partir de los datos recopilados:", font=("Helvetica",10)).pack(pady=5)

# Botón para enviar los datos a la IA
btn_realizar_consulta = tk.Button(tab_integracion_ia, text="Generación de informe con Inteligencia Artificial (OpenAI)", font=("Helvetica",10, "bold"), padx=10, pady=20, command=realizar_consulta_ia)
btn_realizar_consulta.pack(pady=10)
texto_respuesta_ia = scrolledtext.ScrolledText(tab_integracion_ia, height=40, width=180)
texto_respuesta_ia.pack(pady=5)


# Botón para generar resumen con IA. Se asegura que la nueva pestaña se incluye en la interfaz
tab_control.pack(expand=1, fill="both")


###################################################################
######           Cerrar sesión de la aplicación               #####
###################################################################

# Cuando el usuario pulsa el botón "X" de la ventana para cerrar, en vez de cerrar la aplicación, 
root.protocol("WM_DELETE_WINDOW", vaciar_csv)
root.mainloop() # Inicia el bucle principal y lo mantiene la interfaz viva hasta que se cierra explícitamente.
