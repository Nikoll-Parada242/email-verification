import tkinter as tk
from tkinter import font as tkfont

# ==========================================================
# 1. LOGICA DE VERIFICACIÓN (BACKEND MODULAR)
# ==========================================================
def analyze_email(subject, content):
    """
    Analiza el asunto y contenido de un correo para determinar su nivel de riesgo.
    
    PLACEHOLDER PARA FUTURAS INTEGRACIONES:
    Aquí es donde más adelante puedes integrar:
    1. Un modelo de Machine Learning de NLP (ej. entrenado con Scikit-Learn o TensorFlow).
    2. Una llamada de API externa (ej. VirusTotal, PhishTank, OpenAI API, etc.).
    
    Ejemplo de integración de API simulada:
    # response = requests.post("https://api.seguridad.com/analizar", json={"text": text})
    # return response.json()
    """
    
    # Base de palabras clave sospechosas con sus respectivos pesos de riesgo
    suspicious_keywords = {
        # Urgencia / Acción inmediata
        "urgente": 25,
        "inmediato": 20,
        "importante": 10,
        "atención": 10,
        "acción requerida": 25,
        "cuenta bloqueada": 30,
        "suspensión": 25,
        
        # Ganancias / Ofertas
        "ganaste": 30,
        "premio": 30,
        "sorteo": 25,
        "gratis": 15,
        "herencia": 35,
        "dinero": 20,
        "dólares": 20,
        "millones": 25,
        
        # Finanzas / Seguridad
        "banco": 20,
        "banca": 15,
        "seguridad": 15,
        "verificar": 15,
        "confirmar": 15,
        "contraseña": 25,
        "password": 25,
        "credenciales": 25,
        "iniciar sesión": 20,
        "actualizar datos": 25,
        
        # Enlaces/Archivos
        "link": 15,
        "enlace": 15,
        "archivo adjunto": 20,
        "factura": 15,
    }
    
    # Combinamos el asunto y contenido para el escaneo
    text_to_analyze = (subject + " " + content).lower()
    
    found_keywords = []
    accumulated_risk = 0
    
    # Escaneamos el texto buscando coincidencias
    for word, weight in suspicious_keywords.items():
        if word in text_to_analyze:
            found_keywords.append(word)
            accumulated_risk += weight
            
    # Limitamos el puntaje de riesgo entre 5% (mínimo por defecto) y 100% (máximo)
    risk_score = min(accumulated_risk, 100)
    if not found_keywords and (subject.strip() or content.strip()):
        risk_score = 5
        
    # Definimos el veredicto basándonos en un umbral del 40%
    is_malicious = risk_score >= 40
    
    # Estructuramos la explicación detallada
    details = []
    if is_malicious:
        details.append(f"• Nivel de riesgo estimado: {risk_score}%, superando el umbral de seguridad.")
        details.append(f"• Palabras sospechosas detectadas: {', '.join([f'\"{w}\"' for w in found_keywords])}.")
        details.append("• Alerta: La redacción muestra urgencia o solicita datos confidenciales.")
        details.append("• Recomendación: No hagas clic en ningún enlace ni descargues archivos.")
    else:
        details.append(f"• Nivel de riesgo estimado: {risk_score}%, dentro de límites seguros.")
        if found_keywords:
            details.append(f"• Palabras de bajo riesgo detectadas: {', '.join([f'\"{w}\"' for w in found_keywords])}.")
        else:
            details.append("• No se detectaron palabras clave sospechosas de phishing o spam.")
        details.append("• Recomendación: Aunque el correo parece seguro, verifica el remitente real.")
        
    return {
        "is_malicious": is_malicious,
        "risk_score": risk_score,
        "found_keywords": found_keywords,
        "details": details
    }


# ==========================================================
# 2. COMPONENTE DE BOTÓN MODERNO INTERACTIVO
# ==========================================================
class ModernButton(tk.Button):
    """
    Un botón plano con estilo moderno que soporta cambios de color
    dinámicos al pasar el mouse por encima (efecto hover).
    """
    def __init__(self, parent, text, command, bg_color="#6366f1", hover_color="#4f46e5", fg_color="#ffffff", font=None, **kwargs):
        if font is None:
            font = ("Segoe UI", 11, "bold")
            
        super().__init__(
            parent,
            text=text,
            command=command,
            bg=bg_color,
            fg=fg_color,
            activebackground=hover_color,
            activeforeground=fg_color,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=font,
            **kwargs
        )
        self.bg_color = bg_color
        self.hover_color = hover_color
        
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        
    def on_enter(self, event):
        self.configure(bg=self.hover_color)
        
    def on_leave(self, event):
        self.configure(bg=self.bg_color)


# ==========================================================
# 3. PANTALLA DE ENTRADA DE DATOS (INICIO)
# ==========================================================
class InputScreen(tk.Frame):
    def __init__(self, parent, verify_callback):
        super().__init__(parent, bg="#0f172a") # Fondo oscuro slate-900
        self.verify_callback = verify_callback
        
        # Tarjeta contenedora con un tono de gris más claro (slate-800)
        card = tk.Frame(self, bg="#1e293b", highlightthickness=1, highlightbackground="#334155")
        card.pack(pady=25, padx=25, fill="both", expand=True)
        
        # Icono y encabezado
        header_icon = tk.Label(card, text="🛡️", font=("Segoe UI", 36), bg="#1e293b", fg="#6366f1")
        header_icon.pack(pady=(20, 5))
        
        title_label = tk.Label(card, text="Analizador de Correos", font=("Segoe UI", 18, "bold"), bg="#1e293b", fg="#f8fafc")
        title_label.pack(pady=5)
        
        subtitle_label = tk.Label(
            card, 
            text="Analiza si un correo es seguro o una posible amenaza de Phishing/Spam.", 
            font=("Segoe UI", 9), 
            bg="#1e293b", 
            fg="#94a3b8",
            wraplength=400,
            justify="center"
        )
        subtitle_label.pack(pady=(0, 20))
        
        # --- Campo: Asunto ---
        lbl_subject = tk.Label(card, text="Asunto del correo", font=("Segoe UI", 10, "bold"), bg="#1e293b", fg="#cbd5e1")
        lbl_subject.pack(anchor="w", padx=30, pady=(10, 2))
        
        self.entry_subject = tk.Entry(
            card, 
            bg="#0f172a", 
            fg="#f8fafc", 
            insertbackground="#f8fafc", 
            relief="flat", 
            highlightthickness=1, 
            highlightbackground="#334155", 
            highlightcolor="#6366f1",
            font=("Segoe UI", 11)
        )
        self.entry_subject.pack(fill="x", padx=30, pady=(0, 10), ipady=6)
        
        # --- Campo: Contenido ---
        lbl_content = tk.Label(card, text="Contenido del correo", font=("Segoe UI", 10, "bold"), bg="#1e293b", fg="#cbd5e1")
        lbl_content.pack(anchor="w", padx=30, pady=(10, 2))
        
        self.txt_content = tk.Text(
            card, 
            bg="#0f172a", 
            fg="#f8fafc", 
            insertbackground="#f8fafc", 
            relief="flat", 
            highlightthickness=1, 
            highlightbackground="#334155", 
            highlightcolor="#6366f1",
            font=("Segoe UI", 11),
            wrap="word",
            height=6
        )
        self.txt_content.pack(fill="both", expand=True, padx=30, pady=(0, 10))
        
        # Etiqueta de error invisible por defecto
        self.lbl_error = tk.Label(card, text="", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#ef4444")
        self.lbl_error.pack(pady=5)
        
        # Botón de verificación
        btn_verify = ModernButton(
            card, 
            text="Verificar correo  🔍", 
            command=self.submit_data,
            bg_color="#6366f1",
            hover_color="#4f46e5"
        )
        btn_verify.pack(fill="x", padx=30, pady=(0, 25), ipady=8)
        
    def submit_data(self):
        subject = self.entry_subject.get().strip()
        content = self.txt_content.get("1.0", tk.END).strip()
        
        # Validación: al menos un campo debe tener texto
        if not subject and not content:
            self.lbl_error.config(text="⚠️ Por favor, ingresa al menos el asunto o el contenido.")
            return
            
        self.lbl_error.config(text="") # Limpiar error
        self.verify_callback(subject, content)


# ==========================================================
# 4. PANTALLA DE RESULTADOS (DINÁMICA)
# ==========================================================
class ResultScreen(tk.Frame):
    def __init__(self, parent, result, reset_callback):
        super().__init__(parent, bg="#0f172a")
        
        is_malicious = result["is_malicious"]
        score = result["risk_score"]
        
        # Selección del esquema de color dinámico según el resultado
        if is_malicious:
            theme_color = "#ef4444"    # Rojo Alerta
            hover_color = "#dc2626"
            header_text = "⚠️  CORREO MALICIOSO DETECTADO"
            desc_text = "Se encontraron patrones de palabras de Phishing/Spam."
            accent_bg = "#2d1f24"      # Contenedor con tinte rojizo
            border_color = "#ef4444"
        else:
            theme_color = "#10b981"    # Verde Seguro
            hover_color = "#059669"
            header_text = "✅  CORREO SEGURO"
            desc_text = "No se detectaron amenazas evidentes en el análisis."
            accent_bg = "#1b2a2a"      # Contenedor con tinte verdoso
            border_color = "#10b981"
            
        # Tarjeta contenedora
        card = tk.Frame(self, bg="#1e293b", highlightthickness=1, highlightbackground="#334155")
        card.pack(pady=25, padx=25, fill="both", expand=True)
        
        # Banner del veredicto dinámico
        verdict_frame = tk.Frame(card, bg=accent_bg, highlightthickness=1, highlightbackground=border_color)
        verdict_frame.pack(fill="x", padx=25, pady=(25, 15), ipady=10)
        
        lbl_verdict = tk.Label(verdict_frame, text=header_text, font=("Segoe UI", 14, "bold"), bg=accent_bg, fg=theme_color)
        lbl_verdict.pack(pady=(5, 2))
        
        lbl_desc = tk.Label(verdict_frame, text=desc_text, font=("Segoe UI", 9), bg=accent_bg, fg="#cbd5e1")
        lbl_desc.pack(pady=(0, 5))
        
        # --- Barra de Progreso de Riesgo Personalizada (Canvas) ---
        score_label = tk.Label(card, text=f"Nivel de Riesgo Estimado: {score}%", font=("Segoe UI", 11, "bold"), bg="#1e293b", fg=theme_color)
        score_label.pack(pady=(10, 2))
        
        # Dibujamos un progress bar elegante en un canvas
        progress_canvas = tk.Canvas(card, width=320, height=18, bg="#0f172a", highlightthickness=0)
        progress_canvas.pack(pady=(0, 20))
        
        # Fondo del progress bar
        progress_canvas.create_rectangle(0, 0, 320, 18, fill="#0f172a", outline="")
        
        # Barra rellena proporcional al score (límite máximo 320 px)
        fill_width = int((score / 100.0) * 320)
        if fill_width > 0:
            progress_canvas.create_rectangle(0, 0, fill_width, 18, fill=theme_color, outline="")
            
        # --- Detalles del Riesgo ---
        details_title = tk.Label(card, text="Detalles del Análisis:", font=("Segoe UI", 10, "bold"), bg="#1e293b", fg="#f8fafc")
        details_title.pack(anchor="w", padx=25, pady=(5, 5))
        
        # Contenedor interior para viñetas
        details_box = tk.Frame(card, bg="#0f172a", highlightthickness=1, highlightbackground="#334155")
        details_box.pack(fill="both", expand=True, padx=25, pady=(0, 20))
        
        # Agregamos las viñetas de detalle de forma ordenada
        for detail in result["details"]:
            lbl_bullet = tk.Label(
                details_box, 
                text=detail, 
                font=("Segoe UI", 9), 
                bg="#0f172a", 
                fg="#cbd5e1", 
                justify="left", 
                anchor="w",
                wraplength=350
            )
            lbl_bullet.pack(fill="x", padx=15, pady=6)
            
        # Botón para volver al inicio
        btn_reset = ModernButton(
            card, 
            text="← Validar otro correo", 
            command=reset_callback,
            bg_color="#475569",       # Botón secundario Slate
            hover_color="#334155"
        )
        btn_reset.pack(fill="x", padx=25, pady=(0, 25), ipady=8)


# ==========================================================
# 5. ORQUESTADOR DE LA APLICACIÓN (VENTANA PRINCIPAL)
# ==========================================================
class EmailVerifierApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Email Guard - Analizador de Phishing")
        self.geometry("540x680")
        self.configure(bg="#0f172a")
        self.resizable(False, False)
        
        # Centrar la ventana en la pantalla del usuario
        self.center_window()
        
        # Referencia al frame actual en pantalla
        self.current_screen = None
        
        # Iniciamos mostrando la pantalla de entrada de datos
        self.show_input_screen()
        
    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
        
    def show_input_screen(self):
        # Destruir la pantalla actual si existe
        if self.current_screen is not None:
            self.current_screen.destroy()
            
        # Crear y empaquetar la pantalla de inicio
        self.current_screen = InputScreen(self, self.on_verify_request)
        self.current_screen.pack(fill="both", expand=True)
        
    def on_verify_request(self, subject, content):
        # Procesar los datos a través del analizador backend
        result = analyze_email(subject, content)
        
        # Transicionar a la pantalla de resultados con el reporte correspondiente
        self.show_result_screen(result)
        
    def show_result_screen(self, result):
        # Destruir la pantalla de inicio
        if self.current_screen is not None:
            self.current_screen.destroy()
            
        # Crear y empaquetar la pantalla de resultados
        self.current_screen = ResultScreen(self, result, self.show_input_screen)
        self.current_screen.pack(fill="both", expand=True)


if __name__ == "__main__":
    # Inicialización del loop principal de la GUI
    app = EmailVerifierApp()
    app.mainloop()
