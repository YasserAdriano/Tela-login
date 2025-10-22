import customtkinter as ctk
import sqlite3
import hashlib
import os
import string 

# =========================================================
# 1. CONFIGURAÇÃO GERAL E TEMAS
# =========================================================
COR_FUNDO = "#121212"
COR_FUNDO_FRAME = "#1a1a1a" 
COR_ROXO_NEON = "#6a0dad"
COR_ROXO_HOVER = "#8f00ff"
COR_TEXTO = "#FFFFFF"         # Cor do texto principal digitado
COR_ENTRY = "#2a2a2a" 
COR_PLACEHOLDER = "#8a8a8a" # Cor do texto de placeholder simulado
SIMBOLOS_PERMITIDOS = "@#$%&!_?"
COR_AGUA = "#444444" 

# Define o tema padrão para o aplicativo
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# =========================================================
# 2. BANCO DE DADOS E FUNÇÕES DE SEGURANÇA
# =========================================================
def setup_database():
    """
    Inicializa o banco de dados 'usuarios.db' e cria a tabela 'usuarios'
    se ela ainda não existir.
    """
    conn = sqlite3.connect('usuarios.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        username TEXT NOT NULL UNIQUE,
        salt BLOB NOT NULL,
        hash_senha BLOB NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def hash_senha(senha, salt):
    """
    Gera um hash seguro da senha usando PBKDF2 com o salt fornecido.
    """
    return hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), salt, 100000)

def validar_senha(senha):
    """
    Verifica se a senha atende aos requisitos mínimos.
    Retorna (True, "OK") ou (False, "Mensagem de Erro").
    """
    tem_maiuscula = False
    tem_numero = False
    tem_simbolo = False
    
    for char in senha:
        if char.isupper():
            tem_maiuscula = True
        elif char.isdigit():
            tem_numero = True
        elif char in SIMBOLOS_PERMITIDOS:
            tem_simbolo = True

    if len(senha) < 8:
        return False, "Senha deve ter no mínimo 8 caracteres."
    if not tem_maiuscula:
        return False, "Senha precisa de 1 letra maiúscula."
    if not tem_numero:
        return False, "Senha precisa de 1 número."
    if not tem_simbolo:
        return False, f"Senha precisa de 1 símbolo ({SIMBOLOS_PERMITIDOS})"

    return True, "OK"

# =========================================================
# 3. FUNÇÕES GLOBAIS (SIMULAÇÃO DE PLACEHOLDER)
# =========================================================
def on_focus_in(event, entry, placeholder, is_senha=False):
    """
    Função de callback para quando um CTkEntry recebe foco.
    Limpa o placeholder e ajusta a cor/visualização.
    """
    if entry.get() == placeholder:
        entry.delete(0, 'end')
        entry.configure(text_color=COR_TEXTO)
        if is_senha:
            entry.configure(show="*")

def on_focus_out(event, entry, placeholder, is_senha=False):
    """
    Função de callback para quando um CTkEntry perde o foco.
    Restaura o placeholder se o campo estiver vazio.
    """
    if entry.get() == "":
        entry.insert(0, placeholder)
        entry.configure(text_color=COR_PLACEHOLDER)
        if is_senha:
            entry.configure(show="") # Mostra o texto do placeholder (ex: "Senha")

# =========================================================
# 4. CLASSE PRINCIPAL (CONTROLADOR DE PÁGINAS)
# =========================================================
class AppLogin(ctk.CTk):
    """
    Classe principal do aplicativo. Atua como a janela raiz e
    controla a navegação entre os diferentes frames (páginas).
    """
    def __init__(self):
        super().__init__()
        self.title("Sistema de Login")
        self.geometry("400x550") 
        self.configure(fg_color=COR_FUNDO)

        # Container principal onde os frames serão empilhados
        container = ctk.CTkFrame(self, fg_color=COR_FUNDO)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # Dicionário para armazenar referências aos frames
        self.frames = {}

        # Itera e inicializa todos os frames (páginas) do aplicativo
        for F in (LoginFrame, RegisterFrame, ForgotPasswordFrame, SuccessFrame):
            frame = F(container, self) 
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew") # Empilha todos no mesmo local

        # Adiciona a marca d'água "made by Yasser"
        watermark = ctk.CTkLabel(self, text="made by Yasser", 
                                 font=ctk.CTkFont(size=11, slant="italic"), 
                                 text_color=COR_AGUA)
        watermark.place(relx=1.0, rely=1.0, x=-40, y=-15, anchor="se") 
        
        # Exibe o frame inicial
        self.show_frame("LoginFrame")

    def show_frame(self, frame_name):
        """
        Move o frame solicitado para a frente (torna-o visível).
        Também chama 'clear_fields' para resetar o estado do frame.
        """
        frame = self.frames[frame_name]
        if hasattr(frame, 'clear_fields'):
            frame.clear_fields()
        frame.tkraise()

# =========================================================
# 5. FRAME DE LOGIN (PÁGINA 1)
# =========================================================
class LoginFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COR_FUNDO)
        self.controller = controller 
        
        self.user_placeholder = "Usuário"
        self.pass_placeholder = "Senha"

        # Frame interno para centralizar o conteúdo
        frame_login = ctk.CTkFrame(self, fg_color=COR_FUNDO_FRAME, corner_radius=10)
        frame_login.pack(pady=40, padx=40, expand=True)

        label_titulo = ctk.CTkLabel(frame_login, text="Login", font=ctk.CTkFont(size=24, weight="bold"))
        label_titulo.pack(pady=(20, 30))

        # --- Widgets ---
        self.entry_username = ctk.CTkEntry(frame_login, width=250, height=40, 
                                           fg_color=COR_ENTRY, border_width=0) 
        self.entry_username.pack(pady=10)

        self.entry_senha = ctk.CTkEntry(frame_login, width=250, height=40, 
                                        fg_color=COR_ENTRY, border_width=0)
        self.entry_senha.pack(pady=10)
        
        # Vincula os eventos de foco para simular o placeholder
        self.entry_username.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_username, self.user_placeholder))
        self.entry_username.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_username, self.user_placeholder))
        
        self.entry_senha.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_senha, self.pass_placeholder, is_senha=True))
        self.entry_senha.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_senha, self.pass_placeholder, is_senha=True))

        self.check_mostrar_senha_login = ctk.CTkCheckBox(frame_login, text="Mostrar Senha",
                                                         command=self.toggle_mostrar_senha_login,
                                                         hover_color=COR_ROXO_HOVER, fg_color=COR_ROXO_NEON)
        self.check_mostrar_senha_login.pack(pady=5, padx=0, anchor="center") 

        self.botao_login = ctk.CTkButton(frame_login, text="Entrar", command=self.funcao_login, 
                                         width=250, height=40, 
                                         fg_color=COR_ROXO_NEON, hover_color=COR_ROXO_HOVER)
        self.botao_login.pack(pady=(15, 10))

        self.botao_registrar = ctk.CTkButton(frame_login, text="Registrar", 
                                             command=lambda: controller.show_frame("RegisterFrame"), 
                                             width=250, height=40, 
                                             fg_color="transparent", border_color=COR_ROXO_NEON, 
                                             border_width=2, hover_color=COR_ENTRY)
        self.botao_registrar.pack(pady=10)
        
        self.botao_esqueci_senha = ctk.CTkButton(frame_login, text="Esqueci minha senha", 
                                                 command=lambda: controller.show_frame("ForgotPasswordFrame"),
                                                 text_color=COR_ROXO_NEON, fg_color="transparent",
                                                 hover_color=COR_FUNDO_FRAME)
        self.botao_esqueci_senha.pack(pady=5)

        self.label_status_login = ctk.CTkLabel(frame_login, text="", text_color="red")
        self.label_status_login.pack(pady=10)
        
        self.clear_fields() # Configura placeholders na inicialização

    def clear_fields(self):
        """Reseta os campos e placeholders do frame de login."""
        self.label_status_login.configure(text="")
        if self.check_mostrar_senha_login.get() == 1:
            self.check_mostrar_senha_login.deselect()
            
        on_focus_out(None, self.entry_username, self.user_placeholder)
        on_focus_out(None, self.entry_senha, self.pass_placeholder, is_senha=True)
        self.toggle_mostrar_senha_login()

    def toggle_mostrar_senha_login(self):
        """Alterna a visibilidade da senha."""
        if self.entry_senha.get() == self.pass_placeholder:
            # Se for o placeholder, não deve ocultar (mostrar "*")
            self.entry_senha.configure(show="")
            return
            
        if self.check_mostrar_senha_login.get() == 1:
            self.entry_senha.configure(show="")
        else:
            self.entry_senha.configure(show="*")

    def funcao_login(self):
        """Valida as credenciais do usuário."""
        username = self.entry_username.get()
        senha = self.entry_senha.get()
        
        # Ignora o texto do placeholder na validação
        if username == self.user_placeholder: username = ""
        if senha == self.pass_placeholder: senha = ""

        if not username or not senha:
            self.label_status_login.configure(text="Preencha todos os campos.")
            return

        conn = sqlite3.connect('usuarios.db')
        c = conn.cursor()
        
        # Busca o usuário no banco
        c.execute("SELECT salt, hash_senha FROM usuarios WHERE username = ?", (username,))
        resultado = c.fetchone()
        
        if not resultado:
            self.label_status_login.configure(text="Usuário ou senha incorretos.")
            conn.close()
            return
            
        # Compara o hash da senha digitada com o hash do banco
        salt_db, hash_db = resultado
        hash_tentativa = hash_senha(senha, salt_db)

        if hash_tentativa == hash_db:
            # Login bem-sucedido
            self.controller.show_frame("SuccessFrame")
        else:
            self.label_status_login.configure(text="Usuário ou senha incorretos.")
            
        conn.close()

# =========================================================
# 6. FRAME DE REGISTRO (PÁGINA 2)
# =========================================================
class RegisterFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COR_FUNDO)
        self.controller = controller

        self.user_placeholder = "Nome de usuário"
        self.pass1_placeholder = "Senha"
        self.pass2_placeholder = "Confirmar Senha"

        frame_reg = ctk.CTkFrame(self, fg_color=COR_FUNDO_FRAME, corner_radius=10)
        frame_reg.pack(pady=40, padx=40, expand=True)

        self.label_titulo = ctk.CTkLabel(frame_reg, text="Criar Conta", font=ctk.CTkFont(size=20, weight="bold"))
        self.label_titulo.pack(pady=(20, 10))

        self.entry_username = ctk.CTkEntry(frame_reg, width=200, fg_color=COR_ENTRY)
        self.entry_username.pack(pady=10)
        self.entry_senha1 = ctk.CTkEntry(frame_reg, width=200, fg_color=COR_ENTRY)
        self.entry_senha1.pack(pady=10)
        self.entry_senha2 = ctk.CTkEntry(frame_reg, width=200, fg_color=COR_ENTRY)
        self.entry_senha2.pack(pady=10)

        # Vincula eventos de foco
        self.entry_username.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_username, self.user_placeholder))
        self.entry_username.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_username, self.user_placeholder))
        
        self.entry_senha1.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_senha1, self.pass1_placeholder, is_senha=True))
        self.entry_senha1.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_senha1, self.pass1_placeholder, is_senha=True))

        self.entry_senha2.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_senha2, self.pass2_placeholder, is_senha=True))
        self.entry_senha2.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_senha2, self.pass2_placeholder, is_senha=True))

        self.check_mostrar_senha = ctk.CTkCheckBox(frame_reg, text="Mostrar Senha", 
                                                   command=self.toggle_mostrar_senha_registro,
                                                   hover_color=COR_ROXO_HOVER, fg_color=COR_ROXO_NEON)
        self.check_mostrar_senha.pack(pady=5)
        
        self.botao_registrar = ctk.CTkButton(frame_reg, text="Registrar", command=self.funcao_registrar, 
                                             fg_color=COR_ROXO_NEON, hover_color=COR_ROXO_HOVER)
        self.botao_registrar.pack(pady=20)
        
        self.botao_voltar = ctk.CTkButton(frame_reg, text="Voltar ao Login", 
                                          command=lambda: controller.show_frame("LoginFrame"),
                                          fg_color="transparent", text_color=COR_ROXO_NEON,
                                          hover_color=COR_FUNDO_FRAME) 
        self.botao_voltar.pack(pady=0)

        self.label_status = ctk.CTkLabel(frame_reg, text="", text_color="red", wraplength=280)
        self.label_status.pack(pady=10)
        
        self.clear_fields()

    def clear_fields(self):
        """Reseta os campos e placeholders do frame de registro."""
        self.label_status.configure(text="")
        if self.check_mostrar_senha.get() == 1:
            self.check_mostrar_senha.deselect()
        
        on_focus_out(None, self.entry_username, self.user_placeholder)
        on_focus_out(None, self.entry_senha1, self.pass1_placeholder, is_senha=True)
        on_focus_out(None, self.entry_senha2, self.pass2_placeholder, is_senha=True)
        self.toggle_mostrar_senha_registro()
            
    def toggle_mostrar_senha_registro(self):
        """Alterna a visibilidade das senhas no registro."""
        if self.entry_senha1.get() != self.pass1_placeholder:
            self.entry_senha1.configure(show="" if self.check_mostrar_senha.get() == 1 else "*")
        else:
            self.entry_senha1.configure(show="")

        if self.entry_senha2.get() != self.pass2_placeholder:
            self.entry_senha2.configure(show="" if self.check_mostrar_senha.get() == 1 else "*")
        else:
            self.entry_senha2.configure(show="")

    def funcao_registrar(self):
        """Valida os dados e cria um novo usuário no banco."""
        username = self.entry_username.get()
        senha1 = self.entry_senha1.get()
        senha2 = self.entry_senha2.get()
        
        # Ignora o texto do placeholder na validação
        if username == self.user_placeholder: username = ""
        if senha1 == self.pass1_placeholder: senha1 = ""
        if senha2 == self.pass2_placeholder: senha2 = ""
        
        # Validação de campos
        if not username or not senha1 or not senha2:
            self.label_status.configure(text="Preencha todos os campos.")
            return
        if senha1 != senha2:
            self.label_status.configure(text="As senhas não coincidem.")
            return
            
        # Validação de requisitos da senha
        is_valid, message = validar_senha(senha1)
        if not is_valid:
            self.label_status.configure(text=message, text_color="red")
            return

        conn = sqlite3.connect('usuarios.db')
        c = conn.cursor()
        
        # Verifica se o usuário já existe
        c.execute("SELECT * FROM usuarios WHERE username = ?", (username,))
        if c.fetchone():
            self.label_status.configure(text="Este usuário já existe.", text_color="red")
            conn.close()
            return
            
        # Cria novo salt e hash
        salt = os.urandom(16)
        hash_gerado = hash_senha(senha1, salt)
        
        try:
            # Insere o novo usuário no banco
            c.execute("INSERT INTO usuarios (username, salt, hash_senha) VALUES (?, ?, ?)", 
                      (username, salt, hash_gerado))
            conn.commit()
            self.label_status.configure(text="Usuário criado! Voltando ao login...", text_color="green")
            self.after(2000, lambda: self.controller.show_frame("LoginFrame"))
        except sqlite3.Error as e:
            self.label_status.configure(text=f"Erro: {e}", text_color="red")
        finally:
            conn.close()

# =========================================================
# 7. FRAME DE ESQUECI SENHA (PÁGINA 3)
# =========================================================
class ForgotPasswordFrame(ctk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COR_FUNDO)
        self.controller = controller
        self.verified_username = None # Armazena o usuário verificado
        
        self.user_placeholder = "Seu nome de usuário"
        self.pass1_placeholder = "Nova Senha"
        self.pass2_placeholder = "Confirmar Nova Senha"

        frame_esqueci = ctk.CTkFrame(self, fg_color=COR_FUNDO_FRAME, corner_radius=10)
        frame_esqueci.pack(pady=40, padx=40, expand=True)

        self.label_titulo = ctk.CTkLabel(frame_esqueci, text="Recuperar Senha", font=ctk.CTkFont(size=20, weight="bold"))
        self.label_titulo.pack(pady=(20, 10))

        # --- Parte 1: Verificação de Usuário ---
        self.entry_username = ctk.CTkEntry(frame_esqueci, width=200, fg_color=COR_ENTRY)
        self.entry_username.pack(pady=10)
        self.entry_username.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_username, self.user_placeholder))
        self.entry_username.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_username, self.user_placeholder))

        self.botao_verificar = ctk.CTkButton(frame_esqueci, text="Verificar Usuário", command=self.funcao_verificar,
                                             fg_color=COR_ROXO_NEON, hover_color=COR_ROXO_HOVER)
        self.botao_verificar.pack(pady=10)
        self.label_status = ctk.CTkLabel(frame_esqueci, text="", text_color="red", wraplength=280)
        self.label_status.pack(pady=10)
        
        # --- Parte 2: Redefinição de Senha (ocultos inicialmente) ---
        self.label_nova_senha = ctk.CTkLabel(frame_esqueci, text="Digite a nova senha:", text_color=COR_TEXTO) 
        self.entry_senha1 = ctk.CTkEntry(frame_esqueci, width=200, fg_color=COR_ENTRY)
        self.entry_senha2 = ctk.CTkEntry(frame_esqueci, width=200, fg_color=COR_ENTRY)
        
        self.entry_senha1.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_senha1, self.pass1_placeholder, is_senha=True))
        self.entry_senha1.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_senha1, self.pass1_placeholder, is_senha=True))

        self.entry_senha2.bind("<FocusIn>", lambda e: on_focus_in(e, self.entry_senha2, self.pass2_placeholder, is_senha=True))
        self.entry_senha2.bind("<FocusOut>", lambda e: on_focus_out(e, self.entry_senha2, self.pass2_placeholder, is_senha=True))

        self.check_mostrar_senha = ctk.CTkCheckBox(frame_esqueci, text="Mostrar Senha", 
                                                   command=self.toggle_mostrar_senha_reset,
                                                   hover_color=COR_ROXO_HOVER, fg_color=COR_ROXO_NEON)
        self.botao_atualizar = ctk.CTkButton(frame_esqueci, text="Atualizar Senha", command=self.funcao_atualizar,
                                             fg_color=COR_ROXO_NEON, hover_color=COR_ROXO_HOVER)
        
        self.botao_voltar = ctk.CTkButton(frame_esqueci, text="Voltar ao Login", 
                                          command=lambda: controller.show_frame("LoginFrame"),
                                          fg_color="transparent", text_color=COR_ROXO_NEON,
                                          hover_color=COR_FUNDO_FRAME)
        self.botao_voltar.pack(pady=(20, 10))
        
        self.clear_fields()

    def clear_fields(self):
        """Reseta o frame de 'Esqueci Senha' para seu estado inicial."""
        self.label_status.configure(text="")
        self.entry_username.configure(state="normal")
        self.botao_verificar.configure(state="normal")
        
        on_focus_out(None, self.entry_username, self.user_placeholder)
        
        # Esconde os widgets da "Parte 2"
        self.label_nova_senha.pack_forget()
        self.entry_senha1.pack_forget()
        self.entry_senha2.pack_forget()
        self.check_mostrar_senha.pack_forget()
        if self.check_mostrar_senha.get() == 1:
            self.check_mostrar_senha.deselect()
        self.botao_atualizar.pack_forget()
        self.verified_username = None

    def funcao_verificar(self):
        """Verifica se o usuário existe no banco de dados."""
        username = self.entry_username.get()
        if username == self.user_placeholder: username = ""
        
        if not username:
            self.label_status.configure(text="Digite um nome de usuário.", text_color="red")
            return
            
        conn = sqlite3.connect('usuarios.db')
        c = conn.cursor()
        c.execute("SELECT * FROM usuarios WHERE username = ?", (username,))
        
        if c.fetchone():
            # Usuário encontrado, avança para a "Parte 2"
            self.verified_username = username
            self.label_status.configure(text=f"Usuário '{username}' encontrado!\nAgora, defina sua nova senha.", text_color="green")
            
            self.entry_username.configure(state="disabled")
            self.botao_verificar.configure(state="disabled")
            
            # Mostra os campos de redefinição
            self.label_nova_senha.pack(pady=(10, 0))
            self.entry_senha1.pack(pady=10)
            self.entry_senha2.pack(pady=10)
            on_focus_out(None, self.entry_senha1, self.pass1_placeholder, is_senha=True)
            on_focus_out(None, self.entry_senha2, self.pass2_placeholder, is_senha=True)
            
            self.check_mostrar_senha.pack(pady=5)
            self.botao_atualizar.pack(pady=20)
        else:
            self.label_status.configure(text="Usuário não encontrado.", text_color="red")
        
        conn.close()

    def funcao_atualizar(self):
        """Valida e atualiza a nova senha do usuário no banco."""
        senha1 = self.entry_senha1.get()
        senha2 = self.entry_senha2.get()
        
        if senha1 == self.pass1_placeholder: senha1 = ""
        if senha2 == self.pass2_placeholder: senha2 = ""
        
        if not senha1 or not senha2:
            self.label_status.configure(text="Preencha os campos da nova senha.", text_color="red")
            return
        if senha1 != senha2:
            self.label_status.configure(text="As novas senhas não coincidem.", text_color="red")
            return
            
        # Validação de requisitos da senha
        is_valid, message = validar_senha(senha1)
        if not is_valid:
            self.label_status.configure(text=message, text_color="red")
            return
        
        # Gera novo salt e hash para a nova senha
        salt = os.urandom(16)
        hash_gerado = hash_senha(senha1, salt)
        
        try:
            conn = sqlite3.connect('usuarios.db')
            c = conn.cursor()
            # Atualiza o salt e a senha no banco
            c.execute("UPDATE usuarios SET salt = ?, hash_senha = ? WHERE username = ?",
                      (salt, hash_gerado, self.verified_username))
            conn.commit()
            
            self.label_status.configure(text="Senha alterada com sucesso!", text_color="green")
            self.after(2000, lambda: self.controller.show_frame("LoginFrame"))
        except sqlite3.Error as e:
            self.label_status.configure(text=f"Erro ao atualizar: {e}", text_color="red")
        finally:
            conn.close()

    def toggle_mostrar_senha_reset(self):
        """Alterna a visibilidade das senhas na redefinição."""
        if self.entry_senha1.get() != self.pass1_placeholder:
            self.entry_senha1.configure(show="" if self.check_mostrar_senha.get() == 1 else "*")
        else:
            self.entry_senha1.configure(show="")

        if self.entry_senha2.get() != self.pass2_placeholder:
            self.entry_senha2.configure(show="" if self.check_mostrar_senha.get() == 1 else "*")
        else:
            self.entry_senha2.configure(show="")

# =========================================================
# 8. FRAME DE SUCESSO (PÁGINA 4)
# =========================================================
class SuccessFrame(ctk.CTkFrame):
    """
    Página exibida após o login bem-sucedido.
    """
    def __init__(self, parent, controller):
        super().__init__(parent, fg_color=COR_FUNDO)
        self.controller = controller

        frame_sucesso = ctk.CTkFrame(self, fg_color=COR_FUNDO_FRAME, corner_radius=10)
        frame_sucesso.pack(pady=40, padx=40, expand=True)

        label_sucesso = ctk.CTkLabel(frame_sucesso, 
                                     text="Parabéns, teste de login e senha\nfeitos com sucesso!",
                                     font=ctk.CTkFont(size=18),
                                     text_color=COR_TEXTO)
        label_sucesso.pack(pady=40, padx=40)

        botao_voltar = ctk.CTkButton(frame_sucesso, text="Voltar para tela de login", 
                                     command=lambda: controller.show_frame("LoginFrame"),
                                     fg_color=COR_ROXO_NEON, hover_color=COR_ROXO_HOVER)
        botao_voltar.pack(pady=(0, 30), padx=20)
        
    def clear_fields(self):
        """Este frame não possui campos para limpar."""
        pass

# =========================================================
# 9. PONTO DE ENTRADA DO APLICATIVO
# =========================================================
if __name__ == "__main__":
    setup_database()  # Garante que o banco de dados exista
    app = AppLogin()
    app.mainloop()