# crie uma interface gráfica de um programa de gerenciador de tarefas para gerenciar atividades do dia a dia.
import tkinter as tk
from tkinter import messagebox
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

# Cores inspiradas no tema escuro do VS Code
CorPrincipal = '#1e1e1e'      # Fundo principal
CorContraste = '#252526'      # Painéis e menus
CorDesabilitado = '#3c3c3c'   # Elementos desabilitados
CorSelecao = '#007acc'        # Seleção e destaque

# Variáveis globais de conexão com o servidor AD
SERVIDOR_IP = '172.18.0.12'
USUARIO_AD = 'LAB.ETEC187\\etec'
SENHA_AD = '187781'
OU_COMPUTADORES = 'OU=COMPUTADORES LAB,OU=LABORATORIOS,DC=LAB,DC=ETEC187'
DOMINIO_AD = 'LAB.ETEC187'
FQDN_AD = 'DC-LAB.LAB.ETEC187'

class GerenciadorADApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gerenciador de Usuários - AD Windows Server 2025")
        self.geometry("800x600")
        self.configure(bg=CorPrincipal)
        self._criar_menu()
        self._criar_painel_central()
        self._criar_botoes()

    def _criar_menu(self):
        menubar = tk.Menu(self, bg=CorContraste, fg='white', activebackground=CorSelecao, activeforeground='white')
        funcoes_menu = tk.Menu(menubar, tearoff=0, bg=CorContraste, fg='white', activebackground=CorSelecao, activeforeground='white')
        funcoes_menu.add_command(label="Gerenciar Computadores", command=self.gerenciar_computadores)
        funcoes_menu.add_command(label="Gerenciar Usuários", command=self.gerenciar_usuarios)
        funcoes_menu.add_command(label="Criar Usuário Individual", command=self.criar_usuario_individual)
        funcoes_menu.add_command(label="Criar usuários em Lote", command=self.criar_usuarios_lote)
        funcoes_menu.add_command(label="Compartilhar pastas dos usuários", command=self.compartilhar_pastas)
        menubar.add_cascade(label="Funções", menu=funcoes_menu)
        menubar.add_command(label="Sobre", command=self.sobre)
        self.config(menu=menubar)

    def _criar_painel_central(self):
        self.painel_central = tk.Frame(self, bg=CorContraste)
        self.painel_central.pack(expand=True, fill='both', padx=30, pady=30)

    def _criar_botoes(self):
        for widget in self.painel_central.winfo_children():
            widget.destroy()
        botoes = [
            ("Gerenciar Computadores", self.gerenciar_computadores),
            ("Gerenciar Usuários", self.gerenciar_usuarios),
            ("Criar Usuário Individual", self.criar_usuario_individual),
            ("Criar usuários em Lote", self.criar_usuarios_lote),
            ("Compartilhar pastas dos usuários", self.compartilhar_pastas),
        ]
        for texto, comando in botoes:
            btn = tk.Button(
                self.painel_central,
                text=texto,
                width=30,
                height=2,
                command=comando,
                bg=CorPrincipal,
                fg='white',
                activebackground=CorSelecao,
                activeforeground='white',
                disabledforeground=CorDesabilitado,
                relief='flat',
                font=('Segoe UI', 12, 'bold')
            )
            btn.pack(pady=10)

    def gerenciar_computadores(self):
        for widget in self.painel_central.winfo_children():
            widget.destroy()
        titulo = tk.Label(
            self.painel_central,
            text="Computadores do Servidor",
            bg=CorContraste,
            fg='white',
            font=('Segoe UI', 16, 'bold')
        )
        titulo.pack(pady=(0, 20))

        try:
            server = Server(SERVIDOR_IP, get_info=ALL)
            conn = Connection(server, user=USUARIO_AD, password=SENHA_AD, authentication=NTLM, auto_bind=True)
            conn.search(
                search_base=OU_COMPUTADORES,
                search_filter='(objectClass=computer)',
                search_scope=SUBTREE,
                attributes=['cn']
            )
            computadores = [entry['attributes']['cn'] for entry in conn.response if 'attributes' in entry and 'cn' in entry['attributes']]
        except Exception as e:
            tk.Label(self.painel_central, text=f'Erro ao conectar ao AD: {e}', bg=CorContraste, fg='red').pack()
            return

        if not computadores:
            tk.Label(self.painel_central, text='Nenhum computador encontrado.', bg=CorContraste, fg='white').pack()
        else:
            for nome in computadores:
                linha = tk.Frame(self.painel_central, bg=CorContraste)
                linha.pack(anchor='w', pady=4, fill='x')
                tk.Label(linha, text=nome, bg=CorContraste, fg='white', font=('Segoe UI', 12)).pack(side='left', padx=(0, 10))
                btn_excluir = tk.Button(
                    linha,
                    text='Excluir',
                    command=lambda n=nome: self.excluir_computador(n),
                    bg=CorPrincipal,
                    fg='white',
                    activebackground=CorSelecao,
                    activeforeground='white',
                    relief='flat',
                    font=('Segoe UI', 10, 'bold')
                )
                btn_excluir.pack(side='left')

        btn_voltar = tk.Button(
            self.painel_central,
            text="Voltar",
            command=self._criar_botoes,
            bg=CorPrincipal,
            fg='white',
            activebackground=CorSelecao,
            activeforeground='white',
            relief='flat',
            font=('Segoe UI', 11, 'bold')
        )
        btn_voltar.pack(pady=30)

    def excluir_computador(self, nome_computador):
        try:
            server = Server(SERVIDOR_IP, get_info=ALL)
            conn = Connection(server, user=USUARIO_AD, password=SENHA_AD, authentication=NTLM, auto_bind=True)
            dn = f'CN={nome_computador},{OU_COMPUTADORES}'
            conn.delete(dn)
            if conn.result['description'] == 'success':
                messagebox.showinfo('Sucesso', f'Computador "{nome_computador}" excluído com sucesso!')
                self.gerenciar_computadores()
            else:
                messagebox.showerror('Erro', f'Não foi possível excluir: {conn.result}')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao excluir computador: {e}')

    def gerenciar_usuarios(self):
        messagebox.showinfo("Gerenciar Usuários", "Funcionalidade em desenvolvimento.")

    def criar_usuario_individual(self):
        messagebox.showinfo("Criar Usuário Individual", "Funcionalidade em desenvolvimento.")

    def criar_usuarios_lote(self):
        messagebox.showinfo("Criar usuários em Lote", "Funcionalidade em desenvolvimento.")

    def compartilhar_pastas(self):
        messagebox.showinfo("Compartilhar pastas dos usuários", "Funcionalidade em desenvolvimento.")

    def sobre(self):
        messagebox.showinfo(
            "Sobre",
            "Gerenciador de Usuários para Windows Server 2025\n\nDesenvolvido para facilitar a administração de usuários e computadores no Active Directory.\n\nVersão inicial."
        )

def main():
    app = GerenciadorADApp()
    app.mainloop()

if __name__ == "__main__":
    main()
