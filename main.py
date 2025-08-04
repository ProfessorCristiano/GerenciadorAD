#
# Programa Interface gráfica de um programa de gerenciador de tarefas do AD.
# Criado por Professor Cristiano Teixeira
# Data: 2023-10-01
# Licença: Apache-2.0
# Este programa é um exemplo de interface gráfica para Gerenciar Usuários e Computadores no AD.
# Ele utiliza a biblioteca Tkinter para criar a interface e a biblioteca paramiko para comunicação SSH.
#

import tkinter as tk
from tkinter import messagebox, ttk, simpledialog
import subprocess
import paramiko
import platform
import json

# Definição da classe GerenciadorADApp deve vir antes do main()
# (não mover o main para o topo, manter a ordem correta: imports, classe, main)

# Verificação e instalação automática de dependências
import sys
import subprocess

def instalar_modulo(modulo):
    try:
        __import__(modulo)
    except ImportError:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', modulo])

for pacote in ['paramiko']:
    instalar_modulo(pacote)

# Cores inspiradas no tema escuro do VS Code
CorPrincipal = '#1e1e1e'      # Fundo principal
CorContraste = '#252526'      # Painéis e menus
CorDesabilitado = '#3c3c3c'   # Elementos desabilitados
CorSelecao = '#007acc'        # Seleção e destaque
CorVermelho = '#ff4040'       # Erros e alertas

# Variáveis globais de conexão com o servidor AD
SERVIDOR_IP = '192.168.0.12'
USUARIO_AD = 'LAB.ET\\admin'
SENHA_AD = 'admin'
OU_COMPUTADORES = 'OU=COMPUTADORES-LAB,OU=LABORATORIO,DC=LAB,DC=ET'
OU_USUARIOS = 'OU=ALUNOS,OU=LABORATORIO,DC=LAB,DC=ET'
DOMINIO_AD = 'LAB.ET'
FQDN_AD = 'DC-LAB.LAB.ET'

# Definição de fontes multiplataforma
if platform.system() == "Windows":
    FONTE_PADRAO = ("Arial", 14, "bold")
    FONTE_PADRAO_MENOR = ("Arial", 12, "bold")
    FONTE_PADRAO_TEXTO = ("Arial", 13)
    FONTE_ERRO = ("Arial", 14, "bold")
else:
    FONTE_PADRAO = ("Ubuntu Regular", 14, "bold")
    FONTE_PADRAO_MENOR = ("Ubuntu Regular", 12, "bold")
    FONTE_PADRAO_TEXTO = ("Ubuntu Regular", 13)
    FONTE_ERRO = ("Ubuntu Regular", 14, "bold")

class GerenciadorADApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Gerenciador de Usuários - AD Windows Server 2025")
        self.geometry("800x700")
        self.configure(bg=CorPrincipal)
        self._criar_menu()
        self._criar_painel_central()
        self._criar_botoes()

    def _criar_menu(self):
        menubar = tk.Menu(self, bg=CorContraste, fg='white', activebackground=CorSelecao, activeforeground='white')
        funcoes_menu = tk.Menu(menubar, tearoff=0, bg=CorContraste, fg='white', activebackground=CorSelecao, activeforeground='white')
        funcoes_menu.add_command(label="Principal", command=self._criar_botoes)
        funcoes_menu.add_command(label="Gerenciar Computadores", command=self.gerenciar_computadores)
        funcoes_menu.add_command(label="Gerenciar Usuários", command=self.gerenciar_usuarios)
        funcoes_menu.add_command(label="Criar Usuário Individual", command=self.criar_usuario_individual)
        funcoes_menu.add_command(label="Criar usuários em Lote", command=self.criar_usuarios_lote)
        funcoes_menu.add_command(label="ReCompartilhar pastas dos usuários", command=self.recompartilhar_pastas)
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
            ("Compartilhar pastas dos usuários", self.recompartilhar_pastas),
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
                font=FONTE_PADRAO
            )
            btn.pack(pady=10)

    def gerenciar_computadores(self):
        for widget in self.painel_central.winfo_children():
            widget.destroy()
        # Painel 1: Árvore
        painel_arvore = tk.Frame(self.painel_central, bg=CorContraste)
        painel_arvore.pack(fill='both', expand=True)
        style = ttk.Style()
        style.theme_use('default')
        style.configure('Treeview', background=CorContraste, fieldbackground=CorContraste, foreground='white', font=FONTE_PADRAO_TEXTO)
        style.configure('Treeview.Heading', background=CorPrincipal, foreground='white', font=FONTE_PADRAO_MENOR)
        tree = ttk.Treeview(painel_arvore, selectmode='browse')
        tree.pack(side='left', fill='both', expand=True)
        scrollbar = tk.Scrollbar(painel_arvore, orient="vertical", command=tree.yview)
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        tree.heading('#0', text='Organizational Units / Computadores', anchor='w')

        # Painel 2: Ações
        painel_acoes = tk.Frame(self.painel_central, bg=CorContraste)
        painel_acoes.pack(fill='x')
        label_acoes = tk.Label(painel_acoes, text="Ações para o Objeto Selecionado", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_acoes.pack(anchor='w', padx=10, pady=(10, 0))
        frame_botoes = tk.Frame(painel_acoes, bg=CorContraste)
        frame_botoes.pack(anchor='w', padx=10, pady=5)

        # Painel 3: Voltar
        painel_voltar = tk.Frame(self.painel_central, bg=CorContraste)
        painel_voltar.pack(fill='x')
        btn_voltar = tk.Button(
            painel_voltar,
            text="Voltar",
            command=self._criar_botoes,
            bg=CorPrincipal,
            fg='white',
            activebackground=CorSelecao,
            activeforeground='white',
            relief='flat',
            font=FONTE_PADRAO_MENOR
        )
        btn_voltar.pack(pady=20)

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            comando_ou = (
                f"powershell -Command \"Get-ADOrganizationalUnit -SearchBase '{OU_COMPUTADORES}' -SearchScope Subtree -Filter * | Select-Object DistinguishedName,Name | ConvertTo-Json\""
            )
            stdin, stdout, stderr = ssh.exec_command(comando_ou)
            ou_bytes = stdout.read()
            erro_ou = stderr.read()
            comando_computadores = (
                f"powershell -Command \"Get-ADComputer -SearchBase '{OU_COMPUTADORES}' -SearchScope Subtree -Filter * | Select-Object DistinguishedName,Name | ConvertTo-Json\""
            )
            stdin, stdout, stderr = ssh.exec_command(comando_computadores)
            computadores_bytes = stdout.read()
            erro_computadores = stderr.read()
            ssh.close()
            for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                try:
                    ou_str = ou_bytes.decode(encoding)
                    erro_ou_str = erro_ou.decode(encoding)
                    computadores_str = computadores_bytes.decode(encoding)
                    erro_computadores_str = erro_computadores.decode(encoding)
                    break
                except Exception:
                    ou_str = erro_ou_str = computadores_str = erro_computadores_str = None
            if erro_ou_str or erro_computadores_str:
                raise Exception(erro_ou_str or erro_computadores_str)
        except Exception as e:
            tk.Label(self.painel_central, text=f'Erro ao buscar OUs/Computadores: {e}', bg=CorContraste, fg='red', font=FONTE_ERRO).pack()
            return

        import json
        try:
            ou_list = json.loads(ou_str) if ou_str.strip() else []
            computadores_list = json.loads(computadores_str) if computadores_str.strip() else []
            if isinstance(ou_list, dict):
                ou_list = [ou_list]
            if isinstance(computadores_list, dict):
                computadores_list = [computadores_list]
        except Exception:
            ou_list = []
            computadores_list = []

        def get_parent_dn(dn):
            # Retorna o DN do pai (remove apenas o primeiro elemento OU/USER)
            partes = dn.split(',')
            if len(partes) > 1:
                return ','.join(partes[1:])
            return ''

        # Função 1 - Gerenciar Computadores
        ou_by_dn_comp = {ou['DistinguishedName']: ou for ou in ou_list if 'DistinguishedName' in ou}
        children_comp = {ou['DistinguishedName']: [] for ou in ou_list if 'DistinguishedName' in ou}
        root_dn_comp = OU_COMPUTADORES
        for ou in ou_list:
            parent_dn = get_parent_dn(ou['DistinguishedName'])
            if parent_dn in children_comp:
                children_comp[parent_dn].append(ou['DistinguishedName'])

        def insert_ou_recursive(parent, parent_dn):
            # Ordena OUs filhas por nome
            ou_children_dns = sorted(children_comp.get(parent_dn, []), key=lambda dn: ou_by_dn_comp[dn].get('Name', '').lower())
            for ou_dn in ou_children_dns:
                ou_name = ou_by_dn_comp[ou_dn].get('Name', ou_dn)
                ou_id = tree.insert(parent, 'end', text=ou_name, open=False)
                insert_ou_recursive(ou_id, ou_dn)
                # Inserir computadores desta OU em ordem alfabética
                computadores_ou = [comp for comp in computadores_list if get_parent_dn(comp.get('DistinguishedName', '')) == ou_dn]
                computadores_ou = sorted(computadores_ou, key=lambda c: c.get('Name', '').lower())
                for comp in computadores_ou:
                    comp_name = comp.get('Name')
                    tree.insert(ou_id, 'end', text=comp_name, values=(comp.get('DistinguishedName'),))

        # Limpa a treeview
        for item in tree.get_children():
            tree.delete(item)
        # Insere a raiz e recursivamente as OUs e computadores
        root_id_comp = tree.insert('', 'end', text=ou_by_dn_comp[root_dn_comp]['Name'] if root_dn_comp in ou_by_dn_comp else 'COMPUTADORES-LAB', open=True)
        insert_ou_recursive(root_id_comp, root_dn_comp)

        def on_tree_select(event):
            for widget in frame_botoes.winfo_children():
                widget.destroy()
            item_id = tree.focus()
            if not item_id:
                return
            item_values = tree.item(item_id, 'values')
            item_text = tree.item(item_id, 'text')
            parent_id = tree.parent(item_id)
            # Só exibe botão se for computador (folha, não OU)
            if parent_id and not tree.get_children(item_id):
                btn_excluir = tk.Button(
                    frame_botoes,
                    text="Excluir",
                    command=lambda: self.excluir_computador(item_text),
                    bg=CorPrincipal,
                    fg='white',
                    activebackground=CorSelecao,
                    activeforeground='white',
                    relief='flat',
                    font=FONTE_PADRAO_MENOR
                )
                btn_excluir.pack(side='left', padx=5)
        tree.bind('<<TreeviewSelect>>', on_tree_select)

    def excluir_computador(self, nome_computador):
        # Busca o DistinguishedName do computador selecionado na árvore
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            # Busca o DN do computador
            comando_dn = f"powershell -Command \"Get-ADComputer -Filter {{Name -eq '{nome_computador}'}} -SearchBase '{OU_COMPUTADORES}' | Select-Object -ExpandProperty DistinguishedName\""
            stdin, stdout, stderr = ssh.exec_command(comando_dn)
            dn_bytes = stdout.read()
            erro_bytes = stderr.read()
            for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                try:
                    dn = dn_bytes.decode(encoding).strip()
                    erro = erro_bytes.decode(encoding)
                    break
                except Exception:
                    dn = erro = None
            if erro:
                raise Exception(erro)
            if not dn:
                raise Exception('DistinguishedName não encontrado para o computador selecionado.')
            # Confirmação dupla
            if not messagebox.askyesno('Confirmação', f'Tem certeza que deseja excluir o computador "{nome_computador}"?'):
                return
            if not messagebox.askyesno('Confirmação', f'Esta ação é irreversível. Deseja realmente excluir "{nome_computador}"?'):
                return
            # Exclui o computador
            comando_del = f"powershell -Command \"Remove-ADComputer -Identity '{dn}' -Confirm:$false\""
            stdin, stdout, stderr = ssh.exec_command(comando_del)
            saida = stdout.read().decode(errors='ignore')
            erro = stderr.read().decode(errors='ignore')
            ssh.close()
            if erro:
                messagebox.showerror('Erro', f'Erro ao excluir computador: {erro}')
            else:
                messagebox.showinfo('Sucesso', f'Computador "{nome_computador}" excluído com sucesso!')
                self.gerenciar_computadores()
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao excluir computador: {e}')

    def criar_usuarios_lote(self):
        # Limpa painel central
        for widget in self.painel_central.winfo_children():
            widget.destroy()
        # Painel de seleção de curso
        painel_curso = tk.Frame(self.painel_central, bg=CorContraste)
        painel_curso.pack(fill='x', pady=10)
        tk.Label(painel_curso, text="Selecione o Curso:", bg=CorContraste, fg='white', font=FONTE_PADRAO).pack(anchor='w', padx=10)
        combo_curso = ttk.Combobox(painel_curso, state='readonly', font=FONTE_PADRAO_TEXTO)
        combo_curso.pack(anchor='w', padx=10, pady=5)

        # Painel para digitar nome da turma
        painel_turma = tk.Frame(self.painel_central, bg=CorContraste)
        label_turma = tk.Label(painel_turma, text="Digite o nome da Turma:", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma1 = tk.Label(painel_turma, text="Para Integrado use nome do curso '-' Ano atual", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma2 = tk.Label(painel_turma, text="Exemplo: 'DS-2077'", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma3 = tk.Label(painel_turma, text=" ", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma4 = tk.Label(painel_turma, text="Para cursos modulares inicie em a letra 'M' nome do Curso", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma5 = tk.Label(painel_turma, text="'-' ano atual letra 'a' se for o primeiro semestre do ano", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma6 = tk.Label(painel_turma, text="letra 'b' se for o segundo.", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma7 = tk.Label(painel_turma, text="Exemplo: 'MDS-2077b'", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma8 = tk.Label(painel_turma, text="para a turma que irá começar no segundo semestre.", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        entry_turma = tk.Entry(painel_turma, font=FONTE_PADRAO_TEXTO)
        label_turma.pack(anchor='w', padx=10)
        label_turma1.pack(anchor='w', padx=10)
        label_turma2.pack(anchor='w', padx=10)
        label_turma3.pack(anchor='w', padx=10)
        label_turma4.pack(anchor='w', padx=10)
        label_turma5.pack(anchor='w', padx=10)
        label_turma6.pack(anchor='w', padx=10)
        label_turma7.pack(anchor='w', padx=10)
        label_turma8.pack(anchor='w', padx=10)
        entry_turma.pack(anchor='w', padx=10, pady=5)
        painel_turma.pack_forget()

        # Painel para seleção de arquivo
        painel_arquivo = tk.Frame(self.painel_central, bg=CorContraste)
        label_arquivo = tk.Label(painel_arquivo, text="Selecione o arquivo de logins (.txt, um por linha):", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_arquivo.pack(anchor='w', padx=10)
        btn_arquivo = tk.Button(painel_arquivo, text="Selecionar Arquivo", font=FONTE_PADRAO_MENOR)
        btn_arquivo.pack(anchor='w', padx=10, pady=5)
        label_arquivo_nome = tk.Label(painel_arquivo, text="", bg=CorContraste, fg='white', font=FONTE_PADRAO_TEXTO)
        label_arquivo_nome.pack(anchor='w', padx=10)
        painel_arquivo.pack_forget()
        arquivo_path = {'path': None}

        # Painel de botão de criar usuários
        painel_criar = tk.Frame(self.painel_central, bg=CorContraste)
        btn_criar = tk.Button(painel_criar, text="Criar Usuários", font=FONTE_PADRAO, bg=CorSelecao, fg='white')
        btn_criar.pack(padx=10, pady=10)
        painel_criar.pack_forget()

        # Painel de log não será usado. será arquivo de log .txt
        painel_log = tk.Frame(self.painel_central, bg=CorContraste)
        painel_log.pack(fill='x', pady=10)
        label_log = tk.Label(painel_log, text="", bg=CorContraste, fg='white', font=FONTE_PADRAO_TEXTO, justify='left')
        label_log.pack(anchor='w', padx=10)

        # Painel voltar (sempre no final)
        painel_voltar = tk.Frame(self.painel_central, bg=CorContraste)
        painel_voltar.pack(side='bottom', fill='x', pady=10)
        btn_voltar = tk.Button(
            painel_voltar,
            text="Voltar",
            command=self._criar_botoes,
            bg=CorPrincipal,
            fg='white',
            activebackground=CorSelecao,
            activeforeground='white',
            relief='flat',
            font=FONTE_PADRAO_MENOR
        )
        btn_voltar.pack(pady=10)

        # Buscar cursos disponíveis no AD
        cursos_dn = {}
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            comando_cursos = (
                f"powershell -Command \"Get-ADOrganizationalUnit -SearchBase '{OU_USUARIOS}' -SearchScope OneLevel -Filter * | Select-Object Name,DistinguishedName | ConvertTo-Json\""
            )
            stdin, stdout, stderr = ssh.exec_command(comando_cursos)
            cursos_bytes = stdout.read()
            erro_cursos = stderr.read()
            ssh.close()
            cursos_str = erro_cursos_str = None
            for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                try:
                    cursos_str = cursos_bytes.decode(encoding)
                    erro_cursos_str = erro_cursos.decode(encoding)
                    break
                except Exception:
                    continue
            if erro_cursos_str and erro_cursos_str.strip():
                raise Exception(f'PowerShell: {erro_cursos_str}')
            import json
            cursos_list = json.loads(cursos_str) if cursos_str and cursos_str.strip() else []
            if isinstance(cursos_list, dict):
                cursos_list = [cursos_list]
            cursos_dn = {c['Name']: c['DistinguishedName'] for c in cursos_list if 'Name' in c and 'DistinguishedName' in c}
            if not cursos_dn:
                raise Exception('Nenhum curso encontrado no AD.')
            combo_curso['values'] = list(cursos_dn.keys())
        except Exception as e:
            combo_curso['values'] = []
            messagebox.showerror('Erro', f'Erro ao buscar cursos: {e}')

        def ao_selecionar_curso(event):
            painel_turma.pack(fill='x', pady=10)
            painel_arquivo.pack_forget()
            painel_criar.pack_forget()
            label_log.config(text="")
        combo_curso.bind('<<ComboboxSelected>>', ao_selecionar_curso)

        def ao_digitar_turma(event=None):
            if entry_turma.get().strip():
                painel_arquivo.pack(fill='x', pady=10)
                painel_criar.pack_forget()
                label_log.config(text="")
        entry_turma.bind('<KeyRelease>', ao_digitar_turma)

        def selecionar_arquivo():
            from tkinter import filedialog
            file_path = filedialog.askopenfilename(filetypes=[('Text Files', '*.txt')])
            if file_path:
                arquivo_path['path'] = file_path
                label_arquivo_nome.config(text=file_path)
                painel_criar.pack(fill='x', pady=10)
                label_log.config(text="")
        btn_arquivo.config(command=selecionar_arquivo)

        def criar_usuarios_lote_exec():
            curso = combo_curso.get()
            turma = entry_turma.get().strip().upper()
            arquivo = arquivo_path['path']
            if not curso or not turma or not arquivo:
                messagebox.showerror('Erro', 'Preencha todos os campos e selecione o arquivo.')
                return
            # Nome do grupo: primeira letra maiúscula, resto minúsculo
            nome_grupo = turma.capitalize()
            log_falhas = []
            try:
                with open(arquivo, 'r') as f:
                    usuarios = [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showerror('Erro', f'Erro ao ler arquivo: {e}')
                return
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=SERVIDOR_IP,
                    username=USUARIO_AD.split('\\')[-1],
                    password=SENHA_AD,
                    look_for_keys=False,
                    allow_agent=False
                )
                curso_dn = cursos_dn[curso]
                # 1. Criar OU da turma
                comando_criar_ou = f"powershell -Command \"New-ADOrganizationalUnit -Name '{turma}' -Path '{curso_dn}' -ProtectedFromAccidentalDeletion $false\""
                stdin, stdout, stderr = ssh.exec_command(comando_criar_ou)
                erro_ou = stderr.read().decode(errors='ignore')
                # 2. Criar grupo da turma
                turma_dn = f"OU={turma},{curso_dn}"
                comando_criar_grupo = f"powershell -Command \"New-ADGroup -Name '{nome_grupo}' -GroupScope Global -GroupCategory Security -Path '{turma_dn}'\""
                stdin, stdout, stderr = ssh.exec_command(comando_criar_grupo)
                erro_grupo = stderr.read().decode(errors='ignore')
                # 3. Adicionar grupo ao grupo da turma (primeira letra maiúscula)
                comando_adicionar_grupo = f"powershell -Command \"Add-ADGroupMember -Identity '{nome_grupo}' -Members '{nome_grupo}'\""
                # O grupo recem criado é adicionado a si mesmo (não faz sentido, mas segue a instrução)
                stdin, stdout, stderr = ssh.exec_command(comando_adicionar_grupo)
                erro_add_grupo = stderr.read().decode(errors='ignore')
                # 4. Criar pasta da turma
                pasta_turma = f'F:\\ARQUIVOS\\Alunos\\{curso}\\{turma}'
                comando_criar_pasta_turma = f"powershell -Command \"if (!(Test-Path '{pasta_turma}')) {{ New-Item -Path '{pasta_turma}' -ItemType Directory }}\""
                stdin, stdout, stderr = ssh.exec_command(comando_criar_pasta_turma)
                erro_pasta_turma = stderr.read().decode(errors='ignore')
                # 5. Criar usuários
                for usuario in usuarios:
                    try:
                        pasta_usuario = f'F:\\ARQUIVOS\\Alunos\\{curso}\\{turma}\\{usuario}'
                        compartilhamento = f'\\\\DC-LAB\\{usuario}$'
                        home_directory = compartilhamento
                        script_ps = (
                            f"""
$ErrorActionPreference = 'Stop'
$login = '{usuario}'
$senha = ConvertTo-SecureString '1234' -AsPlainText -Force
$ou = '{turma_dn}'
$grupo = '{nome_grupo}'
$pasta = '{pasta_usuario}'
# Cria usuário
$user = New-ADUser -Name $login -SamAccountName $login -GivenName $login -Surname $login -AccountPassword $senha -Enabled $true -Path $ou -ChangePasswordAtLogon $false -HomeDirectory '{home_directory}' -HomeDrive 'U:' -PassThru
# Adiciona ao grupo
if ($grupo) {{ Add-ADGroupMember -Identity $grupo -Members $login }}
# Cria pasta se não existir
if (!(Test-Path $pasta)) {{ New-Item -Path $pasta -ItemType Directory }}
# Permissões NTFS
$acl = Get-Acl $pasta
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object {{ $acl.RemoveAccessRule($_) }}
$ruleSistema = New-Object System.Security.AccessControl.FileSystemAccessRule('SISTEMA','FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($ruleSistema)
$ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule('{DOMINIO_AD}\\{usuario}','Modify','ContainerInherit,ObjectInherit','None','Allow')
$ruleProf = New-Object System.Security.AccessControl.FileSystemAccessRule('{DOMINIO_AD}\\Professor','Modify','ContainerInherit,ObjectInherit','None','Allow')
$ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule('Administradores','FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($ruleUser)
$acl.AddAccessRule($ruleProf)
$acl.AddAccessRule($ruleAdmins)
Set-Acl $pasta $acl
# Compartilhamento oculto
$share = $login + '$'
if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {{
    Revoke-SmbShareAccess -Name $share -AccountName 'Everyone' -Force -Confirm:$false
}}
if (!(Get-SmbShare -Name $share -ErrorAction SilentlyContinue)) {{
    New-SmbShare -Name $share -Path $pasta -FullAccess 'Administradores' -ChangeAccess '{DOMINIO_AD}\\{usuario}','{DOMINIO_AD}\\Professor'
}} else {{
    Grant-SmbShareAccess -Name $share -AccountName '{DOMINIO_AD}\\{usuario}' -AccessRight Change -Force
    Grant-SmbShareAccess -Name $share -AccountName '{DOMINIO_AD}\\Professor' -AccessRight Change -Force
    Grant-SmbShareAccess -Name $share -AccountName 'Administradores' -AccessRight Full -Force
    Revoke-SmbShareAccess -Name $share -AccountName 'Everyone' -Force -Confirm:$false
}}
Write-Output 'OK'
"""
                        )
                        import tempfile, os
                        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.ps1') as f:
                            f.write(script_ps)
                            temp_script_path = f.name
                        sftp = ssh.open_sftp()
                        remote_path = f'C:/Windows/Temp/criar_usuario_lote_{usuario}_{os.getpid()}.ps1'
                        sftp.put(temp_script_path, remote_path)
                        sftp.close()
                        os.unlink(temp_script_path)
                        comando = f'powershell -ExecutionPolicy Bypass -File "{remote_path}"'
                        stdin, stdout, stderr = ssh.exec_command(comando)
                        saida = stdout.read().decode(errors='ignore')
                        erro = stderr.read().decode(errors='ignore')
                        ssh.exec_command(f'del "{remote_path}"')
                        if erro.strip() or 'Exception' in saida:
                            log_falhas.append(f'Usuário: {usuario} - ERRO: {erro or saida}')
                        else:
                            log_falhas.append(f'Usuário: {usuario} - OK')
                    except Exception as e:
                        log_falhas.append(f'Usuário: {usuario} - EXCEPTION: {e}')
                ssh.close()
            except Exception as e:
                log_falhas.append(f'Falha geral: {e}')
            # Salvar log em arquivo .txt na pasta do programa
            import os
            from datetime import datetime
            log_text = '\n'.join(log_falhas)
            log_path = os.path.join(os.getcwd(), 'log_criacao_lote.txt')
            try:
                with open(log_path, 'a') as f:
                    f.write(f"\n--- {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} ---\n")
                    f.write(log_text + '\n')
            except Exception:
                pass
            # Apenas informar que o log foi gerado
            messagebox.showinfo('Concluído', f'Processo finalizado. Um log foi gerado em:\n{log_path}')
        btn_criar.config(command=criar_usuarios_lote_exec)

    def criar_usuario_individual(self):
        # Limpa painel central
        for widget in self.painel_central.winfo_children():
            widget.destroy()
        # Variáveis compartilhadas como atributos do objeto
        self.painel_usuario = tk.Frame(self.painel_central, bg=CorContraste)
        label_usuario = tk.Label(self.painel_usuario, text="Nome de Usuário:", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        self.entry_usuario = tk.Entry(self.painel_usuario, font=FONTE_PADRAO_TEXTO)
        label_usuario.pack(anchor='w', padx=10)
        self.entry_usuario.pack(anchor='w', padx=10, pady=5)
        self.btn_criar = tk.Button(self.painel_usuario, text="Criar Usuário", font=FONTE_PADRAO, bg=CorSelecao, fg='white')
        self.btn_criar.pack(padx=10, pady=10)
        self.painel_usuario.pack_forget()
        self.painel_turma = tk.Frame(self.painel_central, bg=CorContraste)
        label_turma = tk.Label(self.painel_turma, text="Selecione a turma:", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        self.combo_turma = ttk.Combobox(self.painel_turma, state='readonly', font=FONTE_PADRAO_TEXTO)
        label_turma.pack(anchor='w', padx=10)
        self.combo_turma.pack(anchor='w', padx=10, pady=5)
        self.painel_turma.pack_forget()
        self.turmas_dn = {}
        self.cursos_dn = {}
        painel_curso = tk.Frame(self.painel_central, bg=CorContraste)
        painel_curso.pack(fill='x', pady=10)
        tk.Label(painel_curso, text="Selecione o curso:", bg=CorContraste, fg='white', font=FONTE_PADRAO).pack(anchor='w', padx=10)
        self.combo_curso = ttk.Combobox(painel_curso, state='readonly', font=FONTE_PADRAO_TEXTO)
        self.combo_curso.pack(anchor='w', padx=10, pady=5)
        # Botão Voltar no rodapé
        painel_voltar = tk.Frame(self.painel_central, bg=CorContraste)
        painel_voltar.pack(side='bottom', fill='x', pady=10)
        btn_voltar = tk.Button(
            painel_voltar,
            text="Voltar",
            command=self._criar_botoes,
            bg=CorPrincipal,
            fg='white',
            activebackground=CorSelecao,
            activeforeground='white',
            relief='flat',
            font=FONTE_PADRAO_MENOR
        )
        btn_voltar.pack(pady=10)
        # Buscar cursos (OUs de ALUNOS + Professores)
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            comando_cursos = (
                f"powershell -Command \"Get-ADOrganizationalUnit -SearchBase '{OU_USUARIOS}' -SearchScope OneLevel -Filter * | Select-Object Name,DistinguishedName | ConvertTo-Json\""
            )
            stdin, stdout, stderr = ssh.exec_command(comando_cursos)
            cursos_bytes = stdout.read()
            erro_cursos = stderr.read()
            ssh.close()
            cursos_str = erro_cursos_str = None
            for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                try:
                    cursos_str = cursos_bytes.decode(encoding)
                    erro_cursos_str = erro_cursos.decode(encoding)
                    break
                except Exception:
                    continue
            if erro_cursos_str and erro_cursos_str.strip():
                raise Exception(f'PowerShell: {erro_cursos_str}')
            import json
            cursos_list = json.loads(cursos_str) if cursos_str and cursos_str.strip() else []
            if isinstance(cursos_list, dict):
                cursos_list = [cursos_list]
            self.cursos_dn = {c['Name']: c['DistinguishedName'] for c in cursos_list if 'Name' in c and 'DistinguishedName' in c}
            # Sempre adiciona a opção Professores manualmente
            self.cursos_dn['Professores'] = 'OU=PROFESSORES,OU=LABORATORIO,DC=LAB,DC=ET'
            if not self.cursos_dn:
                raise Exception('Nenhum curso ou OU de Professores encontrado no AD.')
            self.combo_curso['values'] = list(self.cursos_dn.keys())
        except Exception as e:
            self.combo_curso['values'] = []
            messagebox.showerror('Erro', f'Erro ao buscar cursos: {e}')
        def ao_selecionar_curso(event):
            self.painel_turma.pack_forget()
            self.painel_usuario.pack_forget()
            curso = self.combo_curso.get()
            if curso == 'Professores':
                self.painel_usuario.pack(fill='x', pady=10)
            else:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(
                        hostname=SERVIDOR_IP,
                        username=USUARIO_AD.split('\\')[-1],
                        password=SENHA_AD,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    curso_dn = self.cursos_dn[curso]
                    comando_turmas = (
                        f"powershell -Command \"Get-ADOrganizationalUnit -SearchBase '{curso_dn}' -SearchScope OneLevel -Filter * | Select-Object Name,DistinguishedName | ConvertTo-Json\""
                    )
                    stdin, stdout, stderr = ssh.exec_command(comando_turmas)
                    turmas_bytes = stdout.read()
                    erro_turmas = stderr.read()
                    ssh.close()
                    for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                        try:
                            turmas_str = turmas_bytes.decode(encoding)
                            erro_turmas_str = erro_turmas.decode(encoding)
                            break
                        except Exception:
                            turmas_str = erro_turmas_str = None
                    if erro_turmas_str:
                        raise Exception(erro_turmas_str)
                    import json
                    turmas_list = json.loads(turmas_str) if turmas_str and turmas_str.strip() else []
                    if isinstance(turmas_list, dict):
                        turmas_list = [turmas_list]
                    self.turmas_dn = {t['Name']: t['DistinguishedName'] for t in turmas_list if 'Name' in t and 'DistinguishedName' in t}
                    self.combo_turma['values'] = list(self.turmas_dn.keys())
                except Exception as e:
                    self.combo_turma['values'] = []
                    messagebox.showerror('Erro', f'Erro ao buscar turmas: {e}')
                self.painel_turma.pack(fill='x', pady=10)
                self.painel_usuario.pack_forget()

        self.combo_curso.bind('<<ComboboxSelected>>', ao_selecionar_curso)

        def ao_selecionar_turma(event):
            self.painel_usuario.pack(fill='x', pady=10)
        self.combo_turma.bind('<<ComboboxSelected>>', ao_selecionar_turma)

        def criar_usuario():
            curso = self.combo_curso.get()
            turma = self.combo_turma.get() if curso != 'Professores' else ''
            nome_usuario = self.entry_usuario.get().strip()
            if not curso or (curso != 'Professores' and not turma) or not nome_usuario:
                messagebox.showerror('Erro', 'Preencha todos os campos.')
                return
            if not nome_usuario.isalnum():
                messagebox.showerror('Erro', 'O nome de usuário deve ser alfanumérico.')
                return
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=SERVIDOR_IP,
                    username=USUARIO_AD.split('\\')[-1],
                    password=SENHA_AD,
                    look_for_keys=False,
                    allow_agent=False
                )
                if curso == 'Professores':
                    ou_dn = self.cursos_dn['Professores']
                    pasta_fisica = f'F:\\ARQUIVOS\\Professores\\{nome_usuario}'
                else:
                    ou_dn = self.turmas_dn[turma]
                    pasta_fisica = f'F:\\ARQUIVOS\\Alunos\\{curso}\\{turma}\\{nome_usuario}'
                compartilhamento = f'\\\\DC-LAB\\{nome_usuario}$'
                home_directory = compartilhamento
                # Buscar grupo da turma
                if curso == 'Professores':
                    comando_grupo = f"powershell -Command \"Get-ADGroup -SearchBase '{ou_dn}' -SearchScope OneLevel -Filter * | Select-Object Name | ConvertTo-Json\""
                else:
                    comando_grupo = f"powershell -Command \"Get-ADGroup -SearchBase '{ou_dn}' -SearchScope OneLevel -Filter * | Select-Object Name | ConvertTo-Json\""
                stdin, stdout, stderr = ssh.exec_command(comando_grupo)
                grupo_bytes = stdout.read()
                erro_grupo = stderr.read()
                for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                    try:
                        grupo_str = grupo_bytes.decode(encoding)
                        erro_grupo_str = erro_grupo.decode(encoding)
                        break
                    except Exception:
                        grupo_str = erro_grupo_str = None
                if erro_grupo_str:
                    raise Exception(erro_grupo_str)
                grupo_list = json.loads(grupo_str) if grupo_str and grupo_str.strip() else []
                if isinstance(grupo_list, dict):
                    grupo_list = [grupo_list]
                grupo_nome = grupo_list[0]['Name'] if grupo_list else ''
                # Script de criação
                script_ps = f'''
$ErrorActionPreference = 'Stop'
$login = '{nome_usuario}'
$senha = ConvertTo-SecureString '1234' -AsPlainText -Force
$ou = '{ou_dn}'
$grupo = '{grupo_nome}'
$pasta = '{pasta_fisica}'
# Cria usuário
$user = New-ADUser -Name $login -SamAccountName $login -GivenName $login -Surname $login -AccountPassword $senha -Enabled $true -Path $ou -ChangePasswordAtLogon $false -HomeDirectory '{home_directory}' -HomeDrive 'U:' -PassThru
# Adiciona ao grupo
if ($grupo) {{ Add-ADGroupMember -Identity $grupo -Members $login }}
# Cria pasta se não existir
if (!(Test-Path $pasta)) {{ New-Item -Path $pasta -ItemType Directory }}
# Permissões NTFS
$acl = Get-Acl $pasta
$acl.SetAccessRuleProtection($true, $false)
$acl.Access | ForEach-Object {{ $acl.RemoveAccessRule($_) }}
$ruleSistema = New-Object System.Security.AccessControl.FileSystemAccessRule("SISTEMA","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.AddAccessRule($ruleSistema)
$ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule("{DOMINIO_AD}\\$login","Modify","ContainerInherit,ObjectInherit","None","Allow")
$ruleProf = New-Object System.Security.AccessControl.FileSystemAccessRule("{DOMINIO_AD}\\Professor","Modify","ContainerInherit,ObjectInherit","None","Allow")
$ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule("Administradores","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$acl.AddAccessRule($ruleUser)
$acl.AddAccessRule($ruleProf)
$acl.AddAccessRule($ruleAdmins)
Set-Acl $pasta $acl
# Compartilhamento oculto
$share = $login + '$'
if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {{
    Revoke-SmbShareAccess -Name $share -AccountName 'Everyone' -Force -Confirm:$false
}}
if (!(Get-SmbShare -Name $share -ErrorAction SilentlyContinue)) {{
    New-SmbShare -Name $share -Path $pasta -FullAccess "Administradores" -ChangeAccess "{DOMINIO_AD}\\$login","{DOMINIO_AD}\\Professor"
}} else {{
    Grant-SmbShareAccess -Name $share -AccountName "{DOMINIO_AD}\\$login" -AccessRight Change -Force
    Grant-SmbShareAccess -Name $share -AccountName "{DOMINIO_AD}\\Professor" -AccessRight Change -Force
    Grant-SmbShareAccess -Name $share -AccountName "Administradores" -AccessRight Full -Force
    Revoke-SmbShareAccess -Name $share -AccountName 'Everyone' -Force -Confirm:$false
}}
Write-Output 'OK'
'''
                import tempfile, os
                with tempfile.NamedTemporaryFile('w', delete=False, suffix='.ps1') as f:
                    f.write(script_ps)
                    temp_script_path = f.name
                sftp = ssh.open_sftp()
                remote_path = f'C:/Windows/Temp/criar_usuario_individual_{nome_usuario}_{os.getpid()}.ps1'
                sftp.put(temp_script_path, remote_path)
                sftp.close()
                os.unlink(temp_script_path)
                comando = f'powershell -ExecutionPolicy Bypass -File "{remote_path}"'
                stdin, stdout, stderr = ssh.exec_command(comando)
                saida = stdout.read().decode(errors='ignore')
                erro = stderr.read().decode(errors='ignore')
                ssh.exec_command(f'del "{remote_path}"')
                ssh.close()
                if erro.strip() or 'Exception' in saida:
                    messagebox.showerror('Erro', erro or saida)
                else:
                    messagebox.showinfo('Sucesso', f'Usuário "{nome_usuario}" criado com sucesso!')
                    self.entry_usuario.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror('Erro', f'Erro ao criar usuário: {e}')
        self.btn_criar.config(command=criar_usuario)

    def gerenciar_usuarios(self):
        # Limpa painel central
        for widget in self.painel_central.winfo_children():
            widget.destroy()

        # Painel árvore de OUs e usuários
        painel_arvore = tk.Frame(self.painel_central, bg=CorContraste)
        painel_arvore.pack(fill='both', expand=True)
        style = ttk.Style()
        style.theme_use('default')
        style.configure('Treeview', background=CorContraste, fieldbackground=CorContraste, foreground='white', font=FONTE_PADRAO_TEXTO)
        style.configure('Treeview.Heading', background=CorPrincipal, foreground='white', font=FONTE_PADRAO_MENOR)
        tree = ttk.Treeview(painel_arvore, selectmode='browse')
        tree.pack(side='left', fill='both', expand=True)
        scrollbar = tk.Scrollbar(painel_arvore, orient="vertical", command=tree.yview)
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        tree.heading('#0', text='Organizational Units / Usuários', anchor='w')

        # Painel de ações
        painel_acoes = tk.Frame(self.painel_central, bg=CorContraste)
        painel_acoes.pack(fill='x')
        label_acoes = tk.Label(painel_acoes, text="Ações para o Usuário Selecionado", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_acoes.pack(anchor='w', padx=10, pady=(10, 0))
        frame_botoes = tk.Frame(painel_acoes, bg=CorContraste)
        frame_botoes.pack(anchor='w', padx=10, pady=5)

        # Painel voltar
        painel_voltar = tk.Frame(self.painel_central, bg=CorContraste)
        painel_voltar.pack(fill='x')
        btn_voltar = tk.Button(
            painel_voltar,
            text="Voltar",
            command=self._criar_botoes,
            bg=CorPrincipal,
            fg='white',
            activebackground=CorSelecao,
            activeforeground='white',
            relief='flat',
            font=FONTE_PADRAO_MENOR
        )
        btn_voltar.pack(pady=20)

        # Buscar OUs e usuários SOMENTE da OU ALUNOS
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            OU_ALUNOS = 'OU=ALUNOS,OU=LABORATORIO,DC=LAB,DC=ET'
            comando_ou = (
                f"powershell -Command \"Get-ADOrganizationalUnit -SearchBase '{OU_ALUNOS}' -SearchScope Subtree -Filter * | Select-Object DistinguishedName,Name | ConvertTo-Json\""
            )
            stdin, stdout, stderr = ssh.exec_command(comando_ou)
            ou_bytes = stdout.read()
            erro_ou = stderr.read()
            comando_usuarios = (
                f"powershell -Command \"Get-ADUser -SearchBase '{OU_ALUNOS}' -SearchScope Subtree -Filter * | Select-Object DistinguishedName,Name,Enabled | ConvertTo-Json\""
            )
            stdin, stdout, stderr = ssh.exec_command(comando_usuarios)
            usuarios_bytes = stdout.read()
            erro_usuarios = stderr.read()
            ssh.close()
            for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                try:
                    ou_str = ou_bytes.decode(encoding)
                    erro_ou_str = erro_ou.decode(encoding)
                    usuarios_str = usuarios_bytes.decode(encoding)
                    erro_usuarios_str = erro_usuarios.decode(encoding)
                    break
                except Exception:
                    ou_str = erro_ou_str = usuarios_str = erro_usuarios_str = None
            if erro_ou_str or erro_usuarios_str:
                raise Exception(erro_ou_str or erro_usuarios_str)
        except Exception as e:
            tk.Label(self.painel_central, text=f'Erro ao buscar OUs/Usuários: {e}', bg=CorContraste, fg='red', font=FONTE_ERRO).pack()
            return
        try:
            ou_list = json.loads(ou_str) if ou_str.strip() else []
            usuarios_list = json.loads(usuarios_str) if usuarios_str.strip() else []
            if isinstance(ou_list, dict):
                ou_list = [ou_list]
            if isinstance(usuarios_list, dict):
                usuarios_list = [usuarios_list]
        except Exception:
            ou_list = []
            usuarios_list = []

        def get_parent_dn(dn):
            # Retorna o DN do pai (remove apenas o primeiro elemento OU/USER)
            partes = dn.split(',')
            if len(partes) > 1:
                return ','.join(partes[1:])
            return ''

        # Monta árvore de OUs (igual função 1, mas para ALUNOS)
        ou_by_dn_usu = {ou['DistinguishedName']: ou for ou in ou_list if 'DistinguishedName' in ou}
        children_usu = {}
        for ou in ou_list:
            parent_dn = get_parent_dn(ou['DistinguishedName'])
            children_usu.setdefault(parent_dn, []).append(ou['DistinguishedName'])
        root_dn_usu = OU_ALUNOS

        def insert_ou_recursive_usuarios(parent, parent_dn):
            ou_children_dns = sorted(children_usu.get(parent_dn, []), key=lambda dn: ou_by_dn_usu[dn].get('Name', '').lower())
            for ou_dn in ou_children_dns:
                ou_name = ou_by_dn_usu[ou_dn].get('Name', ou_dn)
                ou_id = tree.insert(parent, 'end', text=ou_name, open=False)
                insert_ou_recursive_usuarios(ou_id, ou_dn)
                # Insere usuários desta OU
                usuarios_ou = [u for u in usuarios_list if get_parent_dn(u.get('DistinguishedName', '')) == ou_dn]
                usuarios_ou = sorted(usuarios_ou, key=lambda u: u.get('Name', '').lower())
                for user in usuarios_ou:
                    user_name = user.get('Name')
                    enabled = user.get('Enabled', True)
                    display = f"{user_name} ({'Ativo' if enabled else 'Desabilitado'})"
                    tree.insert(ou_id, 'end', text=display, values=(user.get('DistinguishedName'), enabled))

        # Limpa a treeview
        for item in tree.get_children():
            tree.delete(item)
        # Insere a raiz e recursivamente as OUs e usuários
        root_id_usu = tree.insert('', 'end', text=ou_by_dn_usu[root_dn_usu]['Name'] if root_dn_usu in ou_by_dn_usu else 'ALUNOS', open=True)
        insert_ou_recursive_usuarios(root_id_usu, root_dn_usu)

        def on_tree_select(event):
            for widget in frame_botoes.winfo_children():
                widget.destroy()
            item_id = tree.focus()
            if not item_id:
                return
            item_values = tree.item(item_id, 'values')
            item_text = tree.item(item_id, 'text')
            parent_id = tree.parent(item_id)
            # Só exibe botões se for usuário (folha, não OU)
            if parent_id and not tree.get_children(item_id):
                dn = item_values[0] if item_values else None
                enabled = item_values[1] if len(item_values) > 1 else True
                # Botão Senha
                btn_senha = tk.Button(
                    frame_botoes,
                    text="Senha",
                    command=lambda: self.alterar_senha_usuario(dn),
                    bg=CorPrincipal,
                    fg='white',
                    activebackground=CorSelecao,
                    activeforeground='white',
                    relief='flat',
                    font=FONTE_PADRAO_MENOR
                )
                btn_senha.pack(side='left', padx=5)
                # Botão Informações
                btn_info = tk.Button(
                    frame_botoes,
                    text="Informações",
                    command=lambda: self.info_usuario(dn),
                    bg=CorPrincipal,
                    fg='white',
                    activebackground=CorSelecao,
                    activeforeground='white',
                    relief='flat',
                    font=FONTE_PADRAO_MENOR
                )
                btn_info.pack(side='left', padx=5)
                # Botão Excluir
                btn_excluir = tk.Button(
                    frame_botoes,
                    text="Excluir",
                    command=lambda: self.excluir_usuario(dn, item_text),
                    bg=CorPrincipal,
                    fg='white',
                    activebackground=CorSelecao,
                    activeforeground='white',
                    relief='flat',
                    font=FONTE_PADRAO_MENOR
                )
                btn_excluir.pack(side='left', padx=5)
                # Botão Habilitar/Desabilitar
                if str(enabled).lower() in ['false', '0']:
                    texto_hab = "Habilitar"
                    novo_status = True
                else:
                    texto_hab = "Desabilitar"
                    novo_status = False
                btn_hab = tk.Button(
                    frame_botoes,
                    text=texto_hab,
                    command=lambda: self.habilitar_desabilitar_usuario(dn, novo_status),
                    bg=CorPrincipal,
                    fg='white',
                    activebackground=CorSelecao,
                    activeforeground='white',
                    relief='flat',
                    font=FONTE_PADRAO_MENOR
                )
                btn_hab.pack(side='left', padx=5)
        tree.bind('<<TreeviewSelect>>', on_tree_select)

    def alterar_senha_usuario(self, dn):
        nova_senha = simpledialog.askstring('Alterar Senha', 'Digite a nova senha:', show='*')
        if not nova_senha:
            return
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            comando = f"powershell -Command \"Set-ADAccountPassword -Identity '{dn}' -Reset -NewPassword (ConvertTo-SecureString '{nova_senha}' -AsPlainText -Force)\""
            stdin, stdout, stderr = ssh.exec_command(comando)
            erro = stderr.read().decode(errors='ignore')
            ssh.close()
            if erro.strip():
                messagebox.showerror('Erro', f'Erro ao alterar senha: {erro}')
            else:
                messagebox.showinfo('Sucesso', 'Senha alterada com sucesso!')
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao alterar senha: {e}')

    def info_usuario(self, dn):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            comando = f"powershell -Command \"Get-ADUser -Identity '{dn}' -Properties * | Select-Object Name,Enabled,MemberOf,HomeDirectory | ConvertTo-Json\""
            stdin, stdout, stderr = ssh.exec_command(comando)
            info_bytes = stdout.read()
            erro = stderr.read()
            ssh.close()
            for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                try:
                    info_str = info_bytes.decode(encoding)
                    erro_str = erro.decode(encoding)
                    break
                except Exception:
                    info_str = erro_str = None
            if erro_str:
                raise Exception(erro_str)
            info = json.loads(info_str) if info_str and info_str.strip() else {}
            grupos = info.get('MemberOf', [])
            if isinstance(grupos, str):
                grupos = [grupos]
            msg = f"Usuário: {info.get('Name', '')}\nStatus: {'Ativo' if info.get('Enabled', True) else 'Desabilitado'}\nGrupos:\n" + '\n'.join(grupos) + f"\nHomeDirectory: {info.get('HomeDirectory', '')}"
            messagebox.showinfo('Informações do Usuário', msg)
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao buscar informações: {e}')

    def excluir_usuario(self, dn, nome_usuario):
        if not messagebox.askyesno('Confirmação', f'Tem certeza que deseja excluir o usuário "{nome_usuario}"?'):
            return
        if not messagebox.askyesno('Confirmação', f'Esta ação é irreversível. Deseja realmente excluir "{nome_usuario}"?'):
            return
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            comando = f"powershell -Command \"Remove-ADUser -Identity '{dn}' -Confirm:$false\""
            stdin, stdout, stderr = ssh.exec_command(comando)
            erro = stderr.read().decode(errors='ignore')
            ssh.close()
            if erro.strip():
                messagebox.showerror('Erro', f'Erro ao excluir usuário: {erro}')
            else:
                messagebox.showinfo('Sucesso', f'Usuário "{nome_usuario}" excluído com sucesso!')
                self.gerenciar_usuarios()
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao excluir usuário: {e}')

    def habilitar_desabilitar_usuario(self, dn, habilitar):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            if habilitar:
                comando = f"powershell -Command \"Enable-ADAccount -Identity '{dn}'\""
            else:
                comando = f"powershell -Command \"Disable-ADAccount -Identity '{dn}'\""
            stdin, stdout, stderr = ssh.exec_command(comando)
            erro = stderr.read().decode(errors='ignore')
            ssh.close()
            if erro.strip():
                messagebox.showerror('Erro', f'Erro ao alterar status: {erro}')
            else:
                messagebox.showinfo('Sucesso', f'Usuário {'habilitado' if habilitar else 'desabilitado'} com sucesso!')
                self.gerenciar_usuarios()
        except Exception as e:
            messagebox.showerror('Erro', f'Erro ao alterar status: {e}')

    def recompartilhar_pastas(self):
        import os, tempfile
        from datetime import datetime
        # Limpa painel central
        for widget in self.painel_central.winfo_children():
            widget.destroy()

        painel_curso = tk.Frame(self.painel_central, bg=CorContraste)
        painel_curso.pack(fill='x', pady=10)
        tk.Label(painel_curso, text="Qual Curso deseja Selecionar?", bg=CorContraste, fg='white', font=FONTE_PADRAO).pack(anchor='w', padx=10)
        combo_curso = ttk.Combobox(painel_curso, state='readonly', font=FONTE_PADRAO_TEXTO)
        combo_curso.pack(anchor='w', padx=10, pady=5)

        painel_turma = tk.Frame(self.painel_central, bg=CorContraste)
        painel_turma.pack_forget()
        label_turma = tk.Label(painel_turma, text="Qual Turma deseja Selecionar", bg=CorContraste, fg='white', font=FONTE_PADRAO)
        label_turma.pack(anchor='w', padx=10)
        combo_turma = ttk.Combobox(painel_turma, state='readonly', font=FONTE_PADRAO_TEXTO)
        combo_turma.pack(anchor='w', padx=10, pady=5)

        btn_exec = tk.Button(self.painel_central, text="ReCompartilhar", font=FONTE_PADRAO, bg=CorSelecao, fg='white')
        btn_exec.pack_forget()

        painel_voltar = tk.Frame(self.painel_central, bg=CorContraste)
        painel_voltar.pack(side='bottom', fill='x', pady=10)
        btn_voltar = tk.Button(
            painel_voltar,
            text="Voltar",
            command=self._criar_botoes,
            bg=CorPrincipal,
            fg='white',
            activebackground=CorSelecao,
            activeforeground='white',
            relief='flat',
            font=FONTE_PADRAO_MENOR
        )
        btn_voltar.pack(pady=10)

        cursos_dn = {}
        try:
            import paramiko, json
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=SERVIDOR_IP,
                username=USUARIO_AD.split('\\')[-1],
                password=SENHA_AD,
                look_for_keys=False,
                allow_agent=False
            )
            comando_cursos = (
                f"powershell -Command \"Get-ADOrganizationalUnit -SearchBase 'OU=ALUNOS,OU=LABORATORIO,DC=LAB,DC=ET' -SearchScope OneLevel -Filter * | Select-Object Name,DistinguishedName | ConvertTo-Json\""
            )
            stdin, stdout, stderr = ssh.exec_command(comando_cursos)
            cursos_bytes = stdout.read()
            erro_cursos = stderr.read()
            ssh.close()
            cursos_str = erro_cursos_str = None
            for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                try:
                    cursos_str = cursos_bytes.decode(encoding)
                    erro_cursos_str = erro_cursos.decode(encoding)
                    break
                except Exception:
                    cursos_str = erro_cursos_str = None
            if erro_cursos_str and erro_cursos_str.strip():
                raise Exception(f'PowerShell: {erro_cursos_str}')
            cursos_list = json.loads(cursos_str) if cursos_str and cursos_str.strip() else []
            if isinstance(cursos_list, dict):
                cursos_list = [cursos_list]
            cursos_dn = {c['Name']: c['DistinguishedName'] for c in cursos_list if 'Name' in c and 'DistinguishedName' in c}
            combo_curso['values'] = list(cursos_dn.keys())
        except Exception as e:
            combo_curso['values'] = []
            tk.messagebox.showerror('Erro', f'Erro ao buscar cursos: {e}')

        turmas_dn = {}
        def ao_selecionar_curso(event):
            painel_turma.pack_forget()
            btn_exec.pack_forget()
            curso = combo_curso.get()
            if not curso:
                return
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=SERVIDOR_IP,
                    username=USUARIO_AD.split('\\')[-1],
                    password=SENHA_AD,
                    look_for_keys=False,
                    allow_agent=False
                )
                comando_turmas = (
                    f"powershell -Command \"Get-ADOrganizationalUnit -SearchBase '{cursos_dn[curso]}' -SearchScope OneLevel -Filter * | Select-Object Name,DistinguishedName | ConvertTo-Json\""
                )
                stdin, stdout, stderr = ssh.exec_command(comando_turmas)
                turmas_bytes = stdout.read()
                erro_turmas = stderr.read()
                ssh.close()
                turmas_str = erro_turmas_str = None
                for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                    try:
                        turmas_str = turmas_bytes.decode(encoding)
                        erro_turmas_str = erro_turmas.decode(encoding)
                        break
                    except Exception:
                        turmas_str = erro_turmas_str = None
                if erro_turmas_str and erro_turmas_str.strip():
                    raise Exception(f'PowerShell: {erro_turmas_str}')
                turmas_list = json.loads(turmas_str) if turmas_str and turmas_str.strip() else []
                if isinstance(turmas_list, dict):
                    turmas_list = [turmas_list]
                turmas_dn.clear()
                turmas_dn.update({t['Name']: t['DistinguishedName'] for t in turmas_list if 'Name' in t and 'DistinguishedName' in t})
                combo_turma['values'] = list(turmas_dn.keys())
                painel_turma.pack(fill='x', pady=10)
            except Exception as e:
                combo_turma['values'] = []
                tk.messagebox.showerror('Erro', f'Erro ao buscar turmas: {e}')

        combo_curso.bind('<<ComboboxSelected>>', ao_selecionar_curso)

        def ao_selecionar_turma(event):
            btn_exec.pack(padx=10, pady=10)
        combo_turma.bind('<<ComboboxSelected>>', ao_selecionar_turma)

        def recompartilhar_exec():
            curso = combo_curso.get()
            turma = combo_turma.get()
            if not curso or not turma:
                tk.messagebox.showerror('Erro', 'Selecione curso e turma.')
                return
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(
                    hostname=SERVIDOR_IP,
                    username=USUARIO_AD.split('\\')[-1],
                    password=SENHA_AD,
                    look_for_keys=False,
                    allow_agent=False
                )
                ou_turma_dn = turmas_dn[turma]
                comando_usuarios = (
                    f"powershell -Command \"Get-ADUser -SearchBase '{ou_turma_dn}' -SearchScope OneLevel -Filter * | Select-Object SamAccountName | ConvertTo-Json\""
                )
                stdin, stdout, stderr = ssh.exec_command(comando_usuarios)
                usuarios_bytes = stdout.read()
                erro_usuarios = stderr.read()
                usuarios_str = erro_usuarios_str = None
                for encoding in ('utf-8', 'utf-16-le', 'cp850', 'latin1'):
                    try:
                        usuarios_str = usuarios_bytes.decode(encoding)
                        erro_usuarios_str = erro_usuarios.decode(encoding)
                        break
                    except Exception:
                        usuarios_str = erro_usuarios_str = None
                if erro_usuarios_str and erro_usuarios_str.strip():
                    raise Exception(f'PowerShell: {erro_usuarios_str}')
                usuarios_list = json.loads(usuarios_str) if usuarios_str and usuarios_str.strip() else []
                if isinstance(usuarios_list, dict):
                    usuarios_list = [usuarios_list]
                ssh.close()
            except Exception as e:
                tk.messagebox.showerror('Erro', f'Erro ao buscar usuários: {e}')
                return

            log_falhas = []
            for usuario in usuarios_list:
                login = usuario.get('SamAccountName')
                if not login:
                    continue
                pasta_fisica = f'F:\\ARQUIVOS\\Alunos\\{curso}\\{turma}\\{login}'
                script_ps = (
                    f"$ErrorActionPreference = 'Stop'\n"
                    f"$login = '{login}'\n"
                    f"$pasta = '{pasta_fisica}'\n"
                    f"$share = $login + '$'\n"
                    f"if (!(Test-Path $pasta)) {{ New-Item -Path $pasta -ItemType Directory }}\n"
                    f"$acl = Get-Acl $pasta\n"
                    f"$acl.SetAccessRuleProtection($true, $false)\n"
                    f"$acl.Access | ForEach-Object {{ $acl.RemoveAccessRule($_) }}\n"
                    f"$ruleSistema = New-Object System.Security.AccessControl.FileSystemAccessRule('SISTEMA','FullControl','ContainerInherit,ObjectInherit','None','Allow')\n"
                    f"$acl.AddAccessRule($ruleSistema)\n"
                    f"$ruleUser = New-Object System.Security.AccessControl.FileSystemAccessRule('{DOMINIO_AD}\\{login}','Modify','ContainerInherit,ObjectInherit','None','Allow')\n"
                    f"$ruleProf = New-Object System.Security.AccessControl.FileSystemAccessRule('{DOMINIO_AD}\\Professor','Modify','ContainerInherit,ObjectInherit','None','Allow')\n"
                    f"$ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule('Administradores','FullControl','ContainerInherit,ObjectInherit','None','Allow')\n"
                    f"$acl.AddAccessRule($ruleUser)\n"
                    f"$acl.AddAccessRule($ruleProf)\n"
                    f"$acl.AddAccessRule($ruleAdmins)\n"
                    f"Set-Acl $pasta $acl\n"
                    f"if (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {{ Revoke-SmbShareAccess -Name $share -AccountName 'Everyone' -Force -Confirm:$false }}\n"
                    f"if (!(Get-SmbShare -Name $share -ErrorAction SilentlyContinue)) {{ New-SmbShare -Name $share -Path $pasta -FullAccess 'Administradores' -ChangeAccess '{DOMINIO_AD}\\{login}','{DOMINIO_AD}\\Professor' }} else {{ Grant-SmbShareAccess -Name $share -AccountName '{DOMINIO_AD}\\{login}' -AccessRight Change -Force; Grant-SmbShareAccess -Name $share -AccountName '{DOMINIO_AD}\\Professor' -AccessRight Change -Force; Grant-SmbShareAccess -Name $share -AccountName 'Administradores' -AccessRight Full -Force; Revoke-SmbShareAccess -Name $share -AccountName 'Everyone' -Force -Confirm:$false }}\n"
                    f"Write-Output 'OK'\n"
                )
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(
                        hostname=SERVIDOR_IP,
                        username=USUARIO_AD.split('\\')[-1],
                        password=SENHA_AD,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.ps1') as f:
                        f.write(script_ps)
                        temp_script_path = f.name
                    remote_path = f'C:/Windows/Temp/recompartilhar_{login}_{os.getpid()}.ps1'
                    sftp = ssh.open_sftp()
                    sftp.put(temp_script_path, remote_path)
                    sftp.close()
                    os.unlink(temp_script_path)
                    comando = f'powershell -ExecutionPolicy Bypass -File "{remote_path}"'
                    stdin, stdout, stderr = ssh.exec_command(comando)
                    saida = stdout.read().decode(errors='ignore')
                    erro = stderr.read().decode(errors='ignore')
                    ssh.exec_command(f'del "{remote_path}"')
                    ssh.close()
                    if erro.strip() or 'Exception' in saida:
                        log_falhas.append(f'{login}: {erro or saida}')
                except Exception as e:
                    log_falhas.append(f'{login}: {e}')

            log_path = os.path.join(os.getcwd(), 'log_compartilhamento.txt')
            try:
                with open(log_path, 'a', encoding='utf-8') as f:
                    if log_falhas:
                        f.write(f'[{datetime.now().strftime("%d/%m/%Y %H:%M:%S")}] Falhas ao recompartilhar turma {turma} do curso {curso}:\n')
                        for linha in log_falhas:
                            f.write(linha + '\n')
            except Exception:
                pass
            if log_falhas:
                tk.messagebox.showinfo('Concluído', f'Processo finalizado. Algumas falhas ocorreram. Um log foi gerado em:\n{log_path}')
            else:
                tk.messagebox.showinfo('Concluído', 'Processo finalizado com sucesso!')

        btn_exec.config(command=recompartilhar_exec)

    def sobre(self):
        messagebox.showinfo(
            "Sobre",
            "Gerenciador de Usuários AD - Windows Server 2025\nDesenvolvido por Cristiano Teixeira para uso na ET\nVersão: 3.11\nSuporte: LAB.ET\nLicença Apache 2.0"
        )

def main():
    try:
        print('Iniciando aplicação...')
        app = GerenciadorADApp()
        app.mainloop()
    except Exception as e:
        import traceback
        print('Erro ao iniciar aplicação:')
        traceback.print_exc()

if __name__ == "__main__":
    main()
