import sys
import json
import paramiko
from functools import partial
from PySide6.QtCore import Qt

# gestorad.py
# Mini gestor Active Directory via SSH com GUI PySide6
# Requisitos: pyside6, paramiko
# Uso: python gestorad.py
# Observação: o servidor Windows deve ter SSH ativo e PowerShell com módulo ActiveDirectory disponível.


from PySide6.QtWidgets import (
    QApplication, QMainWindow, QDialog, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QHBoxLayout, QWidget, QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit,
    QMessageBox, QInputDialog, QGroupBox, QFormLayout
)

# Ajuste conforme seu domínio/OU
BASE_OU_DN = "OU=AULA,DC=MEUDOMINIO,DC=AULA"


def ssh_connect(host, port, username, password, timeout=10):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout)
    return client


def run_powershell(client: paramiko.SSHClient, ps_command: str, timeout=30):
    # Executa comando PowerShell no servidor via SSH e retorna stdout (str)
    # Usa -EncodedCommand com Base64 (UTF-16LE) para evitar problemas de escape/aspas ao enviar o script
    import base64
    b = ps_command.encode("utf-16-le")
    enc = base64.b64encode(b).decode("ascii")
    wrapped = f"powershell -NoProfile -NonInteractive -EncodedCommand {enc}"
    stdin, stdout, stderr = client.exec_command(wrapped, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="ignore")
    err = stderr.read().decode("utf-8", errors="ignore")
    if err and not out:
        # Retornar erro também se apropriado
        raise RuntimeError(err.strip())
    return out.strip()


def ps_get_ad_objects_json(base_dn):
    # Monta comando PowerShell para obter objetos AD (OU, user, group) em JSON
    # Usar apenas um f-string para inserir base_dn e manter o restante como strings normais
    cmd = (
        "Import-Module ActiveDirectory; "
        f"$base = '{base_dn}'; "
        "$objs = Get-ADObject -SearchBase $base -SearchScope Subtree -Filter * "
        "-Properties objectClass,Name,DistinguishedName,SamAccountName,HomeDirectory,MemberOf | "
        "Select-Object @{Name='objectClass';Expression={ ($_.objectClass -join ',' ) }}, Name, DistinguishedName, SamAccountName, HomeDirectory, MemberOf; "
        "if ($objs -is [System.Array]) { $objs | ConvertTo-Json -Compress } else { @($objs) | ConvertTo-Json -Compress }"
    )
    return cmd


def ps_reset_password_cmd(identity, new_password):
    # identity pode ser SamAccountName ou DistinguishedName
    safe_pass = new_password.replace("'", "''")
    safe_id = identity.replace("'", "''")
    cmd = (
        f"Import-Module ActiveDirectory; "
        f"$pass = ConvertTo-SecureString '{safe_pass}' -AsPlainText -Force; "
        f"Set-ADAccountPassword -Identity '{safe_id}' -NewPassword $pass -Reset -ErrorAction Stop; "
        f"Unlock-ADAccount -Identity '{safe_id}' -ErrorAction SilentlyContinue; "
        f"Set-ADUser -Identity '{safe_id}' -ChangePasswordAtLogon $true -ErrorAction SilentlyContinue; "
        f"Write-Output 'OK'"
    )
    return cmd


def parse_cn_from_dn(dn):
    # extrai o CN (ou primeiro RDN) de um DN
    if not dn:
        return ""
    parts = dn.split(",", 1)
    return parts[0].split("=", 1)[-1].strip()


def parent_dn(dn):
    # remove o primeiro RDN: retorna parent DN
    if not dn:
        return ""
    parts = dn.split(",", 1)
    return parts[1].strip() if len(parts) > 1 else ""


class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Conectar ao servidor AD via SSH")
        self.host_edit = QLineEdit("seu.servidor.ad")
        self.port_edit = QLineEdit("22")
        self.user_edit = QLineEdit()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.Password)
        btn_ok = QPushButton("Conectar")
        btn_cancel = QPushButton("Cancelar")

        layout = QVBoxLayout()
        form = QFormLayout()
        form.addRow("Host:", self.host_edit)
        form.addRow("Porta:", self.port_edit)
        form.addRow("Usuário SSH:", self.user_edit)
        form.addRow("Senha:", self.pass_edit)
        layout.addLayout(form)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_ok)
        btn_layout.addWidget(btn_cancel)
        layout.addLayout(btn_layout)
        self.setLayout(layout)

        btn_ok.clicked.connect(self.accept)
        btn_cancel.clicked.connect(self.reject)

    def get_credentials(self):
        return self.host_edit.text().strip(), int(self.port_edit.text().strip()), self.user_edit.text().strip(), self.pass_edit.text()


class MainWindow(QMainWindow):
    def __init__(self, ssh_client, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Mini Gestor AD - AULA")
        self.ssh_client = ssh_client

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Nome", "Tipo"])
        self.tree.itemSelectionChanged.connect(self.on_selection_changed)

        # Painel direito
        self.info_group = QGroupBox("Informações")
        info_layout = QFormLayout()
        self.lbl_name = QLabel("")
        self.lbl_sam = QLabel("")
        self.lbl_home = QLabel("")
        self.txt_groups = QTextEdit()
        self.txt_groups.setReadOnly(True)
        self.btn_reset = QPushButton("Resetar senha")
        self.btn_reset.setEnabled(False)
        self.btn_reset.clicked.connect(self.on_reset_password)

        info_layout.addRow("Nome:", self.lbl_name)
        info_layout.addRow("SamAccountName:", self.lbl_sam)
        info_layout.addRow("Home:", self.lbl_home)
        info_layout.addRow("Grupos:", self.txt_groups)
        info_layout.addRow(self.btn_reset)
        self.info_group.setLayout(info_layout)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.tree)
        splitter.addWidget(self.info_group)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        self.setCentralWidget(splitter)
        self.statusBar().showMessage("Carregando objetos AD...")
        QApplication.processEvents()
        try:
            self.load_ad_tree()
            self.statusBar().showMessage("Pronto")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Falha ao carregar AD: {e}")
            self.statusBar().showMessage("Erro ao carregar AD")

    def load_ad_tree(self):
        cmd = ps_get_ad_objects_json(BASE_OU_DN)
        out = run_powershell(self.ssh_client, cmd)
        if not out:
            objs = []
        else:
            try:
                objs = json.loads(out)
            except Exception:
                # PowerShell pode devolver um único objeto (não array) já tratado no PS, mas como salvaguarda:
                try:
                    objs = json.loads(f"[{out}]")
                except Exception:
                    raise RuntimeError("Não foi possível interpretar a resposta JSON do servidor.")
        # objs é lista de dicts
        # construir dicionário por DN
        by_dn = {}
        for o in objs:
            dn = o.get("DistinguishedName") or ""
            by_dn[dn] = o

        # Cria nós para OUs primeiro, em níveis
        node_by_dn = {}
        # Garantir que a base também exista como nó raiz
        root_item = QTreeWidgetItem(self.tree, [parse_cn_from_dn(BASE_OU_DN), "OU"])
        node_by_dn[BASE_OU_DN] = root_item

        # Ordenar por profundidade para criar pais antes de filhos
        def depth_of_dn(dn):
            if not dn:
                return 0
            return dn.count(",")

        sorted_dns = sorted(by_dn.keys(), key=depth_of_dn)
        for dn in sorted_dns:
            obj = by_dn[dn]
            objclass = obj.get("objectClass", "")
            name = obj.get("Name") or parse_cn_from_dn(dn)
            display_type = "other"
            if "organizationalUnit" in objclass.lower():
                display_type = "OU"
            elif "user" in objclass.lower():
                display_type = "User"
            elif "group" in objclass.lower():
                display_type = "Group"
            # achar pai: se o DN estiver abaixo da BASE_OU_DN, encaixar; caso contrário, parent_dn
            parent = parent_dn(dn)
            # if parent is empty or not in node_by_dn, try to attach to BASE_OU_DN if DN endswith base
            parent_item = None
            if parent in node_by_dn:
                parent_item = node_by_dn[parent]
            else:
                # subir até achar
                cur = parent
                while cur and cur not in node_by_dn:
                    cur = parent_dn(cur)
                parent_item = node_by_dn.get(cur, root_item)

            item = QTreeWidgetItem(parent_item, [name, display_type])
            item.setData(0, Qt.UserRole, obj)  # armazenar objeto
            node_by_dn[dn] = item

        self.tree.expandAll()

    def on_selection_changed(self):
        items = self.tree.selectedItems()
        if not items:
            return
        item = items[0]
        obj = item.data(0, Qt.UserRole)
        if not obj:
            self.clear_info()
            return
        objclass = obj.get("objectClass", "")
        if "user" in objclass.lower():
            self.show_user_info(obj)
        else:
            self.clear_info()
            self.lbl_name.setText(obj.get("Name", ""))
            self.lbl_sam.setText(obj.get("SamAccountName") or "")
            self.btn_reset.setEnabled(False)

    def clear_info(self):
        self.lbl_name.setText("")
        self.lbl_sam.setText("")
        self.lbl_home.setText("")
        self.txt_groups.setPlainText("")
        self.btn_reset.setEnabled(False)

    def show_user_info(self, obj):
        self.lbl_name.setText(obj.get("Name", ""))
        self.lbl_sam.setText(obj.get("SamAccountName") or "")
        self.lbl_home.setText(obj.get("HomeDirectory") or "")
        memberof = obj.get("MemberOf") or []
        if isinstance(memberof, str):
            memberof = [memberof]
        group_names = [parse_cn_from_dn(g) for g in memberof]
        self.txt_groups.setPlainText("\n".join(group_names))
        self.btn_reset.setEnabled(True)

    def on_reset_password(self):
        items = self.tree.selectedItems()
        if not items:
            return
        item = items[0]
        obj = item.data(0, Qt.UserRole)
        if not obj:
            return
        sam = obj.get("SamAccountName") or obj.get("DistinguishedName")
        new_pass, ok = QInputDialog.getText(self, "Nova senha", f"Digite nova senha para {sam}:", QLineEdit.Password)
        if not ok or not new_pass:
            return
        confirm, ok2 = QInputDialog.getText(self, "Confirmar senha", f"Confirme nova senha para {sam}:", QLineEdit.Password)
        if not ok2 or confirm != new_pass:
            QMessageBox.warning(self, "Erro", "Senhas não conferem ou operação cancelada.")
            return
        self.statusBar().showMessage("Resetando senha...")
        QApplication.processEvents()
        try:
            cmd = ps_reset_password_cmd(sam, new_pass)
            out = run_powershell(self.ssh_client, cmd)
            if "OK" in out:
                QMessageBox.information(self, "Sucesso", "Senha resetada com sucesso. Usuário deverá trocar no próximo logon.")
                self.statusBar().showMessage("Senha resetada")
            else:
                QMessageBox.warning(self, "Resposta do servidor", f"Saída: {out}")
                self.statusBar().showMessage("Resposta do servidor")
        except Exception as e:
            QMessageBox.critical(self, "Erro", f"Falha ao resetar senha: {e}")
            self.statusBar().showMessage("Erro ao resetar senha")


def main():
    app = QApplication(sys.argv)
    login = LoginDialog()
    if login.exec() != QDialog.Accepted:
        return
    host, port, username, password = login.get_credentials()
    try:
        ssh = ssh_connect(host, port, username, password)
    except Exception as e:
        QMessageBox.critical(None, "Erro de conexão", f"Não foi possível conectar via SSH: {e}")
        return
    window = MainWindow(ssh)
    window.resize(900, 600)
    window.show()
    app.exec()
    try:
        ssh.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()