from urllib.parse import urlencode
import re
import requests
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QFileDialog, QTableWidget, 
                            QTableWidgetItem, QHeaderView, QMessageBox, QLabel,
                            QSpinBox, QTextEdit)
from PyQt6.QtCore import Qt, pyqtSignal, QObject

lock = threading.Lock()

class GetOAuth2Token:
   def __init__(self):
       self.client_id = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"
       self.redirect_uri = "https://localhost"
       self.base_url = "https://login.live.com"
       self.token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
       
   def _get_headers(self, additional_headers: dict = None):
       headers = {
           'accept': '*/*',
           'accept-encoding': 'gzip, deflate, br',
           'accept-language': 'en-US,en;q=0.9',
           'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
           'sec-ch-ua-mobile': '?0',
           'sec-ch-ua-platform': 'Windows',
           'sec-fetch-dest': 'empty',
           'sec-fetch-mode': 'cors',
           'sec-fetch-site': 'same-origin',
           'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Thunderbird/128.2.3'
       }
       if additional_headers:
           headers.update(additional_headers)
       return headers

   def _handle_consent_page(self, post_url: str, resp_content: str, cookies: dict):
       post_headers = self._get_headers({'content-type': "application/x-www-form-urlencoded"})
       
       matches = re.finditer("<input type=\"hidden\" name=\"(.*?)\" id=\"(.*?)\" value=\"(.*?)\"", resp_content)
       form_data = {match.group(1): match.group(3) for match in matches}
       
       encoded_data = urlencode(form_data)
       requests.post(post_url, data=encoded_data, headers=post_headers, cookies=cookies)
       
       form_data["ucaction"] = "Yes"
       encoded_data = urlencode(form_data)
       consent_resp = requests.post(post_url, data=encoded_data, headers=post_headers, 
                                  cookies=cookies, allow_redirects=False)
       
       redirect_url = consent_resp.headers.get('Location')
       final_resp = requests.post(redirect_url, data=encoded_data, headers=post_headers, 
                                cookies=cookies, allow_redirects=False)
       return final_resp.headers.get('Location')

   def run(self, email: str, password: str, file_path=None):
       auth_url = f"{self.base_url}/oauth20_authorize.srf"
       params = {
           'response_type': 'code',
           'client_id': self.client_id,
           'redirect_uri': self.redirect_uri,
           'scope': 'offline_access Mail.ReadWrite',
           'login_hint': email
       }
       auth_url = f"{auth_url}?{urlencode(params)}"
       
       headers = self._get_headers()
       post_headers = self._get_headers({'content-type': "application/x-www-form-urlencoded"})
       
       resp = requests.get(auth_url, headers=headers)
       
       post_url = f"{self.base_url}/ppsecure/post.srf" + re.search("https://login.live.com/ppsecure/post.srf?(.*?)',", resp.text).group(1)
       ppft = re.search("<input type=\"hidden\" name=\"PPFT\" id=\"(.*?)\" value=\"(.*?)\"", resp.text).group(2)
       
       login_data = {
           'ps': '2', 'PPFT': ppft, 'PPSX': 'Passp', 'NewUser': '1',
           'login': email, 'loginfmt': email, 'passwd': password,
           'type': '11', 'LoginOptions': '1', 'i13': '1',
           'CookieDisclosure': '0', 'IsFidoSupported': '1'
       }
       
       login_resp = requests.post(post_url, data=login_data, headers=post_headers, 
                                cookies=resp.cookies.get_dict(), allow_redirects=False)
       redirect_url = login_resp.headers.get('Location')
       
       # Handle consent if needed
       if not redirect_url:
           print(redirect_url)
           match = re.search("id=\"fmHF\" action=\"(.*?)\"", login_resp.text)
           if not match:
               if file_path:
                   dir_path = os.path.dirname(file_path)
                   die_file = os.path.join(dir_path, "die.txt")
                   with open(die_file, "a") as f:
                       f.write(f"{email}|{password}\n")               
               return None
               
           post_url = match.group(1)
           print(post_url)
           if "Update?mkt=" in post_url:
               redirect_url = self._handle_consent_page(post_url, login_resp.text, login_resp.cookies.get_dict())
           elif "confirm?mkt=" in post_url:
               print("TODO: Xử lý - confirm?mkt")
               with lock:
                    if file_path:
                        dir_path = os.path.dirname(file_path)
                        die_file = os.path.join(dir_path, "mail.txt")
                        with open(die_file, "a") as f:
                            f.write(f"{email}|{password}\n")                            
               return "Mail kp"
           elif "Add?mkt=" in post_url:
                print("TODO: Xử lý - add?mkt")
                with lock:
                    if file_path:
                        dir_path = os.path.dirname(file_path)
                        die_file = os.path.join(dir_path, "mail.txt")
                        with open(die_file, "a") as f:
                            f.write(f"{email}|{password}\n")                            
                    return "Mail add"
       
       # Get access token
       if redirect_url:
           code = redirect_url.split('=')[1]
           token_data = {
               'code': code,
               'client_id': self.client_id,
               'redirect_uri': self.redirect_uri,
               'grant_type': 'authorization_code'
           }
           token_resp = requests.post(self.token_url, data=token_data, headers=post_headers)
           with lock:
            if file_path:
                    dir_path = os.path.dirname(file_path)
                    die_file = os.path.join(dir_path, "mailtoken.txt")
                    with open(die_file, "a") as f:
                        f.write(f"{email}|{password}|{token_resp.json()}\n")
                    return "mail token"
       print("TODO: Xử lý - Mail die")
       with lock:
            if file_path:
                dir_path = os.path.dirname(file_path)
                die_file = os.path.join(dir_path, "die.txt")
                with open(die_file, "a") as f:
                    f.write(f"{email}|{password}\n")
       return None


class LogSignals(QObject):
    update_log = pyqtSignal(str)
    update_account = pyqtSignal(int, int, str)
    
class OAuth2GUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.auth = GetOAuth2Token()
        self.accounts = []
        self.file_path = ""
        self.signals = LogSignals()
        self.executor = None
        self.initUI()
        
        # Connect signals
        self.signals.update_log.connect(self.append_log)
        self.signals.update_account.connect(self.update_account_status)
        
    def initUI(self):
        # Set window properties
        self.setWindowTitle('OAuth2 Token Generator')
        self.setGeometry(100, 100, 900, 700)
        
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # File selection area
        file_layout = QHBoxLayout()
        self.file_path_button = QPushButton('Chọn File Tài Khoản')
        self.file_path_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_path_button)
        
        # Thread count control
        thread_layout = QHBoxLayout()
        thread_layout.addWidget(QLabel("Số luồng:"))
        self.thread_count = QSpinBox()
        self.thread_count.setMinimum(1)
        self.thread_count.setMaximum(20)
        self.thread_count.setValue(3)
        thread_layout.addWidget(self.thread_count)
        file_layout.addLayout(thread_layout)
        
        self.run_button = QPushButton('Chạy')
        self.run_button.clicked.connect(self.process_accounts_threaded)
        file_layout.addWidget(self.run_button)
        
        main_layout.addLayout(file_layout)
        
        # Table for displaying accounts
        self.accounts_table = QTableWidget(0, 4)  # 0 rows, 4 columns initially
        self.accounts_table.setHorizontalHeaderLabels(['Email', 'Mật khẩu', 'Trạng thái', 'Token'])
        
        # Set table properties
        header = self.accounts_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        
        main_layout.addWidget(self.accounts_table)
        
        # Log area
        main_layout.addWidget(QLabel("Log:"))
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        main_layout.addWidget(self.log_text)
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Chọn File Tài Khoản', '', 'Text Files (*.txt)')
        if file_path:
            self.file_path = file_path
            try:
                with open(file_path, 'r') as file:
                    self.accounts = []
                    for line in file:
                        line = line.strip()
                        if '|' in line:
                            self.accounts.append(line)
                    
                    # Update table
                    self.update_accounts_table()
                    
                    self.signals.update_log.emit(f'Đã tải {len(self.accounts)} tài khoản từ file {file_path}')
            except Exception as e:
                QMessageBox.critical(self, 'Lỗi', f'Không thể đọc file: {str(e)}')
    
    def update_accounts_table(self):
        self.accounts_table.setRowCount(0)  # Clear table
        
        for i, account_data in enumerate(self.accounts):
            parts = account_data.split('|')
            email = parts[0] if len(parts) > 0 else ""
            password = parts[1] if len(parts) > 1 else ""
            
            self.accounts_table.insertRow(i)
            self.accounts_table.setItem(i, 0, QTableWidgetItem(email))
            self.accounts_table.setItem(i, 1, QTableWidgetItem(password))
            self.accounts_table.setItem(i, 2, QTableWidgetItem("Chưa xử lý"))
            self.accounts_table.setItem(i, 3, QTableWidgetItem(""))
    
    def append_log(self, text):
        self.log_text.append(text)
        # Auto scroll to bottom
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def update_account_status(self, row, column, text):
        if 0 <= row < self.accounts_table.rowCount() and 0 <= column < self.accounts_table.columnCount():
            self.accounts_table.setItem(row, column, QTableWidgetItem(text))
    
    def process_accounts_threaded(self):
        if not self.accounts:
            QMessageBox.warning(self, 'Cảnh báo', 'Không có tài khoản nào để xử lý')
            return
        
        # Reset previous execution if any
        if self.executor:
            self.executor.shutdown(wait=False)
        
        # Create a ThreadPoolExecutor with the specified number of workers
        max_workers = self.thread_count.value()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        self.signals.update_log.emit(f"Bắt đầu xử lý với {max_workers} luồng")
        
        # Submit each account to the thread pool
        for row, account_data in enumerate(self.accounts):
            parts = account_data.split('|')
            if len(parts) >= 2:
                email = parts[0]
                password = parts[1]
                self.executor.submit(self.process_single_account, row, email, password)
    
    def process_single_account(self, row, email, password):
        # Update UI to show processing status
        self.signals.update_account.emit(row, 2, "Đang xử lý...")
        self.signals.update_log.emit(f"Xử lý tài khoản: {email}")
        
        try:
            auth = GetOAuth2Token()  # Create a new instance for thread safety
            result = auth.run(email, password, self.file_path)  # Pass file_path for writing to files
            
            if result == "Mail kp":
                self.signals.update_account.emit(row, 2, "Mail kp")
                self.signals.update_account.emit(row, 3, "")
                self.signals.update_log.emit(f"Tài khoản {email}: Mail kp")
            elif result == "Mail add":
                self.signals.update_account.emit(row, 2, "mail add")
                self.signals.update_account.emit(row, 3, "")
                self.signals.update_log.emit(f"Tài khoản {email}: Add mail")
            elif result == "mail token":
                self.signals.update_account.emit(row, 2, "mail token")
                self.signals.update_account.emit(row, 3, "")
                self.signals.update_log.emit(f"Tài khoản {email}: mail có token")
            elif isinstance(result, dict):  # Trường hợp xác thực thành công và trả về token
                token = result.get('access_token', 'Không có token')
                self.signals.update_account.emit(row, 2, "Thành công")
                # Hiển thị toàn bộ thông tin token_resp.json() trên bảng
                token_info = str(result)
                self.signals.update_account.emit(row, 3, token_info[:100] + "..." if len(token_info) > 100 else token_info)
                self.signals.update_log.emit(f"Tài khoản {email} xác thực thành công: {token[:30]}...")
            else:
                self.signals.update_account.emit(row, 2, "Die")
                self.signals.update_account.emit(row, 3, "")
                self.signals.update_log.emit(f"Tài khoản {email}: Die")
                
        except Exception as e:
            error_message = str(e)
            self.signals.update_account.emit(row, 2, f"Lỗi: {error_message[:20]}...")
            self.signals.update_log.emit(f"Lỗi khi xử lý {email}: {error_message}")
    
    def process_accounts(self):
        # This is kept for reference
        for row in range(len(self.accounts)):
            email = self.accounts_table.item(row, 0).text()
            password = self.accounts_table.item(row, 1).text()
            
            # Update status
            self.accounts_table.setItem(row, 2, QTableWidgetItem("Đang xử lý..."))
            QApplication.processEvents()  # Update UI
            
            try:
                result = self.auth.run(email, password)
                if result:
                    token = result.get('access_token', 'Không có token')
                    self.accounts_table.setItem(row, 2, QTableWidgetItem("Thành công"))
                    self.accounts_table.setItem(row, 3, QTableWidgetItem(token[:20] + "..."))
                else:
                    self.accounts_table.setItem(row, 2, QTableWidgetItem("Thất bại"))
                    self.accounts_table.setItem(row, 3, QTableWidgetItem(""))
            except Exception as e:
                self.accounts_table.setItem(row, 2, QTableWidgetItem(f"Lỗi: {str(e)[:20]}..."))
                self.accounts_table.setItem(row, 3, QTableWidgetItem(""))
            
            QApplication.processEvents()  # Update UI


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = OAuth2GUI()
    gui.show()
    sys.exit(app.exec())
