from PyQt5.QtWidgets import QWidget, QApplication, QLabel, QPushButton, QMessageBox, QLineEdit, QComboBox, QFileDialog, QInputDialog, QTextEdit
from PyQt5.QtGui import QIcon
import sys,os
import subprocess
import string
import json


class View_Windows_Logs(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(0, 30, 1920, 1000)
		self.setWindowTitle("Firewall Logs")
		self.setWindowIcon(QIcon('Images/firewall.ico'))
		
		self.board = QTextEdit(self)
		self.board.setGeometry(5, 5, 1915, 990)
		self.board.setStyleSheet("font-size:20px;")
		self.board.setReadOnly(True)
		self.board.show()
		
	def show_log(self, text):
		self.board.setPlainText(text)
	

class Show_Log_Setting(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(650, 30, 600, 350)
		self.setFixedSize(600, 350)
		self.setWindowTitle("Firewall Log Settings")
		self.setWindowIcon(QIcon('Images/firewall.ico'))
	
		self.board = QTextEdit(self)
		self.board.setGeometry(5, 5, 590, 340)
		self.board.setReadOnly(True)
		self.board.show()
		
	def set_log(self, text):
		self.board.setPlainText(text)


class Monitor_Current_Firewall_State(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(650, 30, 600, 370)
		self.setFixedSize(600, 370)
		self.setWindowTitle("Monitoring Firewall State")
		self.setWindowIcon(QIcon('Images/firewall.ico'))
		
		self.board = QTextEdit(self)
		self.board.setGeometry(5, 5, 590, 330)
		self.board.setReadOnly(True)
		self.board.show()
		
		self.get = QPushButton(self)
		self.get.setText("Firewall State")
		self.get.setGeometry(5, 335, 590, 30)
		
		def show_firewall_state():
			ps_script = """Get-NetFirewallProfile | ForEach-Object {
@"
Profile		: $($_.Name)
Enabled		: $($_.Enabled)
Default Inbound		: $($_.DefaultInboundAction)
Default Outbound	: $($_.DefaultOutboundAction)
Log Allowed		: $($_.LogAllowed)
Log Blocked		: $($_.LogBlocked)
Log File		: $($_.LogFileName)
----------------------------------------------------------------------------------------------------------------------------------
"@
}
			"""
			cmd = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script], text=True, capture_output=True)
			st = ""
			st += cmd.stdout
			self.board.setPlainText(st)
			
		self.get.clicked.connect(show_firewall_state)
		self.get.show()


class Check_Specific_Rule(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(0, 30, 600, 350)
		self.setWindowTitle("Firewall Rules")
		self.setWindowIcon(QIcon('Images/firewall.ico'))
		
		self.board = QTextEdit(self)
		self.board.setReadOnly(True)
		self.board.setGeometry(5, 5, 590, 340)
		self.board.show()
		
	def set_text(self, text):
		self.board.setPlainText(text)
		
		
class All_Firewall_Rule(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(650, 30, 600, 500)
		self.setFixedSize(600, 500)
		self.setWindowTitle("Firewall Rules")
		self.setWindowIcon(QIcon('Images/firewall.ico'))
	
	# A Box where we can see firewall rules.
	
	def firewall_rule_box(self):
		self.firewall_rule_box = QTextEdit(self)
		self.firewall_rule_box.setGeometry(5, 5, 590, 400)
		self.firewall_rule_box.setReadOnly(True)
		self.firewall_rule_box.show()
	
	def firewall_rule_box_info(self):
		self.firewall_rule_box_info = QLabel(self)
		self.firewall_rule_box_info.setStyleSheet("background:#CBC6C8;font-size:11px;")
		self.firewall_rule_box_info.setGeometry(5, 405, 590, 30)
		self.firewall_rule_box_info.show()
	
	
	# A Button which is used to represent firewall logs
	
	def firewall_rule_get_button(self):
		self.firewall_rule_get_button = QPushButton(self)
		self.firewall_rule_get_button.setText("Get Rules")
		self.firewall_rule_get_button.setGeometry(5, 435, 295, 30)
		
		def firewall_get_rule():
			self.firewall_rule_box.setText("")
			path = os.getcwd()
			cmd = f'netsh advfirewall firewall show rule name=all > "{path}\\Data\\rule.txt"'
			state = subprocess.run(cmd, shell=True)
			
			if state.returncode == 0:
				file = open("Data/rule.txt", "r")
				self.firewall_rule_box.setText(file.read())
				
			info = ""
			ps_script = """
			$rules = Get-NetFirewallRule
			$result = [PSCustomObject]@{
				TotalRules = $rules.Count
				Allowed = ($rules | Where Action -eq "Allow").Count
				Blocked = ($rules | Where Action -eq "Block").Count
				Enabled = ($rules | Where Enabled -eq "True").Count
				Disabled = ($rules | Where Enabled -eq "False").Count
				Inbound = ($rules | Where Direction -eq "Inbound").Count
				Outbound = ($rules | Where Direction -eq "Outbound").Count
			}
			$result | ConvertTo-Json
			"""
			state1 = subprocess.run(["powershell", "-NoProfile", ps_script], capture_output=True, text=True)
			with open("Data/file1.json", "w") as file:
				if state1.returncode == 0:
					file.write(state1.stdout)
				else:
					file.write("None")

			with open("Data/file1.json", "r") as file:
				data = json.load(file)
				for i, j in data.items():
					info += f"| {i} : {j} "
				file.close()
				
			self.firewall_rule_box_info.setText(info)

		self.firewall_rule_get_button.clicked.connect(firewall_get_rule)
		self.firewall_rule_get_button.show()
		
	# A Button which is used to clear the screen
	
	def firewall_rule_clear_button(self):
		self.firewall_rule_clear_button = QPushButton(self)
		self.firewall_rule_clear_button.setText("Clear the Rules")
		self.firewall_rule_clear_button.setGeometry(300, 435, 295, 30)
		
		def firewall_clear_rule():
			self.firewall_rule_box.setText("")
			self.firewall_rule_box_info.setText("")
			
			
		self.firewall_rule_clear_button.clicked.connect(firewall_clear_rule)
		self.firewall_rule_clear_button.show()
			
	# A Input box for entering filters
	
	def firewall_rule_filter_box(self):
		self.firewall_rule_filter_box = QLineEdit(self)
		self.firewall_rule_filter_box.setPlaceholderText("Enter the Display Name...")
		self.firewall_rule_filter_box.setGeometry(5, 465, 500, 30)
		self.firewall_rule_filter_box.show()
	
	# A Button for performing filter action
	
	def firewall_rule_filter_button(self):
		self.firewall_rule_filter_button = QPushButton(self)
		self.firewall_rule_filter_button.setText("Filter")
		self.firewall_rule_filter_button.setGeometry(505, 465, 90, 30)
		
		def firewall_filter_button():
			filter_text = self.firewall_rule_filter_box.text().strip()
			rules = f"Get-NetFirewallRule | Where DisplayName -like '*{filter_text}*'" 
			state = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", rules], text=True, capture_output=True, shell=True)
			self.firewall_rule_box.setText("")
			self.firewall_rule_box.setText(state.stdout)
			
			info = ""

			ps_script = f"""
			$rules = Get-NetFirewallRule |
				Where-Object {{ $_.DisplayName -like "*{filter_text}*" }}

			$result = [PSCustomObject]@{{
				TotalRules = $rules.Count
				Allowed    = ($rules | Where-Object {{ $_.Action -eq "Allow" }}).Count
				Blocked    = ($rules | Where-Object {{ $_.Action -eq "Block" }}).Count
				Enabled    = ($rules | Where-Object {{ $_.Enabled -eq "True" }}).Count
				Disabled   = ($rules | Where-Object {{ $_.Enabled -eq "False" }}).Count
				Inbound    = ($rules | Where-Object {{ $_.Direction -eq "Inbound" }}).Count
				Outbound   = ($rules | Where-Object {{ $_.Direction -eq "Outbound" }}).Count
			}}

			$result | ConvertTo-Json
			"""

			state1 = subprocess.run(["powershell", "-NoProfile", ps_script], capture_output=True, text=True)
			with open("Data/file2.json", "w") as file:
				if state1.returncode == 0:
					file.write(state1.stdout)
				else:
					file.write("None")

			with open("Data/file2.json", "r") as file:
				data = json.load(file)
				for i, j in data.items():
					info += f"| {i} : {j} "
				file.close()
			
			self.firewall_rule_box_info.setText(info)
			
		self.firewall_rule_filter_button.clicked.connect(firewall_filter_button)
		self.firewall_rule_filter_button.show()


class Monitor(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(650, 30, 500, 435)
		self.setFixedSize(500, 435)
		self.setWindowTitle("Monitoring Firewall")
		self.setWindowIcon(QIcon('Images/firewall.ico'))
		
	# View All Firewall Rule Button's function here
	
	def view_all_rule(self):
		
		# Button for performing to view all Firewall Rules
		
		self.view_all_rule_btn = QPushButton(self)
		self.view_all_rule_btn.setText("View All Firewall Rules")
		self.view_all_rule_btn.setGeometry(5, 5, 490, 30)
		self.view_all_rule_btn.clicked.connect(self.show_all_rule)
		self.view_all_rule_btn.show()
	
	def check_specific_rule(self):
		self.check_specific_rule_label = QLabel(self)
		self.check_specific_rule_label.setText("Check Specific Rule")
		self.check_specific_rule_label.setGeometry(5, 35, 200, 30)
		self.check_specific_rule_label.show()
		
		self.check_specific_rule_entry1 = QLineEdit(self)
		self.check_specific_rule_entry1.setPlaceholderText("Enter the rule name here...")
		self.check_specific_rule_entry1.setGeometry(5, 65, 260, 30)
		self.check_specific_rule_entry1.show()
		
		profile = ["Profile", "Domain", "Private", "Public", "Any"]
		self.check_specific_rule_profile = QComboBox(self)
		self.check_specific_rule_profile.addItems(profile)
		self.check_specific_rule_profile.setCurrentIndex(0)
		self.check_specific_rule_profile.setGeometry(265, 65, 130, 30)
		self.check_specific_rule_profile.show()
		
		direction = ["Direction", "Inbound", "Outbound"]
		self.check_specific_rule_dir = QComboBox(self)
		self.check_specific_rule_dir.addItems(direction)
		self.check_specific_rule_dir.setCurrentIndex(0)
		self.check_specific_rule_dir.setGeometry(5, 95, 130, 30)
		self.check_specific_rule_dir.show()
			
		self.check_specific_rule_lip = QLineEdit(self)
		self.check_specific_rule_lip.setPlaceholderText("Local IP")
		self.check_specific_rule_lip.setGeometry(135, 95, 90, 30)
		self.check_specific_rule_lip.show()
		
		self.check_specific_rule_lport = QLineEdit(self)
		self.check_specific_rule_lport.setPlaceholderText("L Port")
		self.check_specific_rule_lport.setStyleSheet("font-size:10px;")
		self.check_specific_rule_lport.setGeometry(225, 95, 40, 30)
		self.check_specific_rule_lport.show()
		
		self.check_specific_rule_rip = QLineEdit(self)
		self.check_specific_rule_rip.setPlaceholderText("Remote IP")
		self.check_specific_rule_rip.setGeometry(265, 95, 90, 30)
		self.check_specific_rule_rip.show()

		self.check_specific_rule_rport = QLineEdit(self)
		self.check_specific_rule_rport.setPlaceholderText("R Port")
		self.check_specific_rule_rport.setStyleSheet("font-size:10px;")
		self.check_specific_rule_rport.setGeometry(355, 95, 40, 30)
		self.check_specific_rule_rport.show()
		
		action = ["Action", "Allow", "Block"]
		self.check_specific_rule_allow_block = QComboBox(self)
		self.check_specific_rule_allow_block.setGeometry(5, 125, 130, 30)
		self.check_specific_rule_allow_block.addItems(action)
		self.check_specific_rule_allow_block.setCurrentIndex(0)
		self.check_specific_rule_allow_block.show()
			
		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		self.check_specific_rule_protocol = QComboBox(self)
		self.check_specific_rule_protocol.setGeometry(135, 125, 130, 30)
		self.check_specific_rule_protocol.addItems(protocols)
		self.check_specific_rule_protocol.setCurrentIndex(0)
		self.check_specific_rule_protocol.show()
		
		enable = ["Enable", "Yes", "No"]
		self.check_specific_rule_enable = QComboBox(self)
		self.check_specific_rule_enable.addItems(enable)
		self.check_specific_rule_enable.setGeometry(265, 125, 130, 30)
		self.check_specific_rule_enable.setCurrentIndex(0)
		self.check_specific_rule_enable.show()
		
		self.check_specific_rule_entry4 = QLineEdit(self)
		self.check_specific_rule_entry4.setPlaceholderText("Program file...")
		self.check_specific_rule_entry4.setGeometry(5, 155, 340, 30)
		self.check_specific_rule_entry4.show()
		
		self.check_specific_rule_get_file_button = QPushButton(self)
		self.check_specific_rule_get_file_button.setText("File")
		self.check_specific_rule_get_file_button.setGeometry(345, 155, 50, 30)
		
		def get_file():
			file, _ = QFileDialog.getOpenFileName(self, "Files")
			self.check_specific_rule_entry4.setText(file.replace("/", "\\"))
			
		self.check_specific_rule_get_file_button.clicked.connect(get_file)
		self.check_specific_rule_get_file_button.show()
		
		
		self.check_specific_rule_action = QPushButton(self)
		self.check_specific_rule_action.setText("Action")
		self.check_specific_rule_action.setGeometry(395, 65, 100, 120)
		
		def check_specific():
			name = self.check_specific_rule_entry1.text().strip()
			direction = self.check_specific_rule_dir.currentText()
			profile = self.check_specific_rule_profile.currentText()			
			localip = self.check_specific_rule_lip.text().strip()
			localport = self.check_specific_rule_lport.text().strip()
			remoteip = self.check_specific_rule_rip.text().strip()
			remoteport = self.check_specific_rule_rport.text().strip()
			action = self.check_specific_rule_allow_block.currentText()
			protocol = self.check_specific_rule_protocol.currentText()
			program = self.check_specific_rule_entry4.text().strip()
			enable = self.check_specific_rule_enable.currentText()
			
			if name == "":
				name = 'None'
			if direction == "Direction":
				direction = 'None'
			if profile == "Profile":
				profile = 'None'
			if localip == "":
				localip = 'None'
			if localport == "":
				localport = 'None'
			if remoteip == "":
				remoteip = 'None'
			if remoteport == "":
				remoteport = 'None'
			if action == "Action":
				action = 'None'
			if protocol == "Protocol":
				protocol = 'None'
			if program == "":
				program = 'None'
			if enable == "Enable":
				enable = 'None'
			elif enable == "Yes":
				enable = 'True'
			elif enable == "No":
				enable = 'False'
			
			ps_script = f"""
# Inputs (can come from Python / GUI)
$DisplayName = "{name}"     # partial or $null
$Direction   = "{direction}"          # Inbound / Outbound / $null
$Action      = "{action}"             # Allow / Block / $null
$Enabled     = "{enable}" # True / False / $null
$Profile     = "{profile}"            # Public / Private / Domain / $null
$Protocol    = "{protocol}"               # TCP / UDP / ICMP / $null
$LocalPort   = "{localport}"               # 80 / Any / $null
$RemotePort  = "{remoteport}"               # 443 / Any / $null
$Program     = "{program}"               # chrome.exe / full path / $null
$LocalIP     = "{localip}"               # 192.168.1.10 / Any / $null
$RemoteIP    = "{remoteip}"               # 8.8.8.8 / Any / $null


Get-NetFirewallRule | Where-Object {{

    # ---- Rule level ----
    ($DisplayName -eq 'None' -or $_.DisplayName -like "*$DisplayName*") -and
    ($Direction   -eq 'None' -or $_.Direction   -eq $Direction)        -and
    ($Action      -eq 'None' -or $_.Action      -eq $Action)           -and
    ($Enabled     -eq 'None' -or $_.Enabled     -eq $Enabled)          -and
    ($Profile     -eq 'None' -or $_.Profile     -match $Profile)       -and

    # ---- Port / Protocol ----
    ($Protocol   -eq 'None' -or
        (($_ | Get-NetFirewallPortFilter).Protocol -eq $Protocol)
    ) -and

    ($LocalPort  -eq 'None' -or
        (($_ | Get-NetFirewallPortFilter).LocalPort -eq $LocalPort)
    ) -and

    ($RemotePort -eq 'None' -or
        (($_ | Get-NetFirewallPortFilter).RemotePort -eq $RemotePort)
    ) -and

    # ---- Program ----
    ($Program -eq 'None' -or
        (($_ | Get-NetFirewallApplicationFilter).Program -like "*$Program*")
    ) -and

    # ---- IP Address ----
    ($LocalIP -eq 'None' -or
        (($_ | Get-NetFirewallAddressFilter).LocalAddress -eq $LocalIP)
    ) -and

    ($RemoteIP -eq 'None' -or
        (($_ | Get-NetFirewallAddressFilter).RemoteAddress -eq $RemoteIP)
    )
}}

"""			
			completed = subprocess.run(["powershell", "-Command", ps_script], capture_output=True, text=True)

			if completed.returncode != 0:
				raise RuntimeError(completed.stderr)

			output = completed.stdout.strip()
			self.check_specific_firewall_rule(output)
			
		self.check_specific_rule_action.clicked.connect(check_specific)
		self.check_specific_rule_action.show()	
		
	def monitor_current_firewall_state(self):
		self.monitor_current_firewall_state_btn = QPushButton(self)
		self.monitor_current_firewall_state_btn.setText("Monitor Current Firewall State")
		self.monitor_current_firewall_state_btn.setGeometry(5, 190, 490, 30)
		
		def current_firewall_state():
			self.monitor_current_firewall()
			
		self.monitor_current_firewall_state_btn.clicked.connect(current_firewall_state)
		self.monitor_current_firewall_state_btn.show()
		
	def firewall_logging_ED(self):
		
		# Label for Firewall Logging 
		
		self.firewall_logging_ED_label = QLabel(self)
		self.firewall_logging_ED_label.setText("Firewall Logging")
		self.firewall_logging_ED_label.setGeometry(5, 220, 200, 30)
		self.firewall_logging_ED_label.show()
		

		# Dropdown box for Profile
		
		profile = ["Profile", "DomainProfile", "PrivateProfile", "PublicProfile", "AllProfile"]
		self.firewall_logging_ED_drop0 = QComboBox(self)
		self.firewall_logging_ED_drop0.setGeometry(5, 250, 100, 30)
		self.firewall_logging_ED_drop0.setStyleSheet("font-size:12px;")
		self.firewall_logging_ED_drop0.setCurrentIndex(0)
		self.firewall_logging_ED_drop0.addItems(profile)
		self.firewall_logging_ED_drop0.show()
		
		
		# Dropdown box for Enable or Disable
		
		enable = ["AllowedConnections", "Enable", "Disable", "NotConfigured"]
		self.firewall_logging_ED_drop1 = QComboBox(self)
		self.firewall_logging_ED_drop1.setGeometry(105, 250, 130, 30)
		self.firewall_logging_ED_drop1.setStyleSheet("font-size:11px;")
		self.firewall_logging_ED_drop1.addItems(enable)
		self.firewall_logging_ED_drop1.setCurrentIndex(0)
		self.firewall_logging_ED_drop1.show()

		
		# Dropdown box for allowedconnections or droppedconnections
		
		action = ["DroppedConnections", "Enable", "Disable", "NotConfigured"]
		self.firewall_logging_ED_drop2 = QComboBox(self)
		self.firewall_logging_ED_drop2.setGeometry(235, 250, 161, 30)
		self.firewall_logging_ED_drop2.setStyleSheet("font-size:11px;")
		self.firewall_logging_ED_drop2.addItems(action)
		self.firewall_logging_ED_drop2.setCurrentIndex(0)
		self.firewall_logging_ED_drop2.show()
		
		
		# Input box for entering file name
		
		self.firewall_logging_ED_file_name_entry = QLineEdit(self)
		self.firewall_logging_ED_file_name_entry.setPlaceholderText("Enter the File Name...")
		self.firewall_logging_ED_file_name_entry.setGeometry(5, 280, 200, 30)
		self.firewall_logging_ED_file_name_entry.show()
		
		
		# Button for Selecting File
		
		self.firewall_logging_ED_file_button = QPushButton(self)
		self.firewall_logging_ED_file_button.setText("File")
		self.firewall_logging_ED_file_button.setGeometry(205, 280, 100, 30)
		
		def get_file():
			file, _ = QFileDialog.getSaveFileName(self, "Save As", "", "All Files (*.*)")
			self.firewall_logging_ED_file_name_entry.setText(file.replace("/", "\\"))
		self.firewall_logging_ED_file_button.clicked.connect(get_file)
		self.firewall_logging_ED_file_button.show()
		
		
		# Input box for entering file size 1 - 32767
		
		self.firewall_logging_ED_file_size = QLineEdit(self)
		self.firewall_logging_ED_file_size.setPlaceholderText("file size : 1-32767")
		self.firewall_logging_ED_file_size.setStyleSheet("font-size:10px;")
		self.firewall_logging_ED_file_size.setGeometry(305, 280, 90, 30)
		self.firewall_logging_ED_file_size.show()
		
		
		# Button for doing action to manage logging 
		
		self.firewall_logging_ED_action = QPushButton(self)
		self.firewall_logging_ED_action.setText("Action")
		self.firewall_logging_ED_action.setGeometry(395, 250, 100, 60)
		
		def firewall_action():
			profile = self.firewall_logging_ED_drop0.currentText().lower()
			allowedcon = self.firewall_logging_ED_drop1.currentText().lower()
			droppedcon = self.firewall_logging_ED_drop2.currentText().lower()
			size = self.firewall_logging_ED_file_size.text()
			file_name = self.firewall_logging_ED_file_name_entry.text().replace("/", "\\")
			
			cmd = "netsh advfirewall set"
			
			
			# Mandatory field is profile
			
			if profile == "profile":
				QMessageBox.warning(self, "Missing Input", "Select the profile like AllProfile,DomainProfile,PrivateProfile,PublicProfile")
				return
			else:
				cmd += f" {profile} logging"
			
			
			# Logic for AllowedConnections 
			
			if allowedcon != "allowedconnections" and droppedcon == "droppedconnections" and size == "" and file_name == "":
				cmd += f' allowedconnections {allowedcon}'
			
			
			# Logic for DroppedConnections
			
			if droppedcon != "droppedconnections" and allowedcon == "allowedconnections" and size == "" and file_name == "":
				cmd += f' droppedconnections {droppedcon}'
			
			
			# Logic for File Size
			
			if size != "" and allowedcon == "allowedconnections" and droppedcon == "droppedconnections" and file_name == "":
				cmd += f' maxfilesize {size}'
			
			
			# Logic for File name
			
			if file_name != "" and allowedcon == "allowedconnections" and droppedcon == "droppedconnections" and size == "":
				cmd += f' filename {file_name}'
			
			# Logic for all if not present
			
			if allowedcon == "allowedconnections" and droppedcon == "droppedconnections" and size == "" and file_name == "":
				QMessageBox.warning(self, "Requirement Error", "You have to full fill one field at a time either AllowedConnections,DroppedConnections,size,FileName")
			
			
			state = subprocess.run(cmd, shell=True)
			if state.returncode == 0:
				QMessageBox.information(self, "!!! Success !!!", "You have successfully done your job !!!")
			else:
				QMessageBox.warning(self, "Error", "Are you Administrator, you must modify one field")
			
		self.firewall_logging_ED_action.clicked.connect(firewall_action)
		self.firewall_logging_ED_action.show()
		
	def check_log_setting(self):
		
		# Label for Log Settings 
		
		self.check_log_setting_label = QLabel(self)
		self.check_log_setting_label.setText("Check Log Setting")
		self.check_log_setting_label.setGeometry(5, 310, 200, 30)
		self.check_log_setting_label.show()
		
		# Dropdown box for selecting profile
		
		profile = ["AllProfiles", "DomainProfile", "PrivateProfile", "PublicProfile"]
		self.check_log_setting_drop1 = QComboBox(self)
		self.check_log_setting_drop1.setGeometry(5, 340, 150, 30)
		self.check_log_setting_drop1.addItems(profile)
		self.check_log_setting_drop1.setCurrentIndex(0)
		self.check_log_setting_drop1.show()
		
		# Action button for checking Log Settings
		
		self.check_log_setting_action = QPushButton(self)
		self.check_log_setting_action.setText("Action")
		self.check_log_setting_action.setGeometry(155, 340, 100, 30)
		
		# Function call's on click Action button
		
		def check_log():
			cmd = "netsh advfirewall show"
			profile = self.check_log_setting_drop1.currentText().lower()
			cmd += f" {profile} logging"
			state = subprocess.run(cmd, text=True, capture_output=True)
			
			if state.returncode == 0:
				self.show_log_setting(state.stdout)
			else:
				QMessageBox.warning(self, "Warning", "Something Wrong Happend")
				
		self.check_log_setting_action.clicked.connect(check_log)
		self.check_log_setting_action.show()
		
	def view_windows_firewall_logs(self):
		
		# Label for View Windows Firewall Logs
		
		self.view_windows_firewall_logs_label = QLabel(self)
		self.view_windows_firewall_logs_label.setText("View Windows Firewall Logs")
		self.view_windows_firewall_logs_label.setGeometry(5, 370, 200, 30)
		self.view_windows_firewall_logs_label.show()
		
		
		# TextBox for entering file name of log file.
		
		self.view_windows_firewall_logs_file = QLineEdit(self)
		self.view_windows_firewall_logs_file.setPlaceholderText("Enter the Log File Name...")
		self.view_windows_firewall_logs_file.setGeometry(5, 400, 200, 30)
		self.view_windows_firewall_logs_file.show()
		
		
		# Button for selecting file from system
		
		self.view_windows_firewall_logs_file1 = QPushButton(self)
		self.view_windows_firewall_logs_file1.setGeometry(205, 400, 100, 30)
		self.view_windows_firewall_logs_file1.setText("File")
		
		def open_file():
			file, _ = QFileDialog.getOpenFileName(self, "Files")
			self.view_windows_firewall_logs_file.setText(file.replace("/", "\\"))
			
		self.view_windows_firewall_logs_file1.clicked.connect(open_file)
		self.view_windows_firewall_logs_file1.show()
		
		
		# Action button for view windows firewall logs
		
		self.view_windows_firewall_logs_action = QPushButton(self)
		self.view_windows_firewall_logs_action.setText("Action")
		self.view_windows_firewall_logs_action.setGeometry(305, 400, 100, 30)
		
		def windows_firewall_log():
			file = self.view_windows_firewall_logs_file.text()

			if file == "" or ".log" not in file:
				QMessageBox.warning(self, "Input Error", "File Name is Mandatory to view the log with .log extension.")

			else:
				with open(file, "r") as f:
					lines = f.read()
					self.view_windows_fire_logs(lines)
					f.close()
				
		self.view_windows_firewall_logs_action.clicked.connect(windows_firewall_log)
		self.view_windows_firewall_logs_action.show()
	
	
	# Function for calling All_Firewall_Rule Class
	
	def show_all_rule(self):
		self.show_all_rule = All_Firewall_Rule()
		self.show_all_rule.firewall_rule_box()
		self.show_all_rule.firewall_rule_get_button()
		self.show_all_rule.firewall_rule_clear_button()
		self.show_all_rule.firewall_rule_box_info()
		self.show_all_rule.firewall_rule_filter_box()
		self.show_all_rule.firewall_rule_filter_button()
		self.show_all_rule.show()
	
	
	# Function for calling Check_Specific_Rule Class
	
	def check_specific_firewall_rule(self, text):
		self.check_specific_firewall_rules = Check_Specific_Rule()
		self.check_specific_firewall_rules.set_text(text)
		self.check_specific_firewall_rules.show()
	
	
	# Function for calling Monitor_Current_Firewall_State Class
	
	def monitor_current_firewall(self):
		self.monitor = Monitor_Current_Firewall_State()
		self.monitor.show()
	
	
	# Function for calling Show_Log_Setting Class
	
	def show_log_setting(self, text):
		self.show_log = Show_Log_Setting()
		self.show_log.set_log(text)
		self.show_log.show()
	
	
	# Function for calling View_Windows_Logs Class
	
	def view_windows_fire_logs(self, text):
		self.view_log = View_Windows_Logs()
		self.view_log.show_log(text)
		self.view_log.show()

		
class Notes(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(650, 30, 500, 500)
		self.setFixedSize(500, 500)		
		self.setWindowTitle("Firewall Documentation")
		self.setWindowIcon(QIcon('Images/firewall.ico'))
		
		# TextEdit for Notes
		
		self.board = QTextEdit(self)
		self.board.setReadOnly(True)
		file_path = os.path.abspath(__file__)
		dir_path = os.path.dirname(file_path)
		with open(f"{dir_path}\\Notes\\notes.txt", "r") as file:
			self.board.setText(file.read())
			self.board.setStyleSheet("font-family:Times New Roman;font-size:16px")
			file.close()
		self.board.setGeometry(5, 5, 490, 490)
		self.board.show()


class Allow_Block_App(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(500, 100, 400, 400)
		self.setFixedSize(400, 400)
		self.setWindowTitle("Allow Block Application")
		self.setWindowIcon(QIcon('Images/firewall.ico'))

	# Allow Block Application Rule Name function here
	
	def app_rule_name(self):
		self.app_rule_name = QLineEdit(self)
		self.app_rule_name.setPlaceholderText("Enter the Rule Name...")
		self.app_rule_name.setGeometry(5, 5, 390, 30)
		self.app_rule_name.show()
	
	# Allow Block Application Rule Name function here
	
	def app_rule_description(self):
		self.app_rule_description = QTextEdit(self)
		self.app_rule_description.setGeometry(5, 35, 390, 60)
		self.app_rule_description.setPlaceholderText("Enter Description here...")
		self.app_rule_description.show()
	
	# Application or program for rule here
	
	def app_rule_program(self):
		
		# Text box for manually enter program or application name or location here
		
		self.app_rule_program_text_box = QLineEdit(self)
		self.app_rule_program_text_box.setPlaceholderText("Application Name ....")
		self.app_rule_program_text_box.setGeometry(5, 95, 340, 30)
		self.app_rule_program_text_box.show()
		
		# Button for getting file from system.
		
		self.app_rule_program_file_btn = QPushButton(self)
		self.app_rule_program_file_btn.setText("File")
		self.app_rule_program_file_btn.setGeometry(345, 95, 52, 30)
		
		def get_file():
			file, _ = QFileDialog(self).getOpenFileName()
			self.app_rule_program_text_box.setText(file)
			
		self.app_rule_program_file_btn.clicked.connect(get_file)
		self.app_rule_program_file_btn.show()
		
	
	def app_rule_local_ip(self):
		
		# Text box for entering local ip address
		
		self.app_rule_local_ip = QLineEdit(self)
		self.app_rule_local_ip.setPlaceholderText("L_IP:255.255.255.255")
		self.app_rule_local_ip.setGeometry(5, 125, 140, 30)
		self.app_rule_local_ip.show()
	
	def app_rule_local_port(self):
		
		# Text Box for entering local port 
		
		self.app_rule_local_port = QLineEdit(self)
		self.app_rule_local_port.setPlaceholderText("L Port")
		self.app_rule_local_port.setGeometry(145, 125, 60, 30)
		self.app_rule_local_port.show()
		
	
	def app_rule_remote_ip(self):
		
		# Text box for remote ip address
		
		self.app_rule_remote_ip = QLineEdit(self)
		self.app_rule_remote_ip.setPlaceholderText("R_IP:255.255.255.255")
		self.app_rule_remote_ip.setGeometry(205, 125, 135, 30)
		self.app_rule_remote_ip.show()
		
	def app_rule_remote_port(self):
		
		# Text Box for entering local port 
		
		self.app_rule_remote_port = QLineEdit(self)
		self.app_rule_remote_port.setPlaceholderText("R Port")
		self.app_rule_remote_port.setGeometry(340, 125, 55, 30)
		self.app_rule_remote_port.show()
		
	def app_rule_direction(self):
		
		# Dropdown box for selecting Inbound or Outbound Direction
		
		direction = ["Direction", "Inbound", "Outbound"]
		
		self.app_rule_dir = QComboBox(self)
		self.app_rule_dir.setGeometry(5, 155, 200, 30)
		self.app_rule_dir.addItems(direction)
		self.app_rule_dir.setCurrentIndex(0)
		self.app_rule_dir.show()
		
	def app_rule_action(self):
		
		# Dropdown box for select action allow or block 
		
		action = ["Action", "Allow", "Block"]
		
		self.app_rule_action = QComboBox(self)
		self.app_rule_action.setGeometry(205, 155, 190, 30)
		self.app_rule_action.addItems(action)
		self.app_rule_action.setCurrentIndex(0)
		self.app_rule_action.show()
		
	def app_rule_profile(self):
		
		# Dropdown box for selec profile domain, private, public, any
		
		profiles = ["Profile", "Domain", "Private", "Public", "Any"]
		
		self.app_rule_profile = QComboBox(self)
		self.app_rule_profile.setGeometry(5, 185, 200, 30)
		self.app_rule_profile.addItems(profiles)
		self.app_rule_profile.setCurrentIndex(0)
		self.app_rule_profile.show()
		
	
	def app_rule_protocol(self):
		
		# Dropdown box for selecting protocol
		
		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		self.app_rule_protocol = QComboBox(self)
		self.app_rule_protocol.setGeometry(205, 185, 190, 30)
		self.app_rule_protocol.addItems(protocols)
		self.app_rule_protocol.setCurrentIndex(0)
		self.app_rule_protocol.show()
	
	def app_rule_service(self):
		
		# Dropdown box for selecting service
		
		services = ["Service", "wuauserv","bits","Dhcp","Dnscache","EventLog","Schedule","WinDefend","Spooler","TermService", "LanmanWorkstation","LanmanServer","Browser","W32Time","IKEEXT","iphlpsvc","PolicyAgent", "RemoteRegistry","lmhosts","Netlogon","ProfSvc","RpcSs","RpcLocator","SamSs","SCardSvr", "Winmgmt","SSDPSRV","upnphost","TrkWks","Themes","WSearch","TrustedInstaller","Wecsvc", "WerSvc","WEPHOSTSVC","WdiServiceHost","WdNisSvc","msiserver","BFE","MpsSvc","WlanSvc", "ALG","AudioSrv","Audiosrv","Fax","FTP","FTPSVC","ftpsvc","MSMQ","Netman","NlaSvc","NcbService", "PlugPlay","Power","RasMan","RasAuto","RDPDR","TermService","UmRdpService","SessionEnv", "ShellHWDetection","SharedAccess","stisvc","SysMain","TapiSrv","TrkWks","UmRdpService", "W3SVC","WAS","wscsvc","wdiagsvc","WdNisSvc","WinHttpAutoProxySvc","WpnService","WpnUserService","AppHostSvc","Appinfo","AppMgmt","BthHFSrv","CertPropSvc","ClipSVC","DoSvc","edgeupdate","edgeupdatem","gpsvc","HvHost","InstallService","IntelAudioService","iphlpsvc","lfsvc","lmhosts","MapsBroker","MessagingService","MixedRealityOpenXRSvc","NgcSvc","NgcCtnrSvc","OneSyncSvc","PhoneSvc","PrintNotify","PushToInstall","QWAVE","RtkAudioUniversalService","SEMgrSvc","SessionEnv","StateRepository","StorSvc","svsvc","SystemEventsBroker","TimeBrokerSvc","UserManager","UsoSvc","VacSvc","VaultSvc","WaaSMedicSvc","Wcmsvc","WdBoot","WdFilter","WerSvc","wisvc","WMPNetworkSvc","workfolderssvc","WpcMonSvc","WPDBusEnum","wscsvc", "Any"]
		
		self.app_rule_service = QComboBox(self)
		self.app_rule_service.setGeometry(5, 215, 200, 30)
		self.app_rule_service.addItems(services)
		self.app_rule_service.setCurrentIndex(0)
		self.app_rule_service.show()
		
	def app_rule_interface_type(self):
		
		# Dropdown box for selecting interface type
		
		interfaces = ["Interface", "Wireless", "LAN", "RAS", "Any"]
		
		self.app_rule_interface_type = QComboBox(self)
		self.app_rule_interface_type.setGeometry(205, 215, 190, 30)
		self.app_rule_interface_type.addItems(interfaces)
		self.app_rule_interface_type.setCurrentIndex(0)
		self.app_rule_interface_type.show()
		
	def app_rule_security(self):
		
		# Dropdown box for selecting security options
		
		security = ["Security", "Authenticate", "Authenc", "Authdynenc", "Authnoencap", "Notrequired"]
		
		self.app_rule_security = QComboBox(self)
		self.app_rule_security.setGeometry(5, 245, 390, 30)
		self.app_rule_security.addItems(security)
		self.app_rule_security.setCurrentIndex(0)
		self.app_rule_security.show()
		
	def app_rule_rmtcompgrp(self):
		
		# Text Box for rmtcomputergrp
		
		self.app_rule_rmtcompgrp = QLineEdit(self)
		self.app_rule_rmtcompgrp.setPlaceholderText("rmtcomputergrp='CN=Servers,CN=Users,DC=example,DC=com'")
		self.app_rule_rmtcompgrp.setGeometry(5, 275, 390, 30)
		self.app_rule_rmtcompgrp.show()
		
	def app_rule_rmtusrgrp(self):
		
		# Text Box for rmtusrgrp
		
		self.app_rule_rmtusrgrp = QLineEdit(self)
		self.app_rule_rmtusrgrp.setPlaceholderText("rmtusrgrp='CN=ITUsers,CN=Users,DC=example,DC=com'")
		self.app_rule_rmtusrgrp.setGeometry(5, 305, 390, 30)
		self.app_rule_rmtusrgrp.show()
		
	def app_rule_enable(self):
		
		# Dropdown box for selecting Enable=Yes|No
		
		enable = ["Enable", "Yes", "No"]
		
		self.app_rule_enable = QComboBox(self)
		self.app_rule_enable.setGeometry(5, 335, 390, 30)
		self.app_rule_enable.addItems(enable)
		self.app_rule_enable.setCurrentIndex(0)
		self.app_rule_enable.show()
		

	def app_rule_action_button(self):
		
		# Button for doing action 
		
		self.app_rule_action_button = QPushButton(self)
		self.app_rule_action_button.setText("Action")
		self.app_rule_action_button.setGeometry(5, 365, 390, 30)
		
		def action():
			cmd = "netsh advfirewall firewall add rule"
			name = self.app_rule_name.text()
			description = self.app_rule_description.toPlainText()
			program = self.app_rule_program_text_box.text().replace("/", "\\")
			localip = self.app_rule_local_ip.text()
			localport = self.app_rule_local_port.text()
			remoteip = self.app_rule_remote_ip.text()
			remoteport = self.app_rule_remote_port.text()
			dirs = self.app_rule_dir.currentText().lower()
			direction = dirs[0:2] if dirs == "inbound" else dirs[0:3]
			action = self.app_rule_action.currentText().lower()
			profile = self.app_rule_profile.currentText().lower()
			protocol = self.app_rule_protocol.currentText().lower()
			service = self.app_rule_service.currentText().lower()
			interface = self.app_rule_interface_type.currentText().lower()
			security = self.app_rule_security.currentText().lower()
			rmtcomputergrp = self.app_rule_rmtcompgrp.text()
			rmtusrgrp = self.app_rule_rmtusrgrp.text()
			enable = self.app_rule_enable.currentText().lower()
			
			
			# Check for mandatory fields 
			
			if name == "" or direction == "direction" or action == "action" or program == "" or enable == "enable":
				QMessageBox.warning(self, "Input Error", "Required field is Name, Direction, Action, Program, Enable=yes")		
			
			
			# Name
			
			if name != "":
				cmd += f' name="{name}"'
			
			
			# Direction
			
			if direction != "direction":
				cmd += f" dir={direction}"
			
			
			# Action
			
			if action != "action":
				cmd += f" action={action}"
			
			
			# Program
			
			if program != "":
				cmd += f' program="{program}"'
			
			
			# Enable
			
			if enable == "yes" or enable == "no":
				cmd += f" enable={enable}"
			
			
			# Description
			
			if description != "":
				cmd += f' description="{description}"'
			
			
			# Input filtering for Local IP address for Allow/Block Program
			
			if localip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in localip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' localip={localip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Local IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' localip=any'
			
			
			# Input filtering for Local Port number for Allow/Block Program
			
			if localport != "":
				if localport.isdigit():
					if int(localport) >= 1 and int(localport) <= 65535:
						cmd += f' localport={localport}'
					else:
						QMessageBox.warning(self, "Wrong Port Number", "Enter port number in between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' localport=any'
			
			
			# Input filtering for Remote IP address for Allow/Block Program
			
			if remoteip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in remoteip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' remoteip={remoteip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Remote IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address Format", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' remoteip=any'
			
			
			# Input filtering for Remote Port number for Allow/Block Program
			
			if remoteport != "":
				if remoteport.isdigit():
					if int(remoteport) >= 1 and int(remoteport) <= 65535:	
						cmd += f' remoteport={remoteport}'
					else:
						QMessageBox.warning(self, "Wrong Port Number", "Enter port number in between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Remote Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' localport=any'
			
		
			if profile != "profile":
				cmd += f' profile={profile}'
				
			if protocol != "protocol":
				cmd += f' protocol={protocol}'
			else:
				if localport != "" or remoteport != "":
					port = QMessageBox.information(self, "Port & Protocol rule", "If Port is specified then use tcp or udp as protocol")
					if port:
						return 0
			
			
			# Service
			
			if service != "service":
				cmd += f' service={service}'
			
			
			# Interface Type
			
			if interface != "interface":
				cmd += f' interfacetype={interface}'
			
			
			# Security
			
			if security != "security":
				cmd += f' security={security}'
			
			
			# rmtcomputergrp
			
			if rmtcomputergrp != "":
				cmd += f' rmtcomputergrp={rmtcomputergrp}'
			
			
			# rmtusrgrp
			
			if rmtusrgrp != "":
				cmd += f' rmtusrgrp={rmtusrgrp}'
			
			
			# Run the command
			print(cmd)
			state = subprocess.run(cmd, shell=True)
			
			if "returncode=1" in str(state):
				QMessageBox.warning(self, "Privillege Error", "You need to be Administrator")			
			else:
				QMessageBox.information(self, "Success", "Rule successfully added.")
				self.close()
				
		self.app_rule_action_button.clicked.connect(action)
		self.app_rule_action_button.show()
		

class Allow_Block_Port(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Allow Block Port")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setGeometry(500, 100, 400, 250)
		self.setFixedSize(400, 250)
	
	def allow_block_port_rule_name(self):
		
		# Text Box for entering rule name for allow block port 
	
		self.allow_block_port_rule_name = QLineEdit(self)
		self.allow_block_port_rule_name.setPlaceholderText("Enter the rule name...")
		self.allow_block_port_rule_name.setGeometry(5, 5, 390, 30)
		self.allow_block_port_rule_name.show()
	
	def allow_block_port_rule_description(self):
		
		# Text area for entering description for allow block port
		
		self.allow_block_port_rule_description = QTextEdit(self)
		self.allow_block_port_rule_description.setPlaceholderText("Enter the description here...")
		self.allow_block_port_rule_description.setGeometry(5, 35, 390, 60)
		self.allow_block_port_rule_description.show()
		
	def allow_block_port_rule_local_ip(self):
		
		# Text Box for entering local ip address here
		
		self.allow_block_port_rule_local_ip = QLineEdit(self)
		self.allow_block_port_rule_local_ip.setPlaceholderText("L_IP:255.255.255.255")
		self.allow_block_port_rule_local_ip.setGeometry(5, 95, 140, 30)
		self.allow_block_port_rule_local_ip.show()
	
	def allow_block_port_rule_local_port(self):
		
		# Text Box for entering local Port number here
		
		self.allow_block_port_rule_local_port = QLineEdit(self)
		self.allow_block_port_rule_local_port.setPlaceholderText("L_Port")
		self.allow_block_port_rule_local_port.setGeometry(145, 95, 55, 30)
		self.allow_block_port_rule_local_port.show()
	
	def allow_block_port_rule_remote_ip(self):
		
		# Text Box for entering remote ip address here
		
		self.allow_block_port_rule_remote_ip = QLineEdit(self)
		self.allow_block_port_rule_remote_ip.setPlaceholderText("R_IP:255.255.255.255")
		self.allow_block_port_rule_remote_ip.setGeometry(200, 95, 140, 30)
		self.allow_block_port_rule_remote_ip.show()
	
	def allow_block_port_rule_remote_port(self):
		
		# Text Box for entering remote port number 
		
		self.allow_block_port_rule_remote_port = QLineEdit(self)
		self.allow_block_port_rule_remote_port.setPlaceholderText("R_Port")
		self.allow_block_port_rule_remote_port.setGeometry(340, 95, 55, 30)
		self.allow_block_port_rule_remote_port.show()
		
	def allow_block_port_rule_direction(self):
		
		# Dropdown box for selecting direction either Inbound or Outbound
		
		direction = ["Direction", "Inbound", "Outbound"]
		
		self.allow_block_port_rule_direction = QComboBox(self)
		self.allow_block_port_rule_direction.setGeometry(5, 125, 195, 30)
		self.allow_block_port_rule_direction.addItems(direction)
		self.allow_block_port_rule_direction.setCurrentIndex(0)
		self.allow_block_port_rule_direction.show()
	
	def allow_block_port_rule_action(self):
		
		# Dropdown box for selecting action either allow or block
		
		action = ["Action", "Allow", "Block"]
		
		self.allow_block_port_rule_action = QComboBox(self)
		self.allow_block_port_rule_action.setGeometry(200, 125, 195, 30)
		self.allow_block_port_rule_action.addItems(action)
		self.allow_block_port_rule_action.setCurrentIndex(0)
		self.allow_block_port_rule_action.show()
		
	def allow_block_port_rule_protocol(self):
		
		# Dropdown box for selecting protocols according to need

		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		
		self.allow_block_port_rule_protocol = QComboBox(self)
		self.allow_block_port_rule_protocol.setGeometry(5, 155, 195, 30)
		self.allow_block_port_rule_protocol.addItems(protocols)
		self.allow_block_port_rule_protocol.setCurrentIndex(0)
		self.allow_block_port_rule_protocol.show()

	def allow_block_port_rule_profile(self):
		
		# Dropdown box for selecting profile according to need
		
		profile = ["Profile", "Domain", "Private", "Public", "Any"]
		
		self.allow_block_port_rule_profile = QComboBox(self)
		self.allow_block_port_rule_profile.setGeometry(200, 155, 195, 30)
		self.allow_block_port_rule_profile.addItems(profile)
		self.allow_block_port_rule_profile.setCurrentIndex(0)
		self.allow_block_port_rule_profile.show()
	
	def allow_block_port_rule_enable(self):
		
		# Dropdown box for selecting yes or no for enable rule
		
		enable = ["Enable", "Yes", "No"]
		
		self.allow_block_port_rule_enable = QComboBox(self)
		self.allow_block_port_rule_enable.setGeometry(5, 185, 390, 30)
		self.allow_block_port_rule_enable.addItems(enable)
		self.allow_block_port_rule_enable.setCurrentIndex(0)
		self.allow_block_port_rule_enable.show()
	
	def allow_block_port_action_button(self):
		
		# Button for doing action for allow block port
		
		self.allow_block_port_action_button = QPushButton(self)
		self.allow_block_port_action_button.setText("Action")
		self.allow_block_port_action_button.setGeometry(5, 215, 390, 30)
		
		def allow_block_port():
			cmd = "netsh advfirewall firewall add rule"
			name = self.allow_block_port_rule_name.text()
			description = self.allow_block_port_rule_description.toPlainText()
			localip = self.allow_block_port_rule_local_ip.text()
			localport = self.allow_block_port_rule_local_port.text()
			remoteip = self.allow_block_port_rule_remote_ip.text()
			remoteport = self.allow_block_port_rule_remote_port.text()
			direct = self.allow_block_port_rule_direction.currentText().lower()
			direction = direct[0:2] if direct == "inbound" else direct[0:3]
			action = self.allow_block_port_rule_action.currentText().lower()
			protocol = self.allow_block_port_rule_protocol.currentText().lower()
			profile = self.allow_block_port_rule_profile.currentText().lower()
			enable = self.allow_block_port_rule_enable.currentText().lower()
			
			
			# Check for mandatory fields 
			
			if name == "" or direction == "" or action == "" or protocol == "" or localport == "":
				QMessageBox.warning(self, "Input Error", "Mandatory field is Name, Direction, Action, Protocol, Local Port...")
			
			
			# Name
			
			if name != "":
				cmd += f' name="{name}"'
			
			# Description
			
			if description != "":
				cmd += f' description="{description}"'
				
			# Direction
			
			if direction != "dir":
				cmd += f' dir="{direction}"'
			
			
			# Action
			
			if action != "action":
				cmd += f' action={action}'
			
			
			# Input Filtering for Local IP for Allow/Block Port
			
			if localip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in localip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' localip={localip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Local IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' localip=any'
			
			
			# Input Filtering for Local Port Number for Allow/Block Port
			
			if localport != "":
				if localport.isdigit():
					if int(localport) >= 1 and int(localport) <= 65535:
						cmd += f' localport={localport}'	
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' localport=any'
			
			
			# Input Filtering for Remote IP address for Allow/Block Port
			
			if remoteip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in remoteip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' remoteip={remoteip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Remote IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' remoteip=any'
			
			
			# Input Filtering for Remote Port for Allow/Block Port
		
			if remoteport != "":
				if remoteport.isdigit():
					if int(remoteport) >= 1 and int(remoteport) <= 65535:
						cmd += f' remoteport={remoteport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...") 
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Remote Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' remoteport=any'
					
					
			# Protocol
			
			if protocol != "protocol":
				cmd += f' protocol={protocol}'
			else:
				if localport != "" or remoteport != "":
					port = QMessageBox.information(self, "Port & Protocol rule", "If Port is specified then use tcp or udp as protocol")
					if port:
						return 0
			
			
			# Enable
			
			if enable != "enable":
				cmd += f' enable={enable}'
			
			
			# Run the Command 
			
			state = subprocess.run(cmd, shell=True)
			
			if "returncode=1" in str(state):
				QMessageBox.warning(self, "Privillege Error", "You need to be Administrator")			
			else:
				QMessageBox.information(self, "Success", "Rule successfully added.")
				self.close()
				
		self.allow_block_port_action_button.clicked.connect(allow_block_port)
		self.allow_block_port_action_button.show()


class Allow_Block_Service(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Allow Block Service")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setGeometry(500, 100, 400, 310)
		self.setFixedSize(400, 310)
	
	def allow_block_service_rule_nme(self):
		
		# Text box for entering rule name for allow block service
		
		self.allow_block_service_rule_nme = QLineEdit(self)
		self.allow_block_service_rule_nme.setPlaceholderText("Enter the rule name...")
		self.allow_block_service_rule_nme.setGeometry(5, 5, 390, 30)
		self.allow_block_service_rule_nme.show()
		
	def allow_block_service_rule_description(self):
		
		# Text area for allow or block service's description
		
		self.allow_block_service_rule_description = QTextEdit(self)
		self.allow_block_service_rule_description.setPlaceholderText("Enter the description here...")
		self.allow_block_service_rule_description.setGeometry(5, 35, 390, 60)
		self.allow_block_service_rule_description.show()
	
	def allow_block_service_rule_local_ip(self):
		
		# Text box for entering local ip address
	
		self.allow_block_service_rule_local_ip = QLineEdit(self)
		self.allow_block_service_rule_local_ip.setPlaceholderText("L_IP:255.255.255.255")
		self.allow_block_service_rule_local_ip.setGeometry(5, 95, 140, 30)
		self.allow_block_service_rule_local_ip.show()
		
	def allow_block_service_rule_local_port(self):
		
		# Text box for entering local port number
		
		self.allow_block_service_rule_local_port = QLineEdit(self)
		self.allow_block_service_rule_local_port.setPlaceholderText("L_Port")
		self.allow_block_service_rule_local_port.setGeometry(145, 95, 55, 30)
		self.allow_block_service_rule_local_port.show()
	
	def allow_block_service_rule_remote_ip(self):
		
		# Text box for entering remote ip address
		
		self.allow_block_service_rule_remote_ip = QLineEdit(self)
		self.allow_block_service_rule_remote_ip.setPlaceholderText("R_IP:255.255.255.255")
		self.allow_block_service_rule_remote_ip.setGeometry(200, 95, 140, 30)
		self.allow_block_service_rule_remote_ip.show()
	
	def allow_block_service_rule_remote_port(self):
		
		# Text Box for entering remote port number 
		
		self.allow_block_service_rule_remote_port = QLineEdit(self)
		self.allow_block_service_rule_remote_port.setPlaceholderText("R_Port")
		self.allow_block_service_rule_remote_port.setGeometry(340, 95, 55, 30)
		self.allow_block_service_rule_remote_port.show()
	
	def allow_block_service_rule_direction(self):
		
		# Dropdown box for selecting direction either Inbound or Outbound
		
		direction = ["Direction", "Inbound", "Outbound"]
		
		self.allow_block_service_rule_direction = QComboBox(self)
		self.allow_block_service_rule_direction.setGeometry(5, 125, 195, 30)
		self.allow_block_service_rule_direction.addItems(direction)
		self.allow_block_service_rule_direction.setCurrentIndex(0)
		self.allow_block_service_rule_direction.show()
		
	def allow_block_service_rule_action(self):
		
		# Dropdown box for selecting action like allow or block
		
		action = ["Action", "Allow", "Block"]
		
		self.allow_block_service_rule_action = QComboBox(self)
		self.allow_block_service_rule_action.setGeometry(200, 125, 195, 30)
		self.allow_block_service_rule_action.addItems(action)
		self.allow_block_service_rule_action.setCurrentIndex(0)
		self.allow_block_service_rule_action.show()
		
	def allow_block_service_rule_service(self):
		
		# Dropdown box for selecting service according to need
		
		services = ["Service", "Wuauserv","Bits","Dhcp","Dnscache","EventLog","Schedule","WinDefend","Spooler","TermService", "LanmanWorkstation","LanmanServer","Browser","W32Time","IKEEXT","iphlpsvc","PolicyAgent", "RemoteRegistry","lmhosts","Netlogon","ProfSvc","RpcSs","RpcLocator","SamSs","SCardSvr", "Winmgmt","SSDPSRV","upnphost","TrkWks","Themes","WSearch","TrustedInstaller","Wecsvc", "WerSvc","WEPHOSTSVC","WdiServiceHost","WdNisSvc","msiserver","BFE","MpsSvc","WlanSvc", "ALG","AudioSrv","Audiosrv","Fax","FTP","FTPSVC","ftpsvc","MSMQ","Netman","NlaSvc","NcbService", "PlugPlay","Power","RasMan","RasAuto","RDPDR","TermService","UmRdpService","SessionEnv", "ShellHWDetection","SharedAccess","stisvc","SysMain","TapiSrv","TrkWks","UmRdpService", "W3SVC","WAS","wscsvc","wdiagsvc","WdNisSvc","WinHttpAutoProxySvc","WpnService","WpnUserService","AppHostSvc","Appinfo","AppMgmt","BthHFSrv","CertPropSvc","ClipSVC","DoSvc","edgeupdate","edgeupdatem","gpsvc","HvHost","InstallService","IntelAudioService","iphlpsvc","lfsvc","lmhosts","MapsBroker","MessagingService","MixedRealityOpenXRSvc","NgcSvc","NgcCtnrSvc","OneSyncSvc","PhoneSvc","PrintNotify","PushToInstall","QWAVE","RtkAudioUniversalService","SEMgrSvc","SessionEnv","StateRepository","StorSvc","svsvc","SystemEventsBroker","TimeBrokerSvc","UserManager","UsoSvc","VacSvc","VaultSvc","WaaSMedicSvc","Wcmsvc","WdBoot","WdFilter","WerSvc","wisvc","WMPNetworkSvc","workfolderssvc","WpcMonSvc","WPDBusEnum","wscsvc"]
		
		self.allow_block_service_rule_service = QComboBox(self)
		self.allow_block_service_rule_service.setGeometry(5, 155, 195, 30)
		self.allow_block_service_rule_service.addItems(services)
		self.allow_block_service_rule_service.setCurrentIndex(0)
		self.allow_block_service_rule_service.show()
		
	def allow_block_service_rule_protocol(self):
		
		# Dropdown box for selecting protocol according to need
		
		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		
		self.allow_block_service_rule_protocol = QComboBox(self)
		self.allow_block_service_rule_protocol.setGeometry(200, 155, 195, 30)
		self.allow_block_service_rule_protocol.addItems(protocols)
		self.allow_block_service_rule_protocol.setCurrentIndex(0)
		self.allow_block_service_rule_protocol.show()
	
	def allow_block_service_rule_profile(self):
		
		# Dropdown box for selecting profile according to need
		
		profile = ["Profile", "Domain", "Private", "Public", "Any"]
		
		self.allow_block_service_rule_profile = QComboBox(self)
		self.allow_block_service_rule_profile.setGeometry(5, 185, 195, 30)
		self.allow_block_service_rule_profile.addItems(profile)
		self.allow_block_service_rule_profile.setCurrentIndex(0)
		self.allow_block_service_rule_profile.show()
	
	def allow_block_service_rule_interfacetype(self):
		
		# Dropdown box for selecting interfacetype according to need
		
		interfaces = ["Interface", "Wireless", "LAN", "RAS", "Any"]
		
		self.allow_block_service_rule_interfacetype = QComboBox(self)
		self.allow_block_service_rule_interfacetype.setGeometry(200, 185, 195, 30)
		self.allow_block_service_rule_interfacetype.addItems(interfaces)
		self.allow_block_service_rule_interfacetype.setCurrentIndex(0)
		self.allow_block_service_rule_interfacetype.show()
	
	def allow_block_service_rule_edge(self):
		
		# Dropdown box for selecting 
		
		edge = ["Edge", "Yes", "No", "Deferapp"]
		
		self.allow_block_service_rule_edge = QComboBox(self)
		self.allow_block_service_rule_edge.setGeometry(5, 215, 390, 30)
		self.allow_block_service_rule_edge.addItems(edge)
		self.allow_block_service_rule_edge.setCurrentIndex(0)
		self.allow_block_service_rule_edge.show()
	
	def allow_block_service_rule_enable(self):
		
		# Dropdown box for selecting Enable yes/no
		
		enable = ["Enable", "Yes", "No"]
		
		self.allow_block_service_rule_enable = QComboBox(self)
		self.allow_block_service_rule_enable.setGeometry(5, 245, 390, 30)
		self.allow_block_service_rule_enable.addItems(enable)
		self.allow_block_service_rule_enable.setCurrentIndex(0)
		self.allow_block_service_rule_enable.show()
				
	def allow_block_service_rule_action_button(self):
		
		# Button for doing allow or block service 
		
		self.allow_block_service_rule_action_button = QPushButton(self)
		self.allow_block_service_rule_action_button.setText("Action")
		self.allow_block_service_rule_action_button.setGeometry(5, 275, 390, 30)
				
		def allow_block_service():
			cmd = "netsh advfirewall firewall add rule"
			name = self.allow_block_service_rule_nme.text()
			description = self.allow_block_service_rule_description.toPlainText()
			localip = self.allow_block_service_rule_local_ip.text()
			localport = self.allow_block_service_rule_local_port.text()
			remoteip = self.allow_block_service_rule_remote_ip.text()
			remoteport = self.allow_block_service_rule_remote_port.text()
			dirs = self.allow_block_service_rule_direction.currentText().lower()
			direction = dirs[0:2] if dirs == "inbound" else dirs[0:3]
			action = self.allow_block_service_rule_action.currentText().lower()
			service = self.allow_block_service_rule_service.currentText().lower()
			protocol = self.allow_block_service_rule_protocol.currentText().lower()
			profile = self.allow_block_service_rule_profile.currentText().lower()
			interface = self.allow_block_service_rule_interfacetype.currentText().lower()
			edge = self.allow_block_service_rule_edge.currentText().lower()
			enable = self.allow_block_service_rule_enable.currentText().lower()
			
			
			# Check for mandatory fields
			
			if name == "" or direction == "" or action == "" or service == "" or enable == "":
				QMessageBox.warning(self, "Missing Input", "Mandatory fields for allow/block service is Name,Direction,Action,Service,Enable")
		
		
			# Name 
			
			if name != "":
				cmd += f' name="{name}"'
			
			
			# Direction
			
			if direction != "dir":
				cmd += f' dir={direction}'
			
			
			# Action
			
			if action != "action":
				cmd += f' action={action}'
			
			
			# Service
			
			if service != "service":
				cmd += f' service={service}'
			
			
			# Enable
			
			if enable != "enable":
				cmd += f' enable={enable}'
			
			
			# Description
			
			if description != "":
				cmd += f' description="{description}"'
			
			
			# Input filtering for Local IP address 
			
			if localip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in localip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' localip={localip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Local IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' localip=any'
			
			
			# Input filtering for local port number	
			
			if localport != "":
				if localport.isdigit():
					if int(localport) >= 1 and int(localport) <= 65535:
						cmd += f' localport={localport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' localport=any'
			
			
			# Input filtering for remote ip address
			
			if remoteip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in remoteip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' remoteip={remoteip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Remote IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' remoteip=any'					
			
			
			# Input filtering for remote port number
			
			if remoteport != "":
				if remoteport.isdigit():
					if int(remoteport) >= 1 and int(remoteport) <= 65535:
						cmd += f' remoteport={remoteport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' remoteport=any'
			
			
			# Protocol
			
			if protocol != "protocol":
				cmd += f' protocol={protocol}'
			else:
				if localport != "" or remoteport != "":
					port = QMessageBox.information(self, "Port & Protocol rule", "If Port is specified then use tcp or udp as protocol")
					if port:
						return 0
			
			
			# Interface type
			
			if interface != "interface":
				cmd += f' interfacetype={interface}'
			
			
			# Edge
			
			if edge != "edge":
				cmd += f' edge={edge}'
			
			
			# Run the Command 
			
			state = subprocess.run(cmd, shell=True)

			if "returncode=1" in str(state):
				QMessageBox.warning(self, "Privillege Error", "You need to be Administrator")			
			else:
				QMessageBox.information(self, "Successfull", "Rule successfully added.")
				self.close()
				
		self.allow_block_service_rule_action_button.clicked.connect(allow_block_service)
		self.allow_block_service_rule_action_button.show()
		
		
class Allow_Block_Private_IP(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Allow Block Private IP")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setGeometry(500, 100, 400, 280)
		self.setFixedSize(400, 280)
	
	def allow_block_private_ip_name(self):
		
		# Text box for entering rule name of allow block private ip address
		
		self.allow_block_private_ip_name = QLineEdit(self)
		self.allow_block_private_ip_name.setPlaceholderText("Enter the rule name...")
		self.allow_block_private_ip_name.setGeometry(5, 5, 390, 30)
		self.allow_block_private_ip_name.show()
		
	def allow_block_private_ip_description(self):
		
		# Text Area for entering rule description
		
		self.allow_block_private_ip_description = QTextEdit(self)
		self.allow_block_private_ip_description.setPlaceholderText("Enter the description here...")
		self.allow_block_private_ip_description.setGeometry(5, 35, 390, 60)
		self.allow_block_private_ip_description.show()
	
	def allow_block_private_ip_local_ip(self):
		
		# Text box for entering local ip address 
		
		self.allow_block_private_ip_local_ip = QLineEdit(self)
		self.allow_block_private_ip_local_ip.setPlaceholderText("L IP:255.255.255.255")
		self.allow_block_private_ip_local_ip.setGeometry(5, 95, 140, 30)
		self.allow_block_private_ip_local_ip.show()
	
	def allow_block_private_ip_local_port(self):
		
		# Text box for entering local port
		
		self.allow_block_private_ip_local_port = QLineEdit(self)
		self.allow_block_private_ip_local_port.setPlaceholderText("L Port")
		self.allow_block_private_ip_local_port.setGeometry(145, 95, 55, 30)
		self.allow_block_private_ip_local_port.show()
		
	def allow_block_private_ip_remote_ip(self):
		
		# Text box for entering remote ip address 
		
		self.allow_block_private_ip_remote_ip = QLineEdit(self)
		self.allow_block_private_ip_remote_ip.setPlaceholderText("R IP:255.255.255.255")
		self.allow_block_private_ip_remote_ip.setGeometry(200, 95, 140, 30)
		self.allow_block_private_ip_remote_ip.show()
		
	def allow_block_private_ip_remote_port(self):
		
		# Text box for entering remote port number
		
		self.allow_block_private_ip_remote_port = QLineEdit(self)
		self.allow_block_private_ip_remote_port.setPlaceholderText("R Port")
		self.allow_block_private_ip_remote_port.setGeometry(340, 95, 55, 30)
		self.allow_block_private_ip_remote_port.show()
		
	def allow_block_private_ip_direction(self):
		
		# Dropdown box for selecting allow_block_private_ip direction either inbound or outbound
		
		direction = ["Direction", "Inbound", "Outbound"]
		
		self.allow_block_private_ip_direction = QComboBox(self)
		self.allow_block_private_ip_direction.setGeometry(5, 125, 195, 30)
		self.allow_block_private_ip_direction.addItems(direction)
		self.allow_block_private_ip_direction.setCurrentIndex(0)
		self.allow_block_private_ip_direction.show()

	def allow_block_private_ip_action(self):
		
		# Dropdown box for selecting action either allow or block
		
		action = ["Action", "Allow", "Block"]
		
		self.allow_block_private_ip_action = QComboBox(self)
		self.allow_block_private_ip_action.setGeometry(200, 125, 195, 30)
		self.allow_block_private_ip_action.addItems(action)
		self.allow_block_private_ip_action.setCurrentIndex(0)
		self.allow_block_private_ip_action.show()
		
	def allow_block_private_ip_protocol(self):
		
		# Dropdown box for selecting protocol according to need
		
		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		
		self.allow_block_private_ip_protocol = QComboBox(self)
		self.allow_block_private_ip_protocol.setGeometry(5, 155, 195, 30)
		self.allow_block_private_ip_protocol.addItems(protocols)
		self.allow_block_private_ip_protocol.setCurrentIndex(0)
		self.allow_block_private_ip_protocol.show()
		
	def allow_block_private_ip_profile(self):
		
		# Dropdown box for selecting profile according to need
		
		profiles = ["Profile", "Domain", "Private", "Public", "Any"]
		
		self.allow_block_private_ip_profile = QComboBox(self)
		self.allow_block_private_ip_profile.setGeometry(200, 155, 195, 30)
		self.allow_block_private_ip_profile.addItems(profiles)
		self.allow_block_private_ip_profile.setCurrentIndex(0)
		self.allow_block_private_ip_profile.show()
	
	def allow_block_private_ip_interface_type(self):
		
		# Dropdown box for selecting interface type
		
		interfaces = ["Interface", "Wireless", "LAN", "RAS", "Any"]
		
		self.allow_block_private_ip_interface_type = QComboBox(self)
		self.allow_block_private_ip_interface_type.setGeometry(5, 185, 195, 30)
		self.allow_block_private_ip_interface_type.addItems(interfaces)
		self.allow_block_private_ip_interface_type.setCurrentIndex(0)
		self.allow_block_private_ip_interface_type.show()
	
	def allow_block_private_ip_edge(self):
		
		# Dropdown box for selecting edge
		
		edge = ["Edge", "Yes", "No", "Deferapp"]
				
		self.allow_block_private_ip_edge = QComboBox(self)
		self.allow_block_private_ip_edge.setGeometry(200, 185, 195, 30)
		self.allow_block_private_ip_edge.addItems(edge)
		self.allow_block_private_ip_edge.setCurrentIndex(0)
		self.allow_block_private_ip_edge.show()
	
	def allow_block_private_ip_enable(self):
		
		# Dropdown box for selecting for enable yes or no
		
		enable = ["Enable", "Yes", "No"]
		
		self.allow_block_private_ip_enable = QComboBox(self)
		self.allow_block_private_ip_enable.setGeometry(5, 215, 390, 30)
		self.allow_block_private_ip_enable.addItems(enable)
		self.allow_block_private_ip_enable.setCurrentIndex(0)
		self.allow_block_private_ip_enable.show()
		
	def allow_block_private_ip_action_button(self):
		
		# Button for performing allow_block_private_ip 
		
		self.allow_block_private_ip_action_button = QPushButton(self)
		self.allow_block_private_ip_action_button.setText("Action")
		self.allow_block_private_ip_action_button.setGeometry(5, 245, 390, 30)
	
		def allow_block_private_ip():
			
			cmd = "netsh advfirewall firewall add rule"
			
			name = self.allow_block_private_ip_name.text()
			description = self.allow_block_private_ip_description.toPlainText()
			localip = self.allow_block_private_ip_local_ip.text()
			localport = self.allow_block_private_ip_local_port.text()
			remoteip = self.allow_block_private_ip_remote_ip.text()
			remoteport = self.allow_block_private_ip_remote_port.text()
			dire = self.allow_block_private_ip_direction.currentText().lower()
			direction = dire[0:2] if dire == "inbound" else dire[0:3]
			action = self.allow_block_private_ip_action.currentText().lower()
			protocol = self.allow_block_private_ip_protocol.currentText().lower()
			profile = self.allow_block_private_ip_profile.currentText().lower()
			edge = self.allow_block_private_ip_edge.currentText().lower()
			enable = self.allow_block_private_ip_enable.currentText().lower()
			interface = self.allow_block_private_ip_interface_type.currentText().lower()
			
			# Check for mandatory fields
			
			if name == "" or direction == "dir" or action == "action" or remoteip == "" or enable == "enable":
				QMessageBox.warning(self, "Missing Input", "Mandatory fields for allow/block service is Name,Direction,Action,RemoteIP,Enable")
			
			
			# Name
			
			if name != "":
				cmd += f' name="{name}"'
			
			
			# Description
			
			if description != "":
				cmd += f' description="{description}"'
			
			
			# Local IP Address
			
			if localip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in localip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' localip={localip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Local IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' localip=any'
			
			# Input Filtering for Local Port 
			
			if localport != "":
				if localport.isdigit():
					if int(localport) >= 1 and int(localport) <= 65535:
						cmd += f' localport={localport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' localport=any'
			
			
			# Input Filtering for Remote IP address
			
			if remoteip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in remoteip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' remoteip={remoteip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Remote IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' remoteip=any'
		
		
		
			# Input Filtering for Remote Port
			
			if remoteport != "":
				if remoteport.isdigit():
					if int(remoteport) >= 1 and int(remoteport) <= 65535:
						cmd += f' remoteport={remoteport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' remoteport=any'
	
	
			# Direction 
			
			if direction != "dir":
				cmd += f' dir={direction}'
			
			
			# Action
			
			if action != "action":
				cmd += f' action={action}'
			
			
			# Protocol	
			
			if protocol != "protocol":
				cmd += f' protocol={protocol}'
			
			
			# Profile
			
			if profile != "profile":
				cmd += f' profile={profile}'
			
			
			# Edge
			
			if edge != "edge":
				cmd += f' edge={edge}'
			
			
			# Interface
			
			if interface != "interface":
				cmd += f' interfacetype={interface}'
		
		
			# Enable
			
			if enable != "enable":
				cmd += f' enable={enable}'
			
			
			# Run the Command
			
			state = subprocess.run(cmd, shell=True)
			
			
			if "returncode=1" in str(state):
				QMessageBox.warning(self, "Privillege Error", "You need to be Administrator")			
			else:
				QMessageBox.information(self, "Successfull", "Rule successfully added.")
				self.close()
				
				
		self.allow_block_private_ip_action_button.clicked.connect(allow_block_private_ip)
		self.allow_block_private_ip_action_button.show()
		
	
	
class Allow_Block_Public_IP(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Allow Block Public IP")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setGeometry(500, 100, 400, 280)
		self.setFixedSize(400, 280)
	
	def allow_block_public_ip_name(self):
		
		# Text box for entering rule name
		
		self.allow_block_public_ip_name = QLineEdit(self)
		self.allow_block_public_ip_name.setPlaceholderText("Enter the rule name...")
		self.allow_block_public_ip_name.setGeometry(5, 5, 390, 30)
		self.allow_block_public_ip_name.show()
		
	def allow_block_public_ip_description(self):
		
		# Text area for entering description for rule
		
		self.allow_block_public_ip_description = QTextEdit(self)
		self.allow_block_public_ip_description.setPlaceholderText("Enter the description here...")
		self.allow_block_public_ip_description.setGeometry(5, 35, 390, 60)
		self.allow_block_public_ip_description.show()
		
	def allow_block_public_ip_local_ip(self):
		
		# Text box for entering local ip address here 
		
		self.allow_block_public_ip_local_ip = QLineEdit(self)
		self.allow_block_public_ip_local_ip.setPlaceholderText("Enter the local ip...")
		self.allow_block_public_ip_local_ip.setGeometry(5, 95, 140, 30)
		self.allow_block_public_ip_local_ip.show()
		
	def allow_block_public_ip_local_port(self):
		
		# Text box for entering local port number here
		
		self.allow_block_public_ip_local_port = QLineEdit(self)
		self.allow_block_public_ip_local_port.setPlaceholderText("L Port")
		self.allow_block_public_ip_local_port.setGeometry(145, 95, 55, 30)
		self.allow_block_public_ip_local_ip.show()
	
	def allow_block_public_ip_remote_ip(self):
		
		# Text box for entering remote ip address here
		
		self.allow_block_public_ip_remote_ip = QLineEdit(self)
		self.allow_block_public_ip_remote_ip.setPlaceholderText("Enter the remote ip...")
		self.allow_block_public_ip_remote_ip.setGeometry(200, 95, 140, 30)
		self.allow_block_public_ip_remote_ip.show()
	
	def allow_block_public_ip_remote_port(self):
		
		# Text box for entering remote port number 
		
		self.allow_block_public_ip_remote_port = QLineEdit(self)
		self.allow_block_public_ip_remote_port.setPlaceholderText("R Port")
		self.allow_block_public_ip_remote_port.setGeometry(340, 95, 55, 30)
		self.allow_block_public_ip_remote_port.show()
		
	def allow_block_public_ip_direction(self):
		
		# Dropdown box for selection direcion either inbound or outbound
		
		direction = ["Direction", "Inbound", "Outbound"]
		
		self.allow_block_public_ip_direction = QComboBox(self)
		self.allow_block_public_ip_direction.setGeometry(5, 125, 195, 30)
		self.allow_block_public_ip_direction.addItems(direction)
		self.allow_block_public_ip_direction.setCurrentIndex(0)
		self.allow_block_public_ip_direction.show()
	
	def allow_block_public_ip_action(self):
		
		# Dropdown box for selecting action like allow or block
		
		actions = ["Action", "Allow", "Block"]
		
		self.allow_block_public_ip_action = QComboBox(self)
		self.allow_block_public_ip_action.setGeometry(200, 125, 195, 30)
		self.allow_block_public_ip_action.addItems(actions)
		self.allow_block_public_ip_action.setCurrentIndex(0)
		self.allow_block_public_ip_action.show()
	
	
	def allow_block_public_ip_protocol(self):
		
		# Dropdown box for selecting protocol according to need
		
		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		
		self.allow_block_public_ip_protocol = QComboBox(self)
		self.allow_block_public_ip_protocol.setGeometry(5, 155, 195, 30)
		self.allow_block_public_ip_protocol.addItems(protocols)
		self.allow_block_public_ip_protocol.setCurrentIndex(0)
		self.allow_block_public_ip_protocol.show()
	
	def allow_block_public_ip_profile(self):
		
		# Dropdown box for selecting profile
		
		profiles = ["Profile", "Domain", "Private", "Public", "Any"]
		
		self.allow_block_public_ip_profile = QComboBox(self)
		self.allow_block_public_ip_profile.setGeometry(200, 155, 195, 30)
		self.allow_block_public_ip_profile.addItems(profiles)
		self.allow_block_public_ip_profile.setCurrentIndex(0)
		self.allow_block_public_ip_profile.show()
	
	def allow_block_public_ip_interface_type(self):
		
		# Dropdown box for selecting interface type 
		
		interfaces = ["Interface", "Wireless", "LAN", "RAS", "Any"]
		
		self.allow_block_public_ip_interface_type = QComboBox(self)
		self.allow_block_public_ip_interface_type.setGeometry(5, 185, 195, 30)
		self.allow_block_public_ip_interface_type.addItems(interfaces)
		self.allow_block_public_ip_interface_type.setCurrentIndex(0)
		self.allow_block_public_ip_interface_type.show()
		
	def allow_block_public_ip_edge(self):
		
		# Dropdown box for selecting edge value
		
		edge = ["Edge", "Yes", "Deferapp", "Deferuser", "No"]
		
		self.allow_block_public_ip_edge = QComboBox(self)
		self.allow_block_public_ip_edge.setGeometry(200, 185, 195, 30)
		self.allow_block_public_ip_edge.addItems(edge)
		self.allow_block_public_ip_edge.setCurrentIndex(0)
		self.allow_block_public_ip_edge.show()
	
	def allow_block_public_ip_enable(self):
		
		# Dropdown box for selecting enable yes or no
		
		enable = ["Enable", "Yes", "No"]
		
		self.allow_block_public_ip_enable = QComboBox(self)
		self.allow_block_public_ip_enable.addItems(enable)
		self.allow_block_public_ip_enable.setGeometry(5, 215, 390, 30)
		self.allow_block_public_ip_enable.setCurrentIndex(0)
		self.allow_block_public_ip_enable.show()
		
	def allow_block_public_ip_action_button(self):
		
		# Button to performing allow_block_public_ip action
		
		self.allow_block_public_ip_action_button = QPushButton(self)
		self.allow_block_public_ip_action_button.setText("Action")
		self.allow_block_public_ip_action_button.setGeometry(5, 245, 390, 30)
		
		def allow_block_public_ip():
			
			cmd = "netsh advfirewall firewall add rule"
			name = self.allow_block_public_ip_name.text()
			description = self.allow_block_public_ip_description.toPlainText()
			localip = self.allow_block_public_ip_local_ip.text()
			localport = self.allow_block_public_ip_local_port.text()
			remoteip = self.allow_block_public_ip_remote_ip.text()
			remoteport = self.allow_block_public_ip_remote_port.text()
			dirs = self.allow_block_public_ip_direction.currentText().lower()
			direction = dirs[0:2] if dirs == "inbound" else dirs[0:3]
			action = self.allow_block_public_ip_action.currentText().lower()
			protocol = self.allow_block_public_ip_protocol.currentText().lower()
			profile = self.allow_block_public_ip_profile.currentText().lower()
			interface = self.allow_block_public_ip_interface_type.currentText().lower()
			edge = self.allow_block_public_ip_edge.currentText().lower()
			enable = self.allow_block_public_ip_enable.currentText().lower()
			
			# Check for mandatory input fields 
			
			if name == "" or direction == "dir" or action == "action" or remoteip == "" or enable == "enable":
				QMessageBox.warning(self, "Missing Input", "Mandatory fields for allow/block service is Name,Direction,Action,RemoteIP,Enable")
			
			
			# Name
			
			if name != "":
				cmd += f' name="{name}"'
			
			
			# Description
			
			if description != "":
				cmd += f' description="{description}"'
			
			
			# Input Filtering for Local IP Address
			
			if localip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in localip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' localip={localip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Local IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' localip=any'
			
			
			# Input Filtering for Local Port 
			
			if localport != "":
				if localport.isdigit():
					if int(localport) >= 1 and int(localport) <= 65535:
						cmd += f' localport={localport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' localport=any'
			
			
			# Input Filtering for Remote IP address
			
			if remoteip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in remoteip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' remoteip={remoteip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Remote IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
					
			else:
				cmd += f' remoteip=any'
		
		
		
			# Input Filtering for Remote Port
			
			if remoteport != "":
				if remoteport.isdigit():
					if int(remoteport) >= 1 and int(remoteport) <= 65535:
						cmd += f' remoteport={remoteport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			else:
				if protocol == "tcp" or protocol == "udp":
					cmd += f' remoteport=any'
				
				
			# Direction
			
			if direction != "":
				cmd += f' dir={direction}'

			
			# Action
			
			if action != "action":
				cmd += f' action={action}'
			
			
			# Protocol	
			
			if protocol != "protocol":
				cmd += f' protocol={protocol}'
			
			
			# Profile
			
			if profile != "profile":
				cmd += f' profile={profile}'
			
			
			# Interface
			
			if interface != "interface":
				cmd += f' interfacetype={interface}'
				
			
			# Edge
			
			if edge != "edge":
				cmd += f' edge={edge}'
			
			
			# Enable 
			
			if enable != "enable":
				cmd += f' enable={enable}'
				
				
			# Run the Command
			
			state = subprocess.run(cmd, shell=True)
			
			if "returncode=1" in str(state):
				QMessageBox.warning(self, "Privillege Error", "You need to be Administrator")			
			else:
				QMessageBox.information(self, "Successfull", "Rule successfully added.")
				self.close()
				
				
		self.allow_block_public_ip_action_button.clicked.connect(allow_block_public_ip)
		self.allow_block_public_ip_action_button.show()
	
	
class Import_Export_Firewall_Rule(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Import or Export Firewall Rule")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setGeometry(500, 100, 400, 70)
		self.setFixedSize(400, 70)
	
	def import_export_firewall_rule_name(self):
		
		# Text box for name of firewall rule which want to import or export
		
		self.import_export_firewall_rule_name = QLineEdit(self)
		self.import_export_firewall_rule_name.setPlaceholderText("Enter the file name with .wfw extension")
		self.import_export_firewall_rule_name.setGeometry(5, 5, 350, 30)
		self.import_export_firewall_rule_name.show()
	
	def import_export_firewall_rule_get_file(self):
		
		# File Dialog for selecting file from system
		
		self.import_export_firewall_rule_get_file = QPushButton(self)
		self.import_export_firewall_rule_get_file.setGeometry(355, 5, 40, 30)
		self.import_export_firewall_rule_get_file.setText("File")
		
		def get_file():
			file, _ = QFileDialog(self).getSaveFileName()
			self.import_export_firewall_rule_name.setText(file)
			
		self.import_export_firewall_rule_get_file.clicked.connect(get_file)
		self.import_export_firewall_rule_get_file.show()
		
	def import_export_firewall_rule_action_button(self):
		
		
		# Import Button for Import/Export Firewall Rule
		
		self.import_export_firewall_rule_action_button_import = QPushButton(self)
		self.import_export_firewall_rule_action_button_import.setText("Import")
		self.import_export_firewall_rule_action_button_import.setGeometry(5, 35, 195, 30)
		
		def import_export_firewall_rule_import():
			cmd = "netsh advfirewall import"
			name = self.import_export_firewall_rule_name.text().replace("/", "\\")
			if ".wfw" not in name:
				name += ".wfw"
				
			if "\\" not in name:
				x = name
				name = f"Import-Export-Data/{x}"
			
			cmd += f' "{name}"'
			
			if name != "":
				decision = QMessageBox.question(self, "Overwriting Existing", "Importing firewall rule will overwrite existing rules", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
				if decision == QMessageBox.Yes:
					state = subprocess.run(cmd, shell=True)
					if "returncode=1" in str(state):
						QMessageBox.warning(self, "Privilege Error", "You need administrator privileges")
					else:
						QMessageBox.information(self, "Success...", "You have successfully exported firewall rule.")
				else:
					QMessageBox.warning(self, "Cancel the Importint...", "You have cancelled the importing of firewall rule")
			else:
				QMessageBox.warning(self, "Missing Input", "You must specify file name of .wfw extention for importing it...")
			
			
		self.import_export_firewall_rule_action_button_import.clicked.connect(import_export_firewall_rule_import)
		self.import_export_firewall_rule_action_button_import.show()
		
		
		# Export Button for Import/Export Firewall Rule
		
		self.import_export_firewall_rule_action_button_export = QPushButton(self)
		self.import_export_firewall_rule_action_button_export.setText("Export")
		self.import_export_firewall_rule_action_button_export.setGeometry(200, 35, 195, 30)
		
		def import_export_firewall_rule_export():
			cmd = "netsh advfirewall export"
			name = self.import_export_firewall_rule_name.text().replace("/", "\\")
			if ".wfw" not in name:
				name += ".wfw"
				
			if "\\" not in name:
				x = name
				name = f"Import-Export-Data/{x}"
			
			cmd += f' "{name}"'
			
			if name != "":
				decision = QMessageBox.question(self, "File Name", "You need to specify file name with .wfw to export it", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
				if decision == QMessageBox.Yes:
					state = subprocess.run(cmd, shell=True)
					if "returncode=1" in str(state):
						QMessageBox.warning(self, "Privilege Error", "You need administrator privileges")
					else:
						QMessageBox.information(self, "Success...", "You have successfully exported firewall rule.")
				else:
					QMessageBox.warning(self, "Cancel the Exporting...", "You have cancelled the Exporting of firewall rule")
			else:
				QMessageBox.warning(self, "Missing File Name", "You must specify file name of .wfw extention for importing it...")
	
		self.import_export_firewall_rule_action_button_export.clicked.connect(import_export_firewall_rule_export)
		self.import_export_firewall_rule_action_button_export.show()


class Modify_Exist_Rule(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Modify Existing Firewall Rule")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setGeometry(500, 100, 400, 400)
		self.setFixedSize(400, 400)

	def modify_exist_rule_name(self):
		
		# Text Box for entering firewall rule which is exists
		
		self.modify_exist_rule_name = QLineEdit(self)
		self.modify_exist_rule_name.setPlaceholderText("Enter the firewall rule name...")
		self.modify_exist_rule_name.setGeometry(5, 5, 390, 30)
		self.modify_exist_rule_name.show()
	
	def modify_exist_rule_rename(self):
		
		# Text box for entering group name of set of rules
		
		self.modify_exist_rule_rename = QLineEdit(self)
		self.modify_exist_rule_rename.setPlaceholderText("Enter the new name for this rule name...")
		self.modify_exist_rule_rename.setGeometry(5, 35, 390, 30)
		self.modify_exist_rule_rename.show()
		
	def modify_exist_rule_description(self):
		
		# Text area for entering Description here
		
		self.modify_exist_rule_description = QTextEdit(self)
		self.modify_exist_rule_description.setPlaceholderText("Enter the description here...")
		self.modify_exist_rule_description.setGeometry(5, 65, 390, 60)
		self.modify_exist_rule_description.show()
	
	def modify_exist_rule_program(self):
		
		# Text box for entering program file name or location 
		
		self.modify_exist_rule_program = QLineEdit(self)
		self.modify_exist_rule_program.setPlaceholderText("Enter the file name or with path...")
		self.modify_exist_rule_program.setGeometry(5, 125, 300, 30)
		self.modify_exist_rule_program.show()
		
		# Button for getting file from system
		
		self.modify_exist_rule_program_btn = QPushButton(self)
		self.modify_exist_rule_program_btn.setText("File")
		self.modify_exist_rule_program_btn.setGeometry(305, 125, 90, 30)
		
		def get_file():
			file, _ = QFileDialog(self).getOpenFileName()
			self.modify_exist_rule_program.setText(file)
		self.modify_exist_rule_program_btn.clicked.connect(get_file)
		self.modify_exist_rule_program_btn.show()
		
	def modify_exist_rule_local_ip(self):
		
		# Text box for entering local ip here
		
		self.modify_exist_rule_local_ip = QLineEdit(self)
		self.modify_exist_rule_local_ip.setPlaceholderText("L_IP : 255.255.255.255")
		self.modify_exist_rule_local_ip.setGeometry(5, 155, 140, 30)
		self.modify_exist_rule_local_ip.show()
	
	def modify_exist_rule_local_port(self):
		
		# Text box for entering local port number
		
		self.modify_exist_rule_local_port = QLineEdit(self)
		self.modify_exist_rule_local_port.setPlaceholderText("L_Port")
		self.modify_exist_rule_local_port.setGeometry(145, 155, 55, 30)
		self.modify_exist_rule_local_port.show()
	
	def modify_exist_rule_remote_ip(self):
		
		# Text box for entering remote ip address 
		
		self.modify_exist_rule_remote_ip = QLineEdit(self)
		self.modify_exist_rule_remote_ip.setPlaceholderText("R_IP : 255.255.255.255")
		self.modify_exist_rule_remote_ip.setGeometry(200, 155, 140, 30)
		self.modify_exist_rule_remote_ip.show()
		
	def modify_exist_rule_remote_port(self):
		
		# Text box for entering remote port number 
		
		self.modify_exist_rule_remote_port = QLineEdit(self)
		self.modify_exist_rule_remote_port.setPlaceholderText("R_Port")
		self.modify_exist_rule_remote_port.setGeometry(340, 155, 55, 30)
		self.modify_exist_rule_remote_port.show()
	
	def modify_exist_rule_direction(self):
		
		# Dropdown box for selecting direction like Inbound or Outbound
		
		direction = ["Direction", "Inbound", "Outbound"]
		
		self.modify_exist_rule_direction = QComboBox(self)
		self.modify_exist_rule_direction.setGeometry(5, 185, 195, 30)
		self.modify_exist_rule_direction.addItems(direction)
		self.modify_exist_rule_direction.setCurrentIndex(0)
		self.modify_exist_rule_direction.show()
		
	def modify_exist_rule_profile(self):
		
		# Dropdown box for selecting profile like public,private,domain,any
		
		profile = ["Profile", "Domain", "Private", "Public", "Any"]
		
		self.modify_exist_rule_profile = QComboBox(self)
		self.modify_exist_rule_profile.setGeometry(200, 185, 195, 30)
		self.modify_exist_rule_profile.addItems(profile)
		self.modify_exist_rule_profile.setCurrentIndex(0)
		self.modify_exist_rule_profile.show()
		
	def modify_exist_rule_service(self):
		
		# Dropdown box for selecting services according to need
		
		services = ["Service", "wuauserv","bits","Dhcp","Dnscache","EventLog","Schedule","WinDefend","Spooler","TermService", "LanmanWorkstation","LanmanServer","Browser","W32Time","IKEEXT","iphlpsvc","PolicyAgent", "RemoteRegistry","lmhosts","Netlogon","ProfSvc","RpcSs","RpcLocator","SamSs","SCardSvr", "Winmgmt","SSDPSRV","upnphost","TrkWks","Themes","WSearch","TrustedInstaller","Wecsvc", "WerSvc","WEPHOSTSVC","WdiServiceHost","WdNisSvc","msiserver","BFE","MpsSvc","WlanSvc", "ALG","AudioSrv","Audiosrv","Fax","FTP","FTPSVC","ftpsvc","MSMQ","Netman","NlaSvc","NcbService", "PlugPlay","Power","RasMan","RasAuto","RDPDR","TermService","UmRdpService","SessionEnv", "ShellHWDetection","SharedAccess","stisvc","SysMain","TapiSrv","TrkWks","UmRdpService", "W3SVC","WAS","wscsvc","wdiagsvc","WdNisSvc","WinHttpAutoProxySvc","WpnService","WpnUserService","AppHostSvc","Appinfo","AppMgmt","BthHFSrv","CertPropSvc","ClipSVC","DoSvc","edgeupdate","edgeupdatem","gpsvc","HvHost","InstallService","IntelAudioService","iphlpsvc","lfsvc","lmhosts","MapsBroker","MessagingService","MixedRealityOpenXRSvc","NgcSvc","NgcCtnrSvc","OneSyncSvc","PhoneSvc","PrintNotify","PushToInstall","QWAVE","RtkAudioUniversalService","SEMgrSvc","SessionEnv","StateRepository","StorSvc","svsvc","SystemEventsBroker","TimeBrokerSvc","UserManager","UsoSvc","VacSvc","VaultSvc","WaaSMedicSvc","Wcmsvc","WdBoot","WdFilter","WerSvc","wisvc","WMPNetworkSvc","workfolderssvc","WpcMonSvc","WPDBusEnum","wscsvc"]
		
		self.modify_exist_rule_service = QComboBox(self)
		self.modify_exist_rule_service.setGeometry(395, 185, 195, 30)
		self.modify_exist_rule_service.addItems(services)
		self.modify_exist_rule_service.setCurrentIndex(0)
		self.modify_exist_rule_service.show()
		
	def modify_exist_rule_protocol(self):
		
		# Dropdown box for selecting protocol according to need
		
		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		
		self.modify_exist_rule_protocol = QComboBox(self)
		self.modify_exist_rule_protocol.setGeometry(5, 215, 195, 30)
		self.modify_exist_rule_protocol.addItems(protocols)
		self.modify_exist_rule_protocol.setCurrentIndex(0)
		self.modify_exist_rule_protocol.show()
		
	def modify_exist_rule_action(self):
		
		# Dropdown box for selecting action like allow or block
		
		action = ["Action", "Allow", "Block"]
		
		self.modify_exist_rule_action = QComboBox(self)
		self.modify_exist_rule_action.setGeometry(200, 215, 195, 30)
		self.modify_exist_rule_action.addItems(action)
		self.modify_exist_rule_action.setCurrentIndex(0)
		self.modify_exist_rule_action.show()
		
	def modify_exist_rule_interface_type(self):
		
		# Dropdown box for selecting interface like wired,wireless,lan,ras
		
		interfaces = ["Interface", "Wireless", "LAN", "RAS", "Any"]
		
		self.modify_exist_rule_interface_type = QComboBox(self)
		self.modify_exist_rule_interface_type.setGeometry(5, 245, 195, 30)
		self.modify_exist_rule_interface_type.addItems(interfaces)
		self.modify_exist_rule_interface_type.setCurrentIndex(0)
		self.modify_exist_rule_interface_type.show()
	
	def modify_exist_rule_security(self):
		
		# Dropdown box for selecting security
		
		security = ["Security", "authenticate", "authenc", "authdynenc", "notrequired"]
		
		self.modify_exist_rule_security = QComboBox(self)
		self.modify_exist_rule_security.setGeometry(200, 245, 195, 30)
		self.modify_exist_rule_security.addItems(security)
		self.modify_exist_rule_security.setCurrentIndex(0)
		self.modify_exist_rule_security.show()
		
	def modify_exist_rule_enable(self):
		
		# Dropdown box for selecting enable is yes or no
		
		enable = ["Enable", "Yes", "No"]
		
		self.modify_exist_rule_enable = QComboBox(self)
		self.modify_exist_rule_enable.setGeometry(5, 275, 195, 30)
		self.modify_exist_rule_enable.addItems(enable)
		self.modify_exist_rule_enable.setCurrentIndex(0)
		self.modify_exist_rule_enable.show()
	
	def modify_exist_rule_edge(self):
		
		# Dropdown box for selecting edge
		
		edge = ["Edge", "Yes", "Deferapp", "Deferuser", "No"]
		
		self.modify_exist_rule_edge = QComboBox(self)
		self.modify_exist_rule_edge.setGeometry(200, 275, 195, 30)
		self.modify_exist_rule_edge.addItems(edge)
		self.modify_exist_rule_edge.setCurrentIndex(0)
		self.modify_exist_rule_edge.show()
	
	def modify_exist_rule_rmtcompgrp(self):
		
		# Text box for entering <SDDL String> for rmtcomputergrp
		
		self.modify_exist_rule_rmtcompgrp = QLineEdit(self)
		self.modify_exist_rule_rmtcompgrp.setPlaceholderText("rmtcomputergrp='O:<owner>G:<group>D:(A;;CC;;;<SID>'")
		self.modify_exist_rule_rmtcompgrp.setGeometry(5, 305, 390, 30)
		self.modify_exist_rule_rmtcompgrp.show()
		
	def modify_exist_rule_rmtusrgrp(self):
		
		# Text box for entering <SDDL String> 
		
		self.modify_exist_rule_rmtusrgrp = QLineEdit(self)
		self.modify_exist_rule_rmtusrgrp.setPlaceholderText("rmtusrgrp='O:<owner>G:<group>D:(A;;CC;;;<SID>)'")
		self.modify_exist_rule_rmtusrgrp.setGeometry(5, 335, 390, 30)
		self.modify_exist_rule_rmtusrgrp.show()
	
	def modify_exist_rule_action_button(self):

		# Button for performing action modify existing firewall rule
		
		self.modify_exist_rule_action_button = QPushButton(self)
		self.modify_exist_rule_action_button.setText("Action")
		self.modify_exist_rule_action_button.setGeometry(5, 365, 390, 30)
		
		def modify_exist_rule():
			cmd = "netsh advfirewall firewall set rule"
		
			name = self.modify_exist_rule_name.text()
			rename = self.modify_exist_rule_rename.text()
			description = self.modify_exist_rule_description.toPlainText()
			program = self.modify_exist_rule_program.text().replace("/", "\\")
			localip = self.modify_exist_rule_local_ip.text()
			localport = self.modify_exist_rule_local_port.text()
			remoteip = self.modify_exist_rule_remote_ip.text()
			remoteport = self.modify_exist_rule_remote_port.text()
			dirs = self.modify_exist_rule_direction.currentText().lower()
			direction = dirs[0:2] if dirs == "inbound" else dirs[0:3]
			profile = self.modify_exist_rule_profile.currentText().lower()
			service = self.modify_exist_rule_service.currentText().lower()
			protocol = self.modify_exist_rule_protocol.currentText().lower()
			action = self.modify_exist_rule_action.currentText().lower()
			interface = self.modify_exist_rule_interface_type.currentText().lower()
			security = self.modify_exist_rule_security.currentText().lower()
			enable = self.modify_exist_rule_enable.currentText().lower()
			edge = self.modify_exist_rule_edge.currentText().lower()
			rmtcompgrp = self.modify_exist_rule_rmtcompgrp.text()
			rmtusrgrp = self.modify_exist_rule_rmtusrgrp.text()
			
			
			# Name
			
			if name != "":
				cmd += f' name="{name}"'
			
			
			# Group
			
			if rename != "":
				cmd += f' new name="{rename}"'
			
			
			# Description
			
			if description != "":
				cmd += f' new description="{description}'
			
			
			# Program
			
			if program != "":
				cmd += f' new program="{program}"'
			
			
			# Input Filtering for Local IP Address
			
			if localip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in localip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' new localip={localip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Local IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
			
			
			# Input Filtering for Local Port 
			
			if localport != "":
				if localport.isdigit():
					if int(localport) >= 1 and int(localport) <= 65535:
						cmd += f' new localport={localport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			
			
			# Input Filtering for Remote IP address
			
			if remoteip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in remoteip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' new remoteip={remoteip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Remote IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
	
		
			# Input Filtering for Remote Port
			
			if remoteport != "":
				if remoteport.isdigit():
					if int(remoteport) >= 1 and int(remoteport) <= 65535:
						cmd += f' new remoteport={remoteport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			
			
			# Direction
			
			if direction != "dir":
				cmd += f' new dir={direction}'
			
			
			# Profile
			
			if profile != "profile":
				cmd += f' new profile={profile}'
				
				
			# Service	
			
			if service != "service":
				cmd += f' new service={service}'	
			
			
			# Protocol
			
			if protocol != "protocol":
				cmd += f' new protocol={protocol}'
				
				
			# Action
			
			if action != "action":
				cmd += f' new action={action}'


			# Interface
			
			if interface != "interface":
				cmd += f' new interfacetype={interface}'
				
				
			# Security
			
			if security != "security":
				cmd += f' new security={security}'
			
			# Enable
			
			if enable != "enable":
				cmd += f' new enable={enable}'
				
				
			# Edge
			
			if edge != "edge":
				cmd += f' new edge={edge}'
			
			
			# rmtcompgrp
			
			if rmtcompgrp != "":
				cmd += f' new rmtcompgrp="{rmtcompgrp}"'
				
				
			# rmtusrgrp
			
			if rmtusrgrp != "":
				cmd += f' new rmtusrgrp="{rmtusrgrp}"'
			
			
			# Run the Command
			
			state = subprocess.run(cmd, shell=True)
			
			if "returncode=1" in str(state):
				QMessageBox.warning(self, "Privillege Error", "You need to be Administrator")
				self.modify_exist_rule_rename.setText("")
				self.modify_exist_rule_description.setText("")
				self.modify_exist_rule_program.setText("")
				self.modify_exist_rule_local_ip.setText("")
				self.modify_exist_rule_local_port.setText("")
				self.modify_exist_rule_remote_ip.setText("")
				self.modify_exist_rule_remote_port.setText("")
				self.modify_exist_rule_direction.setCurrentIndex(0)
				self.modify_exist_rule_profile.setCurrentIndex(0)
				self.modify_exist_rule_service.setCurrentIndex(0)
				self.modify_exist_rule_protocol.setCurrentIndex(0)
				self.modify_exist_rule_action.setCurrentIndex(0)
				self.modify_exist_rule_interface_type.setCurrentIndex(0)
				self.modify_exist_rule_security.setCurrentIndex(0)
				self.modify_exist_rule_enable.setCurrentIndex(0)
				self.modify_exist_rule_edge.setCurrentIndex(0)
				self.modify_exist_rule_rmtcompgrp.setText("")
				self.modify_exist_rule_rmtusrgrp.setText("")			
			else:
				QMessageBox.information(self, "Successfull", "Rule successfully added.")
				self.modify_exist_rule_rename.setText("")
				self.modify_exist_rule_description.setText("")
				self.modify_exist_rule_program.setText("")
				self.modify_exist_rule_local_ip.setText("")
				self.modify_exist_rule_local_port.setText("")
				self.modify_exist_rule_remote_ip.setText("")
				self.modify_exist_rule_remote_port.setText("")
				self.modify_exist_rule_direction.setCurrentIndex(0)
				self.modify_exist_rule_profile.setCurrentIndex(0)
				self.modify_exist_rule_service.setCurrentIndex(0)
				self.modify_exist_rule_protocol.setCurrentIndex(0)
				self.modify_exist_rule_action.setCurrentIndex(0)
				self.modify_exist_rule_interface_type.setCurrentIndex(0)
				self.modify_exist_rule_security.setCurrentIndex(0)
				self.modify_exist_rule_enable.setCurrentIndex(0)
				self.modify_exist_rule_edge.setCurrentIndex(0)
				self.modify_exist_rule_rmtcompgrp.setText("")
				self.modify_exist_rule_rmtusrgrp.setText("")
				
			
		self.modify_exist_rule_action_button.clicked.connect(modify_exist_rule)
		self.modify_exist_rule_action_button.show()		
		

class Delete_Firewall_Rule(QWidget):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("Delete Firewall Rule")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setGeometry(500, 100, 400, 220)
		self.setFixedSize(400, 220)
	
	def delete_firewall_rule_name(self):
		
		# Text Box for entering firewall rule name
		
		self.delete_firewall_rule_name = QLineEdit(self)
		self.delete_firewall_rule_name.setPlaceholderText("Enter the firewall rule name...")
		self.delete_firewall_rule_name.setGeometry(5, 5, 390, 30)
		self.delete_firewall_rule_name.show()
	
	def delete_firewall_rule_group(self):
		
		# Text Box for entering firewall rule name
		
		self.delete_firewall_rule_group = QLineEdit(self)
		self.delete_firewall_rule_group.setPlaceholderText("Enter the firewall rule group...")
		self.delete_firewall_rule_group.setGeometry(5, 35, 390, 30)
		self.delete_firewall_rule_group.show()
	
	def delete_firewall_rule_program(self):
		
		# Text box for entering program name with path
		
		self.delete_firewall_rule_program = QLineEdit(self)
		self.delete_firewall_rule_program.setPlaceholderText("Enter the file name...")
		self.delete_firewall_rule_program.setGeometry(5, 65, 300, 30)
		self.delete_firewall_rule_program.show()
		
		# Button for getting file from system
		
		self.delete_firewall_rule_get_file = QPushButton(self)
		self.delete_firewall_rule_get_file.setText("File")
		self.delete_firewall_rule_get_file.setGeometry(305, 65, 90, 30)
		
		def get_file():
			file, _ = QFileDialog(self).getOpenFileName()
			self.delete_firewall_rule_program.setText(file)
			
		self.delete_firewall_rule_get_file.clicked.connect(get_file)
		self.delete_firewall_rule_get_file.show() 
		
	def delete_firewall_rule_local_ip(self):
		
		# Text box for entering local ip address
		
		self.delete_firewall_rule_local_ip = QLineEdit(self)
		self.delete_firewall_rule_local_ip.setPlaceholderText("L_IP:255.255.255.255")
		self.delete_firewall_rule_local_ip.setGeometry(5, 95, 140, 30)
		self.delete_firewall_rule_local_ip.show()
		
	def delete_firewall_rule_local_port(self):
		
		# Text box for entering local port number
		
		self.delete_firewall_rule_local_port = QLineEdit(self)
		self.delete_firewall_rule_local_port.setPlaceholderText("L_Port")
		self.delete_firewall_rule_local_port.setGeometry(145, 95, 55, 30)
		self.delete_firewall_rule_local_port.show()
		
	def delete_firewall_rule_remote_ip(self):
		
		# Text box for entering remote ip address
		
		self.delete_firewall_rule_remote_ip = QLineEdit(self)
		self.delete_firewall_rule_remote_ip.setPlaceholderText("R_IP:255.255.255.255")
		self.delete_firewall_rule_remote_ip.setGeometry(200, 95, 140, 30)
		self.delete_firewall_rule_remote_ip.show()
		
	def delete_firewall_rule_remote_port(self):
		
		# Text box for entering remote port number
		
		self.delete_firewall_rule_remote_port = QLineEdit(self)
		self.delete_firewall_rule_remote_port.setPlaceholderText("R_Port")
		self.delete_firewall_rule_remote_port.setGeometry(340, 95, 55, 30)
		self.delete_firewall_rule_remote_port.show()
		
	def delete_firewall_rule_direction(self):
		
		# Dropdown box for selecting direction like Inbound or Outbound
		
		direction = ["Direction", "Inbound", "Outbound"]
		
		self.delete_firewall_rule_direction = QComboBox(self)
		self.delete_firewall_rule_direction.setGeometry(5, 125, 195, 30)
		self.delete_firewall_rule_direction.addItems(direction)
		self.delete_firewall_rule_direction.setCurrentIndex(0)
		self.delete_firewall_rule_direction.show()
		
	def delete_firewall_rule_profile(self):
		
		# Dropdown box for selecting profile like domain,private,public,any
		
		profile = ["Profile", "Domain", "Private", "Public", "Any"]
		
		self.delete_firewall_rule_profile = QComboBox(self)
		self.delete_firewall_rule_profile.setGeometry(200, 125, 195, 30)
		self.delete_firewall_rule_profile.addItems(profile)
		self.delete_firewall_rule_profile.setCurrentIndex(0)
		self.delete_firewall_rule_profile.show()
	
	def delete_firewall_rule_service(self):
		
		# Dropdown box for selecting service according to need
		
		services = ["Service", "wuauserv","bits","Dhcp","Dnscache","EventLog","Schedule","WinDefend","Spooler","TermService", "LanmanWorkstation","LanmanServer","Browser","W32Time","IKEEXT","iphlpsvc","PolicyAgent", "RemoteRegistry","lmhosts","Netlogon","ProfSvc","RpcSs","RpcLocator","SamSs","SCardSvr", "Winmgmt","SSDPSRV","upnphost","TrkWks","Themes","WSearch","TrustedInstaller","Wecsvc", "WerSvc","WEPHOSTSVC","WdiServiceHost","WdNisSvc","msiserver","BFE","MpsSvc","WlanSvc", "ALG","AudioSrv","Audiosrv","Fax","FTP","FTPSVC","ftpsvc","MSMQ","Netman","NlaSvc","NcbService", "PlugPlay","Power","RasMan","RasAuto","RDPDR","TermService","UmRdpService","SessionEnv", "ShellHWDetection","SharedAccess","stisvc","SysMain","TapiSrv","TrkWks","UmRdpService", "W3SVC","WAS","wscsvc","wdiagsvc","WdNisSvc","WinHttpAutoProxySvc","WpnService","WpnUserService","AppHostSvc","Appinfo","AppMgmt","BthHFSrv","CertPropSvc","ClipSVC","DoSvc","edgeupdate","edgeupdatem","gpsvc","HvHost","InstallService","IntelAudioService","iphlpsvc","lfsvc","lmhosts","MapsBroker","MessagingService","MixedRealityOpenXRSvc","NgcSvc","NgcCtnrSvc","OneSyncSvc","PhoneSvc","PrintNotify","PushToInstall","QWAVE","RtkAudioUniversalService","SEMgrSvc","SessionEnv","StateRepository","StorSvc","svsvc","SystemEventsBroker","TimeBrokerSvc","UserManager","UsoSvc","VacSvc","VaultSvc","WaaSMedicSvc","Wcmsvc","WdBoot","WdFilter","WerSvc","wisvc","WMPNetworkSvc","workfolderssvc","WpcMonSvc","WPDBusEnum","wscsvc"]
		
		self.delete_firewall_rule_service = QComboBox(self)
		self.delete_firewall_rule_service.setGeometry(5, 155, 195, 30)
		self.delete_firewall_rule_service.addItems(services)
		self.delete_firewall_rule_service.setCurrentIndex(0)
		self.delete_firewall_rule_service.show()
	
	def delete_firewall_rule_protocol(self):
		
		# Dropdown box for selecting protocol according to need
		
		protocols = ["Protocol", "TCP", "UDP", "ICMPv4", "ICMPv6", "HOPOPT", "IGMP", "IPv6", "IPv6-Route", "IPv6-Frag", "GRE", "IPv6-NoNxt", "IPv6-Opts", "VRRP", "PGM", "L2TP", "Any"]
		
		self.delete_firewall_rule_protocol = QComboBox(self)
		self.delete_firewall_rule_protocol.setGeometry(200, 155, 195, 30)
		self.delete_firewall_rule_protocol.addItems(protocols)
		self.delete_firewall_rule_protocol.setCurrentIndex(0)
		self.delete_firewall_rule_protocol.show()
	
	def delete_firewall_rule_action_button(self):
		
		# Button for performing action to delete firewall rule
		
		self.delete_firewall_rule_action_button = QPushButton(self)
		self.delete_firewall_rule_action_button.setText("Action")
		self.delete_firewall_rule_action_button.setGeometry(5, 185, 390, 30)
		
		def delete_firewall_rule():
			
			cmd = "netsh advfirewall firewall delete rule"
			
			name = self.delete_firewall_rule_name.text()
			group = self.delete_firewall_rule_group.text()
			program = self.delete_firewall_rule_program.text()
			localip = self.delete_firewall_rule_local_ip.text()
			localport = self.delete_firewall_rule_local_port.text()
			remoteip = self.delete_firewall_rule_remote_ip.text()
			remoteport = self.delete_firewall_rule_remote_port.text()
			dirs = self.delete_firewall_rule_direction.currentText().lower()
			direction = dirs[0:2] if dirs == "inbound" else dirs[0:3]
			profile = self.delete_firewall_rule_profile.currentText().lower()
			service = self.delete_firewall_rule_service.currentText().lower()
			protocol = self.delete_firewall_rule_protocol.currentText().lower()
			
			# Check Mandatory Fields
			
			if name == "":
				QMessageBox.warning(self, "Missing Input", "Mandatory fields for delete rule is Rule Name")
			
			
			# Name
			
			if name != "":
				cmd += f' name="{name}"'
			
			
			# Group
			
			if group != "":
				cmd += f' group="{name}"'
			
			
			# Program
			
			if program != "":
				cmd += f' program="{program}"'
		
			
			# Input Filtering for Local IP Address
			
			if localip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in localip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' localip={localip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Local IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
			
			
			# Input Filtering for Local Port 
			
			if localport != "":
				if localport.isdigit():
					if int(localport) >= 1 and int(localport) <= 65535:
						cmd += f' localport={localport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")

	
			# Input Filtering for Remote IP address
			
			if remoteip != "":
				legal_chars = ""
				legal_chars += string.digits
				legal_chars += ".,-/"
				yes = True
				for i in remoteip:
					if i in legal_chars:
						yes = True
					else:
						yes = False
						break
				
				if yes:
					cmd += f' remoteip={remoteip}'
				else:
					QMessageBox.warning(self, "Wrong Character", "Remote IP Address contain Wrong Characters")
					QMessageBox.information(self, "Correct IP Address", "eg. 192.168.10.5 or 192.168.10.5,192.168.10.10,etc or 192.168.10.5-192.168.10.20 or 192.168.10.0/24")
			
		
			# Input Filtering for Remote Port
			
			if remoteport != "":
				if remoteport.isdigit():
					if int(remoteport) >= 1 and int(remoteport) <= 65535:
						cmd += f' remoteport={remoteport}'
					else:
						QMessageBox.warning(self, "Port Number Error", "You have to enter Port number between 1 and 65535...")
				else:
					QMessageBox.warning(self, "Wrong Input", "Don't use character in Local Port Number...")
			
			
			# Direction
			
			if direction != "dir":
				cmd += f' dir={direction}'
			
			
			# Profile
			
			if profile != "profile":
				cmd += f' profile={profile}'
				
				
			# Service
			
			if service != "service":
				cmd += f' service={service}'
				
				
			# Protocol
			
			if protocol != "protocol":
				cmd += f' protocol={protocol}'
			
			
			# Run the Command
			
			state = subprocess.run(cmd, shell=True)
			print(state)
			print(cmd)
			if "returncode=1" in str(state):
				QMessageBox.warning(self, "Privillege Error", "You need to be Administrator")			
			else:
				QMessageBox.information(self, "Successfull", "Rule successfully deleted.")
				self.close()
			
			
		self.delete_firewall_rule_action_button.clicked.connect(delete_firewall_rule)
		self.delete_firewall_rule_action_button.show()
		
		
class Firewall(QWidget):
	def __init__(self):
		super().__init__()
		self.setGeometry(1, 30, 450, 547)
		self.setWindowTitle("Firewall Manager")
		self.setWindowIcon(QIcon("Images/firewall.ico"))
		self.setFixedSize(450, 547)
		
	
	def all_profiles(self):
		
		###### Domain Profiles ######
		
		# Domain profiles state
		domain_firewall_state = subprocess.run("netsh advfirewall show domainprofile | findstr ON", shell=True)
		
		# Domain profile label
		self.domain_profiles_label = QLabel(self)
		self.domain_profiles_label.setText("Domain Profile")
		self.domain_profiles_label.setStyleSheet("font-size:11px;")
		self.domain_profiles_label.setGeometry(10, 1, 100, 30)
		self.domain_profiles_label.show()
		
		# Domain Profile Button
		self.domain_profiles_button = QPushButton(self)
		self.domain_profiles_button.setGeometry(103, 1, 100, 30)
		self.domain_profiles_button.show()
		
		# Set Button text if Domain Profile Firewall ON or OFF
		if "returncode=0" in str(domain_firewall_state):
			self.domain_profiles_button.setText("ON")
			self.domain_profiles_button.setStyleSheet("color:green;")
		else:
			self.domain_profiles_button.setText("OFF")
			self.domain_profiles_button.setStyleSheet("color:red;")
		
		self.domain_profiles_button.setCheckable(True)
		
		def change_domain(checked):
			if checked:
				state = subprocess.run("netsh advfirewall set domainprofile state off", shell=True)
				if "returncode=1" in str(state):
					msg = QMessageBox.warning(self, "Error", "This action requires administrator permission")
					if msg:
						self.domain_profiles_button.setCheckable(False)
				else:
					self.domain_profiles_button.setText("OFF")
					self.domain_profiles_button.setStyleSheet("color:red;")
			else:
				state = subprocess.run("netsh advfirewall set domainprofile state on", shell=True)
				if "returncode=1" in str(state):
					QMessageBox.warning(self, "Warning", "This action requires administrator permission")
				else:	
					self.domain_profiles_button.setText("ON")
					self.domain_profiles_button.setStyleSheet("color:green;")
			self.domain_profiles_button.setCheckable(True)
				
		self.domain_profiles_button.toggled.connect(change_domain)

		###### Private Profiles ######
		
		# Private Profiles State
		private_firewall_state = subprocess.run("netsh advfirewall show privateprofile | findstr ON", shell=True)
		
		# Private Profile Label
		self.private_profiles_label = QLabel(self)
		self.private_profiles_label.setText("Private Profile")
		self.private_profiles_label.setStyleSheet("font-size:11px;")
		self.private_profiles_label.setGeometry(10, 30, 100, 30)
		self.private_profiles_label.show()
		
		# Private Profile Button
		self.private_profiles_button = QPushButton(self)
		self.private_profiles_button.setGeometry(103, 30, 100, 30) 
		self.private_profiles_button.show()
		
		# Set Button text if Private Profile Firewall ON or OFF
		if "returncode=0" in str(private_firewall_state):
			self.private_profiles_button.setText("ON")
			self.private_profiles_button.setStyleSheet("color:green;")
		else:
			self.private_profiles_button.setText("OFF")
			self.private_profiles_button.setStyleSheet("color:red;")
		
		self.private_profiles_button.setCheckable(True)
		
		def change_private(checked):
			if checked:
				state = subprocess.run("netsh advfirewall set privateprofile state off", shell=True)
				if "returncode=1" in str(state):
					msg = QMessageBox.warning(self, "Warning", "This action requires administrator permission")
					if msg:
						self.private_profiles_button.setCheckable(False)
				else:
					self.private_profiles_button.setText("OFF")
					self.private_profiles_button.setStyleSheet("color:red;")
			else:
				state = subprocess.run("netsh advfirewall set privateprofile state on", shell=True)
				if "returncode=1" in str(state):
					QMessageBox.warning(self, "Warning", "This action requires administrator permission")
				else:
					self.private_profiles_button.setText("ON")
					self.private_profiles_button.setStyleSheet("color:green;")
					
			self.private_profiles_button.setCheckable(True)
		
		self.private_profiles_button.toggled.connect(change_private)
		
		
		###### Public Profiles ######
		public_firewall_state = subprocess.run("netsh advfirewall show publicprofile | findstr ON", shell=True)
		
		# Public Profile Label
		self.public_profiles_label = QLabel(self)
		self.public_profiles_label.setText("Public Profile")
		self.public_profiles_label.setStyleSheet("font-size:11px;")
		self.public_profiles_label.setGeometry(10, 60, 100, 30)
		self.public_profiles_label.show()
		
		# Public Profile Button
		self.public_profiles_button = QPushButton(self)
		self.public_profiles_button.setGeometry(103, 60, 100, 30)
		self.public_profiles_button.show()
		
		# Set Button text if Public Profile Firewall ON or OFF
		if "returncode=0" in str(public_firewall_state):
			self.public_profiles_button.setText("ON")
			self.public_profiles_button.setStyleSheet("color:green;")
		else:
			self.public_profiles_button.setText("OFF")
			self.public_profiles_button.setStyleSheet("color:red;")
		
		self.public_profiles_button.setCheckable(True)
		
		def change_public(checked):
			if checked:
				state = subprocess.run("netsh advfirewall set publicprofile state off", shell=True)
				if "returncode=1" in str(state):
					msg = QMessageBox.warning(self, "Warning", "This action requires administrator permission")
					if msg:
						self.public_profiles_button.setCheckable(False)
				else:
					self.public_profiles_button.setText("OFF")
					self.public_profiles_button.setStyleSheet("color:red;")
			else:
				state = subprocess.run("netsh advfirewall set publicprofile state on", shell=True)
				if "returncode=1" in str(state):
					QMessageBox.warning(self, "Warning", "This action requires administrator permission")
				else:
					self.public_profiles_button.setText("ON")
					self.public_profiles_button.setStyleSheet("color:green;")
		
			self.public_profiles_button.setCheckable(True)
		self.public_profiles_button.toggled.connect(change_public)


		###### All Profiles ######
		
		# All Profile State
		
		all_firewall_state = subprocess.run("netsh advfirewall show allprofiles | findstr ON", shell=True)
		
		# All Profile Label
		
		self.all_profiles_label = QLabel(self)
		self.all_profiles_label.setText("All Profile")
		self.all_profiles_label.setStyleSheet("font-size:11px;")
		self.all_profiles_label.setGeometry(10, 90, 100, 30)
		self.all_profiles_label.show()
		
		# All Profile Button
		
		self.all_profiles_button = QPushButton(self)
		self.all_profiles_button.setText("ON")
		self.all_profiles_button.setGeometry(103, 90, 100, 30)
		self.all_profiles_button.show()
		
		# Set Button text if all profile firewall ON or OFF
		if "ON" in str(all_firewall_state):
			self.all_profiles_button.setText("ON")
			self.all_profiles_button.setStyleSheet("color:green;")
		else:
			self.all_profiles_button.setCheckable(True)
			self.all_profiles_button.setStyleSheet("color:red;")
		
		self.all_profiles_button.setCheckable(True)
		
		def change_all(checked):
			if checked:
				state = subprocess.run("netsh advfirewall set allprofiles state off", shell=True)
				if "returncode=1" in str(state):
					msg = QMessageBox.warning(self, "Warning", "This action requires administrator permission")
					if msg:
						self.all_profiles_button.setCheckable(False)
				else:
					self.domain_profiles_button.setText("OFF")
					self.domain_profiles_button.setStyleSheet("color:red;")
					self.private_profiles_button.setText("OFF")
					self.private_profiles_button.setStyleSheet("color:red;")
					self.public_profiles_button.setText("OFF")
					self.public_profiles_button.setStyleSheet("color:red;")
					self.all_profiles_button.setText("OFF")
					self.all_profiles_button.setStyleSheet("color:red;")
			else:
				state = subprocess.run("netsh advfirewall set allprofiles state on", shell=True)
				if "returncode=1" in str(state):
					QMessageBox.warning(self, "Warning", "This action requires administrator permission")
				else:
					self.domain_profiles_button.setText("ON")
					self.domain_profiles_button.setStyleSheet("color:green;")		
					self.private_profiles_button.setText("ON")
					self.private_profiles_button.setStyleSheet("color:green;")
					self.public_profiles_button.setText("ON")
					self.public_profiles_button.setStyleSheet("color:green;")
					self.all_profiles_button.setText("ON")
					self.all_profiles_button.setStyleSheet("color:green;")
			
			self.all_profiles_button.setCheckable(True)
		
		self.all_profiles_button.toggled.connect(change_all)

	# All Inbound Traffic will be blocked here
	
	def all_in_block(self):
		
		# Label for All Inbound Traffic Block
		
		self.All_in_block_label = QLabel(self)
		self.All_in_block_label.setText("ALL In Block")
		self.All_in_block_label.setStyleSheet("font-size:11px;")
		self.All_in_block_label.setGeometry(10, 120, 100, 30)
		self.All_in_block_label.show()
		
		# Button for All Inbound Traffic Block
		
		self.All_in_block_button = QPushButton(self)
		self.All_in_block_button.setText("Block")
		self.All_in_block_button.setGeometry(103, 120, 100, 30)
		self.All_in_block_button.setStyleSheet("color:red;font-weight:bolder;")
		
		# Button clicked Function
		
		def block_all_inbound(checked):
			if checked:
				if self.All_out_block_button.isChecked():
					state1 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound", shell=True)
					
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.All_in_block_button.setCheckable(False)
				else:
					self.All_in_block_button.setText("Blocked")
					self.All_in_block_button.setStyleSheet("color:green;")
			else:
				if self.All_out_block_button.isChecked():
					state2 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound", shell=True)
				else:
					state2 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound", shell=True)
					
				if "returncode=1" in str(state2):
					QMessageBox.warning(self, "Warning", "Need to bo Administrator")
				else:
					self.All_in_block_button.setText("Block")
					self.All_in_block_button.setStyleSheet("color:red;")
					
		self.All_in_block_button.setCheckable(True)
		self.All_in_block_button.clicked.connect(block_all_inbound)
		self.All_in_block_button.show()
	
	# All Outbound Traffic will be blocked here
	
	def all_out_block(self):
		
		# Label for All Outbound Traffic Block
		
		self.All_out_block_label = QLabel(self)
		self.All_out_block_label.setText("All Out Block")
		self.All_out_block_label.setStyleSheet("font-size:11px;")
		self.All_out_block_label.setGeometry(10, 150, 100, 30)
		self.All_out_block_label.show()
		
		# Button for All Outbound Traffic Block
		
		self.All_out_block_button = QPushButton(self)
		self.All_out_block_button.setText("Block")
		self.All_out_block_button.setGeometry(103, 150, 100, 30)
		self.All_out_block_button.setStyleSheet("color:red;")
		self.All_out_block_button.setCheckable(True)
		
		# Button clicked Function for self.All_out_block_button
		
		def block_all_outbound(checked):
			if checked: # this checks if the self.All_out_block_button is clicked
				if self.All_in_block_button.isChecked(): # checks if the self.All_in_block_button if yes then run if block else run else block
					state1 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound", shell=True)
					
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.All_out_block_button.setCheckable(False)
				else:
					self.All_out_block_button.setText("Blocked")
					self.All_out_block_button.setStyleSheet("color:green;")
			else:
				if self.All_in_block_button.isChecked(): # checks if the self.All_in_block_button if yes then run if block else run else block
					state2 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound", shell=True)
				else:
					state2 = subprocess.run("netsh advfirewall set allprofiles firewallpolicy blockinboundalways,allowoutbound", shell=True)
					
				self.All_out_block_button.setText("Block")
				self.All_out_block_button.setStyleSheet("color:red;")
			self.All_out_block_button.setCheckable(True)
		self.All_out_block_button.clicked.connect(block_all_outbound)
		self.All_out_block_button.show()
		
	def domain_block(self):
		
		# Domain In Block
		
		self.domain_in_block_label = QLabel(self)
		self.domain_in_block_label.setText("Domain In Block")
		self.domain_in_block_label.setStyleSheet("font-size:11px;")
		self.domain_in_block_label.setGeometry(10, 180, 100, 30)
		self.domain_in_block_label.show()
		
		self.domain_in_block_button = QPushButton(self)
		self.domain_in_block_button.setText("Block")
		self.domain_in_block_button.setStyleSheet("color:red;")
		self.domain_in_block_button.setGeometry(103, 180, 100, 30)
		self.domain_in_block_button.setCheckable(True)
		
		def block_domain_in(checked):
			if checked:
				if self.domain_out_block_button.isChecked(): # checks if the self.domain_out_block_button is checked or not
					state1 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinboundalways,allowoutbound", shell=True)
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.domain_in_block_button.setCheckable(False)
				else:
					self.domain_in_block_button.setText("Blocked")
					self.domain_in_block_button.setStyleSheet("color:green;")
			else:
				if self.domain_out_block_button.isChecked(): # checks if the self.domain_out_block_button is checked or not
					state2 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinbound,blockoutbound", shell=True)
				else:
					state2 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound", shell=True)
				self.domain_in_block_button.setText("Block")
				self.domain_in_block_button.setStyleSheet("color:red;")
				
			self.domain_in_block_button.setCheckable(True)
			
		self.domain_in_block_button.clicked.connect(block_domain_in)
		
		self.domain_in_block_button.show()
		
		##### Domain Out Block #####
		
		# Domain out block label
		
		self.domain_out_block_label = QLabel(self)
		self.domain_out_block_label.setText("Domain Out Block")
		self.domain_out_block_label.setStyleSheet("font-size:11px;")
		self.domain_out_block_label.setGeometry(10, 210, 100, 30)
		self.domain_out_block_label.show()
		
		# Domain out block button
		
		self.domain_out_block_button = QPushButton(self)
		self.domain_out_block_button.setText("Block")
		self.domain_out_block_button.setStyleSheet("color:red;")
		self.domain_out_block_button.setGeometry(103, 210, 100, 30)
		self.domain_out_block_button.setCheckable(True)
		
		# self.domain_out_block_button on click event as follows 
		
		def block_domain_out(checked):
			if checked:
				if self.domain_in_block_button.isChecked():# checks if the self.domain_in_block_button is checked or not
					state1 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinbound,blockoutbound", shell=True)
					
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.domain_out_block_button.setCheckable(False)
				else:
					self.domain_out_block_button.setText("Blocked")
					self.domain_out_block_button.setStyleSheet("color:green;")
			else:
				if self.domain_in_block_button.isChecked():# checks if the self.domain_in_block_button is checked or not
					state2 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinboundalways,allowoutbound", shell=True)
				else:
					state2 = subprocess.run("netsh advfirewall set domainprofile firewallpolicy blockinbound,allowoutbound", shell=True)
				self.domain_out_block_button.setText("Block")
				self.domain_out_block_button.setStyleSheet("color:red;")
			
			self.domain_out_block_button.setCheckable(True)
			
		self.domain_out_block_button.clicked.connect(block_domain_out)
		self.domain_out_block_button.show()
		
		
	def private_block(self):
		
		# Private In Block
		
		self.private_in_block_label = QLabel(self)
		self.private_in_block_label.setText("Private In Block")
		self.private_in_block_label.setStyleSheet("font-size:11px;")
		self.private_in_block_label.setGeometry(10, 240, 100, 30)
		self.private_in_block_label.show()
		
		self.private_in_block_button = QPushButton(self)
		self.private_in_block_button.setText("Block")
		self.private_in_block_button.setStyleSheet("color:red;")
		self.private_in_block_button.setGeometry(103, 240, 100, 30)
		self.private_in_block_button.setCheckable(True)
		
		def block_private_in(checked):
			if checked:
				if self.private_out_block_button.isChecked():
					state1 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinboundalways,allowoutbound", shell=True)
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.private_in_block_button.setCheckable(False)
				else:
					self.private_in_block_button.setText("Blocked")
					self.private_in_block_button.setStyleSheet("color:green;")
			else:
				if self.private_out_block_button.isChecked():
					state1 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinbound,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound", shell=True)
				self.private_in_block_button.setText("Block")
				self.private_in_block_button.setStyleSheet("color:red;")
			
			self.private_in_block_button.setCheckable(True)
			
		self.private_in_block_button.clicked.connect(block_private_in)
		self.private_in_block_button.show()
		
		# Private Out Block
		
		self.private_out_block_label = QLabel(self)
		self.private_out_block_label.setText("Private Out Block")
		self.private_out_block_label.setStyleSheet("font-size:11px;")
		self.private_out_block_label.setGeometry(10, 270, 100, 30)
		self.private_out_block_label.show()
		
		self.private_out_block_button = QPushButton(self)
		self.private_out_block_button.setText("Block")
		self.private_out_block_button.setStyleSheet("color:red;")
		self.private_out_block_button.setGeometry(103, 270, 100, 30)
		self.private_out_block_button.setCheckable(True)
		
		def block_private_out(checked):
			if checked:
				if self.private_in_block_button.isChecked():
					state1 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinbound,blockoutbound", shell=True)
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.private_out_block_button.setCheckable(False)
				else:
					self.private_out_block_button.setText("Blocked")
					self.private_out_block_button.setStyleSheet("color:green;")
			else:
				if self.private_in_block_button.isChecked():
					state2 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinboundalways,allowoutbound", shell=True)
				else:
					state2 = subprocess.run("netsh advfirewall set privateprofile firewallpolicy blockinbound,allowoutbound", shell=True)
				self.private_out_block_button.setText("Block")
				self.private_out_block_button.setStyleSheet("color:red;")
				
			self.private_out_block_button.setCheckable(True)
				
		self.private_out_block_button.clicked.connect(block_private_out)
		self.private_out_block_button.show()
		
	def public_block(self):
		
		# Public In Block
		
		self.public_in_block_label = QLabel(self)
		self.public_in_block_label.setText("Public In Block")
		self.public_in_block_label.setStyleSheet("font-size:11px;")
		self.public_in_block_label.setGeometry(10, 300, 100, 30)
		self.public_in_block_label.show()
		
		self.public_in_block_button = QPushButton(self)
		self.public_in_block_button.setText("Block")
		self.public_in_block_button.setStyleSheet("color:red;")
		self.public_in_block_button.setGeometry(103, 300, 100, 30)
		self.public_in_block_button.setCheckable(True)
		
		def block_public_in(checked):
			if checked:
				if self.public_out_block_button.isChecked():
					state1 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound", shell=True)
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.public_in_block_button.setCheckable(False)
				else:
					self.public_in_block_button.setText("Blocked")
					self.public_in_block_button.setStyleSheet("color:green;")
			else:
				if self.public_out_block_button.isChecked():
					state2 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinbound,blockoutbound", shell=True)
				else:
					state2 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound", shell=True)
				self.public_in_block_button.setText("Block")
				self.public_in_block_button.setStyleSheet("color:red;")
			
			self.public_in_block_button.setCheckable(True)
			
		self.public_in_block_button.clicked.connect(block_public_in)
		self.public_in_block_button.show()
		
		# Public Out Block
		
		self.public_out_block_label = QLabel(self)
		self.public_out_block_label.setText("Public Out Block")
		self.public_out_block_label.setStyleSheet("font-size:11px;")
		self.public_out_block_label.setGeometry(10, 330, 100, 30)
		self.public_out_block_label.show()
		
		self.public_out_block_button = QPushButton(self)
		self.public_out_block_button.setText("Block")
		self.public_out_block_button.setStyleSheet("color:red;")
		self.public_out_block_button.setGeometry(103, 330, 100, 30)
		self.public_out_block_button.setCheckable(True)
		
		def block_public_out(checked):
			if checked:
				if self.public_in_block_button.isChecked():
					state1 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinboundalways,blockoutbound", shell=True)
				else:
					state1 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinbound,blockoutbound", shell=True)
				if "returncode=1" in str(state1):
					msg = QMessageBox.warning(self, "Warning", "Need to be Administrator")
					if msg:
						self.public_out_block_button.setCheckable(False)
				else:
					self.public_out_block_button.setText("Blocked")
					self.public_out_block_button.setStyleSheet("color:green;")
			else:
				if self.public_in_block_button.isChecked():
					state2 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinboundalways,allowoutbound", shell=True)
				else:
					state2 = subprocess.run("netsh advfirewall set publicprofile firewallpolicy blockinbound,allowoutbound", shell=True)
				self.public_out_block_button.setText("Block")
				self.public_out_block_button.setStyleSheet("color:red;")
				
			self.public_out_block_button.setCheckable(True)
				
		self.public_out_block_button.clicked.connect(block_public_out)
		self.public_out_block_button.show()
	
	def reset_firewall(self):
		self.reset_firewall_btn = QPushButton(self)
		self.reset_firewall_btn.setText("Reset\nFirewall")
		self.reset_firewall_btn.setStyleSheet("color:grey;font-size:25px;font-family:'Times New Roman';")
		self.reset_firewall_btn.setGeometry(5, 360, 196, 120)

		def reset_firewall():
			my_pass = "reset@1234#1234"
			get_pass, _ = QInputDialog.getText(self, "Reset", "Enter the Password")
			if get_pass == my_pass:
				state = subprocess.run("netsh advfirewall reset")
				if "returncode=1" in str(state):
					QMessageBox.warning(self, "Warning", "Need to be Administrator")
				else:
					if QMessageBox.question(self, "Confirmation", "This will remove manually created firewall rules also.", QMessageBox.Yes | QMessageBox.No):
						subprocess.run("netsh advfirewall reset", shell=True)
						self.All_in_block_button.setText("Block")
						self.All_in_block_button.setStyleSheet("color:red;")
						self.All_in_block_button.setCheckable(False)
						
						self.All_out_block_button.setText("Block")
						self.All_out_block_button.setStyleSheet("color:red;")
						self.All_out_block_button.setCheckable(False)
						
						self.domain_in_block_button.setText("Block")
						self.domain_in_block_button.setStyleSheet("color:red;")
						self.domain_in_block_button.setCheckable(False)
						
						self.domain_out_block_button.setText("Block")
						self.domain_out_block_button.setStyleSheet("color:red;")
						self.domain_out_block_button.setCheckable(False)
						
						self.private_in_block_button.setText("Block")
						self.private_in_block_button.setStyleSheet("color:red;")
						self.private_in_block_button.setCheckable(False)
						
						self.private_out_block_button.setText("Block")
						self.private_out_block_button.setStyleSheet("color:red;")
						self.private_out_block_button.setCheckable(False)
						
						self.public_in_block_button.setText("Block")
						self.public_in_block_button.setStyleSheet("color:red;")
						self.public_in_block_button.setCheckable(False)
						
						self.public_out_block_button.setText("Block")
						self.public_out_block_button.setStyleSheet("color:red;")
						self.public_out_block_button.setCheckable(False)
						
						python = sys.executable
						os.execl(python, python, *sys.argv) 
						
					else:
						QMessageBox.information(self, "Informed You", "No Changes were happened")
			else:
				if get_pass == "":
					msg = QMessageBox.warning(self, "Warning", "Enter the password")		
				else:
					msg = QMessageBox.warning(self, "Warning", "Enter the correct password")
					
		self.reset_firewall_btn.clicked.connect(reset_firewall)
		self.reset_firewall_btn.show()
	
	def monitor_firewall(self):
		self.monitor_firewall_btn = QPushButton(self)
		self.monitor_firewall_btn.setText("Monitor")
		self.monitor_firewall_btn.setGeometry(5, 480, 196, 60)
		self.monitor_firewall_btn.clicked.connect(self.monitor)
		self.monitor_firewall_btn.show()
	
	def firewall_notes(self):
		self.firewall_notes_btn = QPushButton(self)
		self.firewall_notes_btn.setText("Notes")
		self.firewall_notes_btn.setGeometry(205, 480, 240, 60)
		self.firewall_notes_btn.clicked.connect(self.notes)
		self.firewall_notes_btn.show()
		
	def allow_block_application(self):
		
		# Allow Block Application Button
		
		self.allow_block_app_btn = QPushButton(self)
		self.allow_block_app_btn.setText("Allow Block Application")
		self.allow_block_app_btn.setGeometry(205, 1, 240, 60)
		self.allow_block_app_btn.clicked.connect(self.allow_block_app)
		self.allow_block_app_btn.show()
	
	def allow_block_port(self):
		
		# Allow Block Port Button	
		
		self.allow_block_port_btn = QPushButton(self)
		self.allow_block_port_btn.setText("Allow Block Port")
		self.allow_block_port_btn.setGeometry(205, 60, 240, 60)
		self.allow_block_port_btn.clicked.connect(self.allow_block_prt)
		self.allow_block_port_btn.show()
		
	def allow_block_service(self):
		
		# Allow Block Service Button
		
		self.allow_block_service_btn = QPushButton(self)
		self.allow_block_service_btn.setText("Allow Block Service")
		self.allow_block_service_btn.setGeometry(205, 120, 240, 60)
		self.allow_block_service_btn.clicked.connect(self.allow_block_srv)
		self.allow_block_service_btn.show()
		
	def allow_block_private_ip(self):
		
		# Allow Block Private IP Button
		
		self.allow_block_private_ip_btn = QPushButton(self)
		self.allow_block_private_ip_btn.setText("Allow Block Private IP")
		self.allow_block_private_ip_btn.setGeometry(205, 180, 240, 60)
		self.allow_block_private_ip_btn.clicked.connect(self.allow_block_priv_ip)
		self.allow_block_private_ip_btn.show()
		
	def allow_block_public_ip(self):
		
		# Allow Block Public IP Button
		
		self.allow_block_public_ip_btn = QPushButton(self)
		self.allow_block_public_ip_btn.setText("Allow Block Public IP")
		self.allow_block_public_ip_btn.setGeometry(205, 240, 240, 60)
		self.allow_block_public_ip_btn.clicked.connect(self.allow_block_pub_ip)
		self.allow_block_public_ip_btn.show()
		
	def import_export_rule(self):
		
		# Button for Import or Export Firewall rule.
		
		self.import_export_rule_btn = QPushButton(self)
		self.import_export_rule_btn.setText("Import or Export Firewall Rule")
		self.import_export_rule_btn.setGeometry(205, 300, 240, 60) 
		self.import_export_rule_btn.clicked.connect(self.import_export_firewall_rule)
		self.import_export_rule_btn.show()
		
	def modify_exist_rule(self):
		
		# Button for Modifying existing rule of firewall.
		
		self.modify_exist_rule_btn = QPushButton(self)
		self.modify_exist_rule_btn.setText("Modify Existing Rule")
		self.modify_exist_rule_btn.setGeometry(205, 360, 240, 60)
		self.modify_exist_rule_btn.clicked.connect(self.modify_exist_firewall_rule)
		self.modify_exist_rule_btn.show()
	
	def delete_firewall_rule(self):
		
		# Delete Firewall Rule Button
		
		self.delete_firewall_rule_btn = QPushButton(self)
		self.delete_firewall_rule_btn.setText("Delete Firewall Rule")
		self.delete_firewall_rule_btn.setGeometry(205, 420, 240, 60)
		self.delete_firewall_rule_btn.clicked.connect(self.delete_fw_rule)
		self.delete_firewall_rule_btn.show()
			
	def notes(self):
		self.firewall_doc = Notes()
		self.firewall_doc.show()


	def monitor(self):
		self.monitor_firewall = Monitor()
		self.monitor_firewall.view_all_rule()
		self.monitor_firewall.check_specific_rule()
		self.monitor_firewall.monitor_current_firewall_state()
		self.monitor_firewall.firewall_logging_ED()
		self.monitor_firewall.check_log_setting()
		self.monitor_firewall.view_windows_firewall_logs()
		self.monitor_firewall.show()
			
	def allow_block_app(self):
		
		# Calling the Allow_Block_App class from here 
		
		self.app = Allow_Block_App()
		self.app.app_rule_name()
		self.app.app_rule_description()
		self.app.app_rule_program()
		self.app.app_rule_local_ip()
		self.app.app_rule_local_port()
		self.app.app_rule_remote_ip()
		self.app.app_rule_remote_port()
		self.app.app_rule_direction()
		self.app.app_rule_action()
		self.app.app_rule_profile()
		self.app.app_rule_protocol()
		self.app.app_rule_service()
		self.app.app_rule_interface_type()
		self.app.app_rule_security()
		self.app.app_rule_rmtcompgrp()
		self.app.app_rule_rmtusrgrp()
		self.app.app_rule_enable()
		self.app.app_rule_action_button()
		self.app.show()

	def allow_block_prt(self):

		# Calling the Allow_Block_Port class from here 
		
		self.allow_block_port = Allow_Block_Port()
		self.allow_block_port.allow_block_port_rule_name()
		self.allow_block_port.allow_block_port_rule_description()
		self.allow_block_port.allow_block_port_rule_local_ip()
		self.allow_block_port.allow_block_port_rule_local_port()	
		self.allow_block_port.allow_block_port_rule_remote_ip()
		self.allow_block_port.allow_block_port_rule_remote_port()
		self.allow_block_port.allow_block_port_rule_direction()
		self.allow_block_port.allow_block_port_rule_action()
		self.allow_block_port.allow_block_port_rule_protocol()
		self.allow_block_port.allow_block_port_rule_profile()
		self.allow_block_port.allow_block_port_rule_enable()
		self.allow_block_port.allow_block_port_action_button()
		self.allow_block_port.show()	
	
	def allow_block_srv(self):
		
		# Calling the Allow_Block_Service class from here 
		
		self.allow_block_service_rule = Allow_Block_Service()
		self.allow_block_service_rule.allow_block_service_rule_nme()
		self.allow_block_service_rule.allow_block_service_rule_description()
		self.allow_block_service_rule.allow_block_service_rule_local_ip()
		self.allow_block_service_rule.allow_block_service_rule_local_port()
		self.allow_block_service_rule.allow_block_service_rule_remote_ip()
		self.allow_block_service_rule.allow_block_service_rule_remote_port()
		self.allow_block_service_rule.allow_block_service_rule_direction()
		self.allow_block_service_rule.allow_block_service_rule_action()
		self.allow_block_service_rule.allow_block_service_rule_service()
		self.allow_block_service_rule.allow_block_service_rule_protocol()
		self.allow_block_service_rule.allow_block_service_rule_profile()
		self.allow_block_service_rule.allow_block_service_rule_interfacetype()
		self.allow_block_service_rule.allow_block_service_rule_edge()
		self.allow_block_service_rule.allow_block_service_rule_enable()
		self.allow_block_service_rule.allow_block_service_rule_action_button()
		self.allow_block_service_rule.show()
	
	def allow_block_priv_ip(self):
		
		# Calling the Allow_Block_Private_IP class from here 
		
		self.allow_block_private_ip = Allow_Block_Private_IP()
		self.allow_block_private_ip.allow_block_private_ip_name()
		self.allow_block_private_ip.allow_block_private_ip_description()
		self.allow_block_private_ip.allow_block_private_ip_local_ip()
		self.allow_block_private_ip.allow_block_private_ip_local_port()
		self.allow_block_private_ip.allow_block_private_ip_remote_ip()
		self.allow_block_private_ip.allow_block_private_ip_remote_port()
		self.allow_block_private_ip.allow_block_private_ip_direction()
		self.allow_block_private_ip.allow_block_private_ip_action()		
		self.allow_block_private_ip.allow_block_private_ip_protocol()
		self.allow_block_private_ip.allow_block_private_ip_profile()
		self.allow_block_private_ip.allow_block_private_ip_interface_type()
		self.allow_block_private_ip.allow_block_private_ip_edge()
		self.allow_block_private_ip.allow_block_private_ip_enable()
		self.allow_block_private_ip.allow_block_private_ip_action_button()
		self.allow_block_private_ip.show()
	
	def allow_block_pub_ip(self):
		self.allow_block_pub_ip = Allow_Block_Public_IP()
		self.allow_block_pub_ip.allow_block_public_ip_name()
		self.allow_block_pub_ip.allow_block_public_ip_description()
		self.allow_block_pub_ip.allow_block_public_ip_local_ip()
		self.allow_block_pub_ip.allow_block_public_ip_local_port()
		self.allow_block_pub_ip.allow_block_public_ip_remote_ip()
		self.allow_block_pub_ip.allow_block_public_ip_remote_port()
		self.allow_block_pub_ip.allow_block_public_ip_direction()
		self.allow_block_pub_ip.allow_block_public_ip_action()
		self.allow_block_pub_ip.allow_block_public_ip_protocol()
		self.allow_block_pub_ip.allow_block_public_ip_profile()
		self.allow_block_pub_ip.allow_block_public_ip_interface_type()
		self.allow_block_pub_ip.allow_block_public_ip_edge()
		self.allow_block_pub_ip.allow_block_public_ip_enable()
		self.allow_block_pub_ip.allow_block_public_ip_action_button()
		self.allow_block_pub_ip.show()
	
	def import_export_firewall_rule(self):
		self.import_export_firewall_rule = Import_Export_Firewall_Rule()
		self.import_export_firewall_rule.import_export_firewall_rule_name()
		self.import_export_firewall_rule.import_export_firewall_rule_get_file()
		self.import_export_firewall_rule.import_export_firewall_rule_action_button()
		self.import_export_firewall_rule.show()
	
	def modify_exist_firewall_rule(self):
		self.modify_exist_firewall_rule = Modify_Exist_Rule()
		self.modify_exist_firewall_rule.modify_exist_rule_name()
		self.modify_exist_firewall_rule.modify_exist_rule_rename()
		self.modify_exist_firewall_rule.modify_exist_rule_description()
		self.modify_exist_firewall_rule.modify_exist_rule_program()
		self.modify_exist_firewall_rule.modify_exist_rule_local_ip()
		self.modify_exist_firewall_rule.modify_exist_rule_local_port()
		self.modify_exist_firewall_rule.modify_exist_rule_remote_ip()
		self.modify_exist_firewall_rule.modify_exist_rule_remote_port()
		self.modify_exist_firewall_rule.modify_exist_rule_direction()
		self.modify_exist_firewall_rule.modify_exist_rule_profile()
		self.modify_exist_firewall_rule.modify_exist_rule_service()
		self.modify_exist_firewall_rule.modify_exist_rule_protocol()
		self.modify_exist_firewall_rule.modify_exist_rule_action()
		self.modify_exist_firewall_rule.modify_exist_rule_interface_type()
		self.modify_exist_firewall_rule.modify_exist_rule_security()
		self.modify_exist_firewall_rule.modify_exist_rule_enable()
		self.modify_exist_firewall_rule.modify_exist_rule_edge()
		self.modify_exist_firewall_rule.modify_exist_rule_rmtcompgrp()
		self.modify_exist_firewall_rule.modify_exist_rule_rmtusrgrp()
		self.modify_exist_firewall_rule.modify_exist_rule_action_button()
		self.modify_exist_firewall_rule.show()
	
	def delete_fw_rule(self):
		self.delete_fw_rule = Delete_Firewall_Rule()
		self.delete_fw_rule.delete_firewall_rule_name()
		self.delete_fw_rule.delete_firewall_rule_group()
		self.delete_fw_rule.delete_firewall_rule_program()
		self.delete_fw_rule.delete_firewall_rule_local_ip()
		self.delete_fw_rule.delete_firewall_rule_local_port()
		self.delete_fw_rule.delete_firewall_rule_remote_ip()
		self.delete_fw_rule.delete_firewall_rule_remote_port()
		self.delete_fw_rule.delete_firewall_rule_direction()
		self.delete_fw_rule.delete_firewall_rule_profile()
		self.delete_fw_rule.delete_firewall_rule_service()
		self.delete_fw_rule.delete_firewall_rule_protocol()
		self.delete_fw_rule.delete_firewall_rule_action_button()
		self.delete_fw_rule.show()
		
	
if __name__ == "__main__":
	app = QApplication(sys.argv)
	wall = Firewall()
	wall.all_profiles()
	wall.all_in_block()
	wall.all_out_block()
	wall.domain_block()
	wall.private_block()
	wall.public_block()
	wall.reset_firewall()
	wall.allow_block_application()
	wall.allow_block_port()
	wall.allow_block_service()
	wall.allow_block_private_ip()
	wall.allow_block_public_ip()
	wall.import_export_rule()
	wall.modify_exist_rule()
	wall.delete_firewall_rule()
	wall.monitor_firewall()
	wall.firewall_notes()
	wall.show()
	sys.exit(app.exec_())
