***** Password for "Firewall Manager.rar" *****

firewall@12345#12345


***** After Extract Directory Structure *****

Firewall Manager
        |-------Backup
        	|-----Firewall Manager.rar
		|-----README.txt
 
	|-------Data
		|---file1.json
		|---file2.json
		|---rule.txt

	|-------Images
                |-----firewall.ico

	|-------Import-Export-Data
		|-----------------file1.wfw
		|-----------------file2.wfw

	|-------Notes
		|----notes.txt
		|----README.txt

	|-------main.py



***** Convert .py to .exe *****

0) Open cmd as Administrator in "Firewall Manager" Directory. 
Requirement's
------------| Download python from "https://www.python.org/downloads/"
------------| Install and Restart the device.
------------| Install PyQt5 (Open cmd as Administrator) write python.exe -m pip install PyQt5

1) Install PyInstaller
-> python.exe -m pip install pyinstaller

2) pyinstaller --onefile --noconsole --icon=Images/firewall.ico --add-data "Images;Images" --add-data "Data;Data" --add-data "Import-Export-Data;Import-Export-Data" --add-data "Notes;Notes" --add-data "Backup;Backup" main.py

3) Above Command Generates 
|---build
|---dist
|---main.spec

4) copy (Backup, Data, Images, Import-Export-Data, Notes) to "dist" Directory.

5) Create New Directory of name "Firewall Manager"

6) Move (build, dist, main.spec) to "Firewall Manager"

7) then run dist/main.exe as administrator.


