# keylogger-C
Keylogger with C and win32 API

## Description:

-The keylogger uses C and employs hooks, win32 API and offset obfuscation. 

-It logs keystrokes entered by the victim for a certain amount of keystrokes, that you specify, to a log file and sends the file to an ftp server.

-Using Windows FTP libraries prompts UAC which is very noisy for a keylogger.

-I used system() and curl to send the file silently to my FTP server (VSFTPd server on Ubuntu)

------------------------------------------------------------------------------------------------------

## Execution:

![image](https://github.com/user-attachments/assets/3007d05d-3a61-48c0-821b-b777845b7355)

![image](https://github.com/user-attachments/assets/46246fbd-de8a-40a6-85dd-4aef1ac10ce8)

![image](https://github.com/user-attachments/assets/8e438666-ad01-4132-9226-cf5351eedf93)

-------------------------------------------------------------------------------------------------------

## VirusTotal Analysis:


![image](https://github.com/user-attachments/assets/284004f6-17ad-4c5d-ab30-84d4b3f8abf3)


