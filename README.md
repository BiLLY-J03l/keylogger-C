# keylogger-C
Keylogger with C

-The keylogger uses C and employs hooks, win32 API and offset obfuscation. 

-It logs keystrokes entered by the victim for a certain amount of keystrokes, that you specify, to a log file and sends the file to an ftp server.

-Using Windows FTP libaries prompts UAC which is very noisy for a keylogger.

-I used system() and curl to send the file silently to my FTP server (VSFTPd server on Ubuntu)

