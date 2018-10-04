#include <iostream>
#include <fstream>
#include <string>
#include "bsapi.h"
#include "WINSCARD.H"
#include "sha256.h"
#include <vector>
#include "aes.hpp"


using namespace std;

int theEnd(int erno);
void BSAPI callback(const ABS_OPERATION* p_operation, ABS_DWORD msg, void* data);
int printRaw(ABS_BIR &a);
int sendScardCommand(string s, SCARDHANDLE hCardHandle, LPCSCARD_IO_REQUEST req, int length, LPCBYTE input, LPBYTE output, LPDWORD retlen);
string GetScardErrMsg(int code);

int main()
{
	/*Initialize the ABS Reader*/
	ABSInitialize();
	unsigned int handle;
	int erno;
	if ((erno = ABSOpen("usb", &handle)) != ABS_STATUS_OK)theEnd(erno);
	printf("Connected ID: %u\n", handle);
	ABS_OPERATION oper;
	oper.Callback = callback;
	oper.OperationID = 1;
	oper.Context = NULL;
	oper.Flags = 0;
	oper.Timeout = 10000000;
	ABS_IMAGE ** pp = NULL;
	ABS_BIR *a[2];
	oper.OperationID++;
	ABS_BOOL b;

	SCARDCONTEXT    hSC;
	SCARDHANDLE     hCardHandle;
	DWORD           dwAP;
	string deviceModel = "ACS AET65 1SAM ICC Reader ICC 0";
	if (SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC) != SCARD_S_SUCCESS)
	{
		printf("Failed SCardEstablishContext\n");
		system("pause");
		exit(1);
	}

	if (SCardConnect(hSC, deviceModel.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCardHandle, &dwAP) != SCARD_S_SUCCESS)
	{

		printf("Failed SCardConnect\n");
		system("pause");
		exit(1);
	}
	typedef struct _SCARD_IO_REQUEST {
		DWORD dwProtocol;
		DWORD cbPciLength;
	} iorequest;
	iorequest req;
	req.cbPciLength = sizeof(iorequest);
	req.dwProtocol = dwAP;

	
	int retlen, len;
	BYTE retarg[500] = {};
	while (1)
	{
		cout << "1. Enroll fingerprint" << endl;
		cout << "2. Insert Secret" << endl;
		cout << "3. Retrieve Secret" << endl;
		cout << "4. Format scard" << endl;
		cout << "5. Exit" << endl;
		int input;
		cin >> input;
		if (input == 1)
		{
			if ((erno = ABSCapture(handle, &oper, ABS_PURPOSE_ENROLL, a, 0)) != ABS_STATUS_OK)theEnd(erno);
			cout << "Please enter username:\n--> ";
			string s;
			getline(cin, s);
			getline(cin, s);
			fstream out;
			s = "user\\" + s;
			out.open(s.c_str(), fstream::out);
			out << (int)a[0][0].Header.Length << endl;
			out << (int)a[0][0].Header.HeaderVersion << endl;
			out << (int)a[0][0].Header.Type << endl;
			out << (int)a[0][0].Header.FormatOwner << endl;
			out << (int)a[0][0].Header.FormatID << endl;
			out << (int)a[0][0].Header.Quality << endl;
			out << (int)a[0][0].Header.Purpose << endl;
			out << (int)a[0][0].Header.FactorsMask << endl;
			for (int i = 0; i < a[0][0].Header.Length - sizeof(a[0][0].Header); i++)out << (int)a[0][0].Data[i] << " ";
			out.close();
		}
		else if (input == 2)
		{
			cout << "Please enter username:\n--> ";
			string s;
			getline(cin, s);
			getline(cin, s);
			s = "user\\" + s;
			fstream in;
			in.open(s.c_str(), fstream::in);
			a[0] = new ABS_BIR;
			int num;
			in >> num;
			a[0][0].Header.Length = num;
			in >> num;
			a[0][0].Header.HeaderVersion = num;
			in >> num;
			a[0][0].Header.Type = num;
			in >> num;
			a[0][0].Header.FormatOwner = num;
			in >> num;
			a[0][0].Header.FormatID = num;
			in >> num;
			a[0][0].Header.Quality = num;
			in >> num;
			a[0][0].Header.Purpose = num;
			in >> num;
			a[0][0].Header.FactorsMask = num;
			for (int i = 0; i < a[0][0].Header.Length - sizeof(a[1][0].Header); i++)
			{
				in >> num;
				a[0][0].Data[i] = num;
			}
			if ((erno = ABSCapture(handle, &oper, ABS_PURPOSE_VERIFY, a + 1, 0)) != ABS_STATUS_OK)theEnd(erno);
			ABSVerifyMatch(handle, a[0], a[1], &b, 0);
			if (b)cout << "[ANS] Match" << endl;
			else
			{
				cout << "[ANS] No Match" << endl;
				continue;
			}
			string rawData;
			rawData += a[0][0].Header.Length;
			rawData += a[0][0].Header.HeaderVersion;
			rawData += a[0][0].Header.Type;
			rawData += a[0][0].Header.FormatOwner;
			rawData += a[0][0].Header.FormatID;
			rawData += a[0][0].Header.Quality;
			rawData += a[0][0].Header.Purpose;
			rawData += a[0][0].Header.FactorsMask;
			for (int i = 0; i < a[0][0].Header.Length - sizeof(a[0][0].Header); i++)rawData += a[0][0].Data[i];
			cout << "Please enter password:\n--> ";
			string passwd;
			getline(cin, passwd);
			string aeskey = sha256(sha256(rawData) + sha256(passwd));
			uint8_t key[32];
			uint8_t iv[16] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
			AES_ctx ctx;
			cout << aeskey << endl;
			for (int i = 0; i < 32; i++)
			{
				BYTE byte = 0;
				if (aeskey[i * 2] >= '0' && aeskey[i * 2] <= '9')byte += aeskey[i * 2] - '0';
				if (aeskey[i * 2] >= 'A' && aeskey[i * 2] <= 'Z')byte += aeskey[i * 2] - 'A' + 10;
				if (aeskey[i * 2] >= 'a' && aeskey[i * 2] <= 'z')byte += aeskey[i * 2] - 'a' + 10;
				if (aeskey[i * 2 + 1] >= '0' && aeskey[i * 2 + 1] <= '9')byte += 16 * (aeskey[i * 2 + 1] - '0');
				if (aeskey[i * 2 + 1] >= 'A' && aeskey[i * 2 + 1] <= 'Z')byte += 16 * (aeskey[i * 2 + 1] - 'A' + 10);
				if (aeskey[i * 2 + 1] >= 'a' && aeskey[i * 2 + 1] <= 'z')byte += 16 * (aeskey[i * 2 + 1] - 'a' + 10);
				key[i] = byte;
			}
			AES_init_ctx_iv(&ctx, key, iv);
			cout << "Please enter the secret (Length = 64):\n--> " << endl;
			getline(cin, s);
			uint8_t *text = new uint8_t[s.size()];
			for (int i = 0; i < 64; i++)text[i] = (uint8_t)s[i];
			AES_CBC_encrypt_buffer(&ctx, text, 64);
			len = 0x07;
			retlen = 0x02;
			BYTE arg1[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xBB, 0x11 };
			sendScardCommand("Select file BB11", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg1, (LPBYTE)retarg, (LPDWORD)&retlen);

			BYTE arg2[256] = { 0x80, 0xD0, 0x00, 0x00 };
			arg2[4] = 64;
			for (int i = 0; i < 64; i++)arg2[i + 5] = text[i];
			len = 5 + 64;
			retlen = 0x02;
			sendScardCommand("Write file BB11", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg2, (LPBYTE)retarg, (LPDWORD)&retlen);

		}
		else if (input == 3)
		{
			cout << "Please enter username:\n--> ";
			string s;
			getline(cin, s);
			getline(cin, s);
			s = "user\\" + s;
			fstream in;
			in.open(s.c_str(), fstream::in);
			if (in.fail())
			{
				cout << "No user" << endl;
				continue;
			}
			a[0] = new ABS_BIR;
			int num;
			in >> num;
			a[0][0].Header.Length = num;
			in >> num;
			a[0][0].Header.HeaderVersion = num;
			in >> num;
			a[0][0].Header.Type = num;
			in >> num;
			a[0][0].Header.FormatOwner = num;
			in >> num;
			a[0][0].Header.FormatID = num;
			in >> num;
			a[0][0].Header.Quality = num;
			in >> num;
			a[0][0].Header.Purpose = num;
			in >> num;
			a[0][0].Header.FactorsMask = num;
			for (int i = 0; i < a[0][0].Header.Length - sizeof(a[1][0].Header); i++)
			{
				in >> num;
				a[0][0].Data[i] = num;
			}
			if ((erno = ABSCapture(handle, &oper, ABS_PURPOSE_VERIFY, a + 1, 0)) != ABS_STATUS_OK)theEnd(erno);
			ABSVerifyMatch(handle, a[0], a[1], &b, 0);
			if (b)cout << "[ANS] Match" << endl;
			else
			{
				cout << "[ANS] No Match" << endl;
				continue;
			}
			string rawData;
			rawData += a[0][0].Header.Length;
			rawData += a[0][0].Header.HeaderVersion;
			rawData += a[0][0].Header.Type;
			rawData += a[0][0].Header.FormatOwner;
			rawData += a[0][0].Header.FormatID;
			rawData += a[0][0].Header.Quality;
			rawData += a[0][0].Header.Purpose;
			rawData += a[0][0].Header.FactorsMask;
			for (int i = 0; i < a[0][0].Header.Length - sizeof(a[0][0].Header); i++)rawData += a[0][0].Data[i];
			cout << "Please enter password:\n--> ";
			string passwd;
			getline(cin, passwd);
			string aeskey = sha256(sha256(rawData) + sha256(passwd));
			uint8_t key[32];
			uint8_t iv[16] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
			AES_ctx ctx;
			cout << aeskey << endl;
			for (int i = 0; i < 32; i++)
			{
				BYTE byte = 0;
				if (aeskey[i * 2] >= '0' && aeskey[i * 2] <= '9')byte += aeskey[i * 2] - '0';
				if (aeskey[i * 2] >= 'A' && aeskey[i * 2] <= 'Z')byte += aeskey[i * 2] - 'A' + 10;
				if (aeskey[i * 2] >= 'a' && aeskey[i * 2] <= 'z')byte += aeskey[i * 2] - 'a' + 10;
				if (aeskey[i * 2 + 1] >= '0' && aeskey[i * 2 + 1] <= '9')byte += 16 * (aeskey[i * 2 + 1] - '0');
				if (aeskey[i * 2 + 1] >= 'A' && aeskey[i * 2 + 1] <= 'Z')byte += 16 * (aeskey[i * 2 + 1] - 'A' + 10);
				if (aeskey[i * 2 + 1] >= 'a' && aeskey[i * 2 + 1] <= 'z')byte += 16 * (aeskey[i * 2 + 1] - 'a' + 10);
				key[i] = byte;
			}
			AES_init_ctx_iv(&ctx, key, iv);
			
			len = 0x07;
			retlen = 0x02;
			BYTE arg1[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xBB, 0x11 };
			sendScardCommand("Select file BB11", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg1, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 0x05;
			retlen = 0x02 + 64;
			BYTE arg2[] = { 0x80, 0xB0, 0x00, 0x00, 64 };
			BYTE retstr[500] = {};
			sendScardCommand("Read file BB11", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg2, (LPBYTE)retstr, (LPDWORD)&retlen);
			s = "";
			for (int i = 0; i < 64; i++)s += retstr[i];
			uint8_t *text = new uint8_t[64];
			for (int i = 0; i < 64; i++)text[i] = (uint8_t)s[i];
			AES_CBC_decrypt_buffer(&ctx, text, 64);
			for (int i = 0; i < 64; i++)s[i] = text[i];
			cout << "Return secret:\n" << s << endl;
		}
		else if (input == 4)
		{
			len = 0x0D;
			retlen = 0x02;
			BYTE arg2[] = { 0x80, 0x20, 0x07, 0x00, 0x08, 0x41, 0x43, 0x4F, 0x53, 0x54, 0x45, 0x53, 0x54 };
			sendScardCommand("Submit IC", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg2, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 0x07;
			retlen = 0x02;
			BYTE arg3[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xFF, 0x02 };
			sendScardCommand("Select file FF02", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg3, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 4 + 5;
			retlen = 0x02;
			BYTE arg4[] = { 0x80, 0xD2, 0x00, 0x00, 0x04, 0x00, 0x00, 0x05, 0x00 };
			sendScardCommand("Write Record FF02", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg4, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 0x0D;
			sendScardCommand("Submit IC", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg2, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 0x07;
			retlen = 0x02;
			BYTE arg5[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xFF, 0x04 };
			sendScardCommand("Select file FF04", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg5, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 7 + 5;
			retlen = 0x02;
			BYTE arg6[] = { 0x80, 0xD2, 0x00, 0x00, 0x07, 0x32, 0x00, 0x00, 0x00, 0xBB, 0x11, 0x80 };
			sendScardCommand("Write Record FF04", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg6, (LPBYTE)retarg, (LPDWORD)&retlen);
		}
		else return 0;

	}
	/*cout << "[LOG] FIRST" << endl;
	//if((erno = ABSEnroll(handle, &oper, a, 0)) != ABS_STATUS_OK)theEnd(erno);
	if ((erno = ABSCapture(handle, &oper, ABS_PURPOSE_ENROLL, a, 0)) != ABS_STATUS_OK)theEnd(erno);
	printRaw(*a[0]);
	cout << "[LOG] SECOND" << endl;
	//if((erno = ABSEnroll(handle, &oper, a + 1, 0)) != ABS_STATUS_OK)theEnd(erno);
	if ((erno = ABSCapture(handle, &oper, ABS_PURPOSE_VERIFY, a + 1, 0)) != ABS_STATUS_OK)theEnd(erno);
	ABSVerifyMatch(handle, a[0], a[1], &b, 0);
	if (b)cout << "MATCH" << endl;
	else cout << "NO MATCH" << endl;
	*/
	/*
	
	SCARDCONTEXT    hSC;
	SCARDHANDLE     hCardHandle;
	DWORD           dwAP;
	string deviceModel = "ACS AET65 1SAM ICC Reader ICC 0";
	if (SCardEstablishContext(SCARD_SCOPE_USER, NULL, NULL, &hSC)  != SCARD_S_SUCCESS)
	{
		printf("Failed SCardEstablishContext\n");
		system("pause");
		exit(1);
	}

	if (SCardConnect(hSC, deviceModel.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCardHandle, &dwAP) != SCARD_S_SUCCESS)
	{

		printf("Failed SCardConnect\n");
		system("pause");
		exit(1);
	}
	typedef struct _SCARD_IO_REQUEST {
		DWORD dwProtocol;
		DWORD cbPciLength;
	} iorequest;
	iorequest req;
	req.cbPciLength = sizeof(iorequest);
	req.dwProtocol = dwAP;
	
	int retlen, len;
	BYTE retarg[500] = {};
	int input;
	while (1)
	{
		cout << "1: Format card" << endl;
		cout << "2: Write card" << endl;
		cout << "3: Read card" << endl;
		cout << "4: exit" << endl;
		cin >> input;
		if (input == 1)
		{
			len = 0x0D;
			retlen = 0x02;
			BYTE arg2[] = { 0x80, 0x20, 0x07, 0x00, 0x08, 0x41, 0x43, 0x4F, 0x53, 0x54, 0x45, 0x53, 0x54 };
			sendScardCommand("Submit IC", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg2, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 0x07;
			retlen = 0x02;
			BYTE arg3[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xFF, 0x02 };
			sendScardCommand("Select file FF02", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg3, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 4 + 5;
			retlen = 0x02;
			BYTE arg4[] = { 0x80, 0xD2, 0x00, 0x00, 0x04, 0x00, 0x00, 0x05, 0x00 };
			sendScardCommand("Write Record FF02", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg4, (LPBYTE)retarg, (LPDWORD)&retlen);

			len = 0x0D;
			sendScardCommand("Submit IC", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg2, (LPBYTE)retarg, (LPDWORD)&retlen);
			
			len = 0x07;
			retlen = 0x02;
			BYTE arg5[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xFF, 0x04 };
			sendScardCommand("Select file FF04", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg5, (LPBYTE)retarg, (LPDWORD)&retlen);
			
			len = 7 + 5;
			retlen = 0x02;
			BYTE arg6[] = { 0x80, 0xD2, 0x00, 0x00, 0x07, 0x32, 0x00, 0x00, 0x00, 0xBB, 0x11, 0x80 };
			sendScardCommand("Write Record FF04", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg6, (LPBYTE)retarg, (LPDWORD)&retlen);
		}
		else if (input == 2)
		{
			string s;
			cout << "Enter the entry" << endl;
			cin.clear();
			getline(cin, s);
			getline(cin, s);
			cout << "Length: " << s.length() << endl;
			len = 0x07;
			retlen = 0x02;
			BYTE arg1[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xBB, 0x11 };
			sendScardCommand("Select file BB11", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg1, (LPBYTE)retarg, (LPDWORD)&retlen);
			
			BYTE arg2[256] = { 0x80, 0xD0, 0x00, 0x00};
			arg2[4] = s.length();
			for (int i = 0; i < s.length(); i++)arg2[i + 5] = s[i];
			len = 5 + s.length();
			retlen = 0x02;
		}
		else if (input == 3)
		{
			len = 0x07;
			retlen = 0x02;
			BYTE arg1[] = { 0x80, 0xA4, 0x00, 0x00, 0x02, 0xBB, 0x11 };
			sendScardCommand("Select file BB11", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg1, (LPBYTE)retarg, (LPDWORD)&retlen);
			
			len = 0x05;
			retlen = 0x02 + 0xF9;
			BYTE arg2[] = { 0x80, 0xB0, 0x00, 0x00, 0xF9};
			BYTE retstr[500] = {};
			sendScardCommand("Read file BB11", hCardHandle, (LPCSCARD_IO_REQUEST)&req, len, (LPCBYTE)arg2, (LPBYTE)retstr, (LPDWORD)&retlen);
			string s;
			for (int i = 0; i < 200; i++)s += retstr[i];
			cout << s << endl;
		}
		else return 0;
	}
	*/
	system("pause");
}

int theEnd(int erno)
{
	unsigned int i = 1;
	const char **c = {};
	ABSGetLastErrorInfo(&i, c);
	cout << "Error " << c << endl;
	system("pause");
	exit(0);
}

int printRaw(ABS_BIR &a)
{
	cout << endl;
	cout << "[LOG] LENGTH: " << (int)a.Header.Length << endl;
	cout << "[LOG] HEADER VERSION: " << (int)a.Header.HeaderVersion << endl;
	cout << "[LOG] TYPE: " << (int)a.Header.Type << endl;
	cout << "[LOG] FORMAT OWNER: " << (int)a.Header.FormatOwner << endl;
	cout << "[LOG] FORMAT ID: " << (int)a.Header.FormatID << endl;
	cout << "[LOG] QUALITY: " << (int)a.Header.Quality << endl;
	cout << "[LOG] PURPOSE: " << (int)a.Header.Purpose << endl;
	cout << "[LOG] FACTORSMASK: " << (int)a.Header.FactorsMask << endl;
	cout << "[LOG] DATA: ";
	for (int i = 0; i < a.Header.Length - sizeof(a.Header); i++)cout << (int)a.Data[i] << " ";
	cout << endl << endl;
	return 0;


}

int sendScardCommand(string s, SCARDHANDLE hCardHandle, LPCSCARD_IO_REQUEST req, int length, LPCBYTE input, LPBYTE output, LPDWORD retlen)
{
	cout << "[LOG] Command: " << s << endl;
	int state = SCardTransmit(hCardHandle, req, input, length, NULL, output, retlen);
	if (state != SCARD_S_SUCCESS)
	{
		cout << "[ERR] Command failed on code " << state << endl;
		cout << "[ERR] Code translate: " << GetScardErrMsg(state) << endl;
		return -1;
	}
	else
	{
		cout << "[LOG] Command returns: ";
		for (int i = 0; i < (int) *retlen; i++)printf("%02X ", output[i] & 0xFF);
		printf("\n");
		return 0;
	}
}

void BSAPI callback(const ABS_OPERATION* p_operation, ABS_DWORD msg, void* data)
{
	switch (msg) {
		// These messages just inform us how the interactive operation
		// progresses
	case ABS_MSG_PROCESS_BEGIN:
		//cout << "begun" << endl;
		break;
	case ABS_MSG_PROCESS_END:
		//cout << "done" << endl;
		break;
		// On some platforms, the biometric operastion can be suspended
		// when other process acquires sensor for other operation. */
	case ABS_MSG_PROCESS_SUSPEND:
		cout << " operation has been suspended" << endl;
		break;
	case ABS_MSG_PROCESS_RESUME:
		cout << " operation has been suspended" << endl;
		break;

		// Info on how the operation progresses is sent. */
	case ABS_MSG_PROCESS_PROGRESS:
	{
		ABS_PROCESS_PROGRESS_DATA* progress_data = (ABS_PROCESS_PROGRESS_DATA*)data;
		if (progress_data->Percentage <= 100)cout << "[LOG] Progress:" << (int)progress_data->Percentage << endl;
		else cout << "[LOG] Operation in progress" << endl;
		break;
	}
	case ABS_MSG_PROCESS_SUCCESS:
		cout << "[LOG] SUC" << endl;
		break;
	case ABS_MSG_PROCESS_FAILURE:
		cout << "[LOG] FAL" << endl;
		break;

		// Prompt messages should inform the user that he should do 
		// something. 
	case ABS_MSG_PROMPT_SCAN:
		cout << "[LOG] SWIPE" << endl;
		break;
	case ABS_MSG_PROMPT_TOUCH:
		cout << "[LOG] TOUCH" << endl;
		break;
	case ABS_MSG_PROMPT_KEEP:
		cout << "[LOG] KEEP" << endl;
		break;
	case ABS_MSG_PROMPT_LIFT:
		cout << "[LOG] GTFO" << endl;
		break;
	case ABS_MSG_PROMPT_CLEAN:
		cout << "[LOG] CLEAN" << endl;
		break;

		// Quality messages come if something went wrong. E.g. the user
		// did not scan his finger in the right way. */
	case ABS_MSG_QUALITY_CENTER_HARDER:
		cout << "[BAD] CENTRE & HARDER" << endl;
		break;
	case ABS_MSG_QUALITY_CENTER:
		cout << "[BAD] CENTRE" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_LEFT:
		cout << "[BAD] TOO LEFT" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_RIGHT:
		cout << "[BAD] TOO RIGHT" << endl;
		break;
	case ABS_MSG_QUALITY_HARDER:
		cout << "[BAD] HARDER" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_LIGHT:
		cout << "[BAD] TOO LIGHT" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_DRY:
		cout << "[BAD] TOO DRY" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_SMALL:
		cout << "[BAD] TOO SMALL" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_SHORT:
		cout << "[BAD] TOO SHORT" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_HIGH:
		cout << "[BAD] TOO HIGH" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_LOW:
		cout << "[BAD] TOO LOW" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_FAST:
		cout << "[BAD] TOO FAST" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_SKEWED:
		cout << "[BAD] TOO SKEW" << endl;
		break;
	case ABS_MSG_QUALITY_TOO_DARK:
		cout << "[BAD] TOO DARK" << endl;
		break;
	case ABS_MSG_QUALITY_BACKWARD:
		cout << "[BAD] TOO BACKWARD" << endl;
		break;
	case ABS_MSG_QUALITY_JOINT:
		cout << "[BAD] JOINT" << endl;
		break;

		// Navigation messages are sent only from ABSNavigate. Its not used
		// in this sample but we list the messages here for completeness. */
	case ABS_MSG_NAVIGATE_CHANGE:
	case ABS_MSG_NAVIGATE_CLICK:
		break;

		/// On these messages the GUI dialog should be made vsiible
		// and invisible respectivelly. */
	case ABS_MSG_DLG_SHOW:
	case ABS_MSG_DLG_HIDE:
		break;
	}
}

string GetScardErrMsg(int code)
{
	switch (code)
	{
		// Smartcard Reader interface errors
	case SCARD_E_CANCELLED:
		return ("The action was canceled by an SCardCancel request.");
		break;
	case SCARD_E_CANT_DISPOSE:
		return ("The system could not dispose of the media in the requested manner.");
		break;
	case SCARD_E_CARD_UNSUPPORTED:
		return ("The smart card does not meet minimal requirements for support.");
		break;
	case SCARD_E_DUPLICATE_READER:
		return ("The reader driver didn't produce a unique reader name.");
		break;
	case SCARD_E_INSUFFICIENT_BUFFER:
		return ("The data buffer for returned data is too small for the returned data.");
		break;
	case SCARD_E_INVALID_ATR:
		return ("An ATR string obtained from the registry is not a valid ATR string.");
		break;
	case SCARD_E_INVALID_HANDLE:
		return ("The supplied handle was invalid.");
		break;
	case SCARD_E_INVALID_PARAMETER:
		return ("One or more of the supplied parameters could not be properly interpreted.");
		break;
	case SCARD_E_INVALID_TARGET:
		return ("Registry startup information is missing or invalid.");
		break;
	case SCARD_E_INVALID_VALUE:
		return ("One or more of the supplied parameter values could not be properly interpreted.");
		break;
	case SCARD_E_NOT_READY:
		return ("The reader or card is not ready to accept commands.");
		break;
	case SCARD_E_NOT_TRANSACTED:
		return ("An attempt was made to end a non-existent transaction.");
		break;
	case SCARD_E_NO_MEMORY:
		return ("Not enough memory available to complete this command.");
		break;
	case SCARD_E_NO_SERVICE:
		return ("The smart card resource manager is not running.");
		break;
	case SCARD_E_NO_SMARTCARD:
		return ("The operation requires a smart card, but no smart card is currently in the device.");
		break;
	case SCARD_E_PCI_TOO_SMALL:
		return ("The PCI receive buffer was too small.");
		break;
	case SCARD_E_PROTO_MISMATCH:
		return ("The requested protocols are incompatible with the protocol currently in use with the card.");
		break;
	case SCARD_E_READER_UNAVAILABLE:
		return ("The specified reader is not currently available for use.");
		break;
	case SCARD_E_READER_UNSUPPORTED:
		return ("The reader driver does not meet minimal requirements for support.");
		break;
	case SCARD_E_SERVICE_STOPPED:
		return ("The smart card resource manager has shut down.");
		break;
	case SCARD_E_SHARING_VIOLATION:
		return ("The smart card cannot be accessed because of other outstanding connections.");
		break;
	case SCARD_E_SYSTEM_CANCELLED:
		return ("The action was canceled by the system, presumably to log off or shut down.");
		break;
	case SCARD_E_TIMEOUT:
		return ("The user-specified timeout value has expired.");
		break;
	case SCARD_E_UNKNOWN_CARD:
		return ("The specified smart card name is not recognized.");
		break;
	case SCARD_E_UNKNOWN_READER:
		return ("The specified reader name is not recognized.");
		break;
	case SCARD_F_COMM_ERROR:
		return ("An internal communications error has been detected.");
		break;
	case SCARD_F_INTERNAL_ERROR:
		return ("An internal consistency check failed.");
		break;
	case SCARD_F_UNKNOWN_ERROR:
		return ("An internal error has been detected, but the source is unknown.");
		break;
	case SCARD_F_WAITED_TOO_LONG:
		return ("An internal consistency timer has expired.");
		break;
	case SCARD_W_REMOVED_CARD:
		return ("The smart card has been removed and no further communication is possible.");
		break;
	case SCARD_W_RESET_CARD:
		return ("The smart card has been reset, so any shared state information is invalid.");
		break;
	case SCARD_W_UNPOWERED_CARD:
		return ("Power has been removed from the smart card and no further communication is possible.");
		break;
	case SCARD_W_UNRESPONSIVE_CARD:
		return ("The smart card is not responding to a reset.");
		break;
	case SCARD_W_UNSUPPORTED_CARD:
		return ("The reader cannot communicate with the card due to ATR string configuration conflicts.");
		break;
	}
	return ("Error is not documented.");
}