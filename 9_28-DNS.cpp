// 9_28-DNS.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "Macor.h"

#pragma comment(lib, "ws2_32.lib")

int MainDealWithArgv(int, TCHAR **, TCHAR *, TCHAR *);
int MainWinStart(SOCKET *,SOCKADDR_IN *, TCHAR *);
int MainMakeRequestData(TCHAR *, size_t *, char *);
int MainSendRecv(SOCKET, char *, size_t, SOCKADDR_IN, char *);
int MainAnlyRespData(char *, DnsRr *);
int MainWinClose(SOCKET);

int DivideDomain(char *, size_t *, char *);
int GetIpArr(char *, size_t, DnsRr *);

int _tmain(int argc, TCHAR **argv)
{
	/*...*/
	SOCKET cSock = NULL;
	SOCKADDR_IN sai = { NULL };
	TCHAR DnsIp[ARRSIZE] = { NULL };
	TCHAR domain[ARRSIZE] = { NULL };
	char DNS_Data[DNSDATASIZE] = { NULL };
	size_t DataLen = 0;
	char FilePath[FILEPATHSIZE] = { NULL };
	DnsRr dr = { NULL };
	TCHAR msg_t[ARRSIZE] = { NULL };

	/*...*/
	ZeroMemory(&sai, sizeof(SOCKADDR_IN));
	ZeroMemory(DnsIp, _countof(DnsIp) * 2);
	ZeroMemory(domain, _countof(domain) * 2);
	ZeroMemory(DNS_Data, _countof(DNS_Data));

	//---------------------------------------------
	//��������
	MainDealWithArgv(argc, argv, domain, DnsIp);

	_tprintf_s(_T("%s, %s, %s, %s\n"), argv[1], argv[2], domain, DnsIp);
	//---------------------------------------------
	//��ʼ���ã�����WSA
	MainWinStart(&cSock, &sai, DnsIp);
	
	//---------------------------------------------
	//������������
	MainMakeRequestData(domain, &DataLen, DNS_Data);

	//---------------------------------------------
	//�����������ݣ�������Ӧ����
	MainSendRecv(cSock, DNS_Data, DataLen, sai, FilePath);

	//---------------------------------------------
	//����DNS��Ӧ����
	MainAnlyRespData(FilePath, &dr);

	_stprintf_s(msg_t, _countof(msg_t), _T("dr.IpCount:%u\n"), dr.IpCount);
	_tprintf_s(msg_t);
	for (int i = 0; i < dr.IpCount; ++i) {
		for (int j = 0; j < 4; ++j) {
			printf("%u", (UCHAR)dr.IpArr[i][j]);
			if (3 == j) {
				continue;
			}
			printf(".");
		}
		printf("\n");
	}
	//---------------------------------------------
	//����������ڴ棬����WSA
	//goto end;
	//end:
	MainWinClose(cSock);
	
	system("pause");
    return 0;
}
/*
*����ʱ�䣺2018-9-28
*���ߣ�zmx
*����˵����
*����˵����
*��ע��
*/
int MainDealWithArgv(int in_argc, TCHAR **argv, TCHAR *out_domain, TCHAR *out_DnsIp) {
	/*�����ڲ�����*/


	/*...*/
	switch (in_argc)
	{
	case 1: {
		;
	}break;
	case 2: {
		_stprintf_s(out_domain, 256, _T("%s"), argv[1]);
	}break;
	case 3: {
		_stprintf_s(out_domain, 256, _T("%s"), argv[1]);
		_stprintf_s(out_DnsIp, 256, _T("%s"), argv[2]);
	}break;
	default:
		_tprintf(_T("��δ����\n"));
		break;
	}

	return 0;
}
/*
*����ʱ�䣺2018-9-28
*���ߣ�zmx
*����˵����
*����˵����
*��ע��
*/
int MainWinStart(SOCKET *out_cSock, SOCKADDR_IN *out_sai, TCHAR *in_DnsIp) {
	/*�����ڲ�����*/
	TCHAR msg_t[ARRSIZE] = { NULL };
	SOCKET cSock = NULL;
	IN_ADDR ia_sa = { NULL };
	char ip[ARRSIZE] = { NULL };
	size_t returnValue = 0;

	/*...*/
	WORD sockVer = MAKEWORD(2, 2);
	WSADATA wsadata;
	if (WSAStartup(sockVer, &wsadata) != 0) {
		_stprintf_s(msg_t, _countof(msg_t), _T("WSAStartup error,GetLastError:%lu, errno:%d\n"), GetLastError(), errno);
		_tprintf_s(msg_t);
		system("pause");
		exit(1);
	}
	//����socket
	cSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);		//return��exit֮ǰҪ�ر�cSock
	if (INVALID_SOCKET == cSock) {
		_stprintf_s(msg_t, _countof(msg_t), _T("socket error, GetLastError:%lu, errno:%d\n"), GetLastError(), errno);
		_tprintf_s(msg_t);
		WSACleanup();
		system("pause");
		exit(1);
	}
	wcstombs_s(&returnValue, ip, _countof(ip), in_DnsIp, _countof(ip));	//TCHARתchar

	inet_pton(AF_INET, ip, &ia_sa);
	out_sai->sin_family = AF_INET;
	out_sai->sin_addr = ia_sa;
	out_sai->sin_port = htons(53);

	*out_cSock = cSock;

	return 0;
}
/*
*����ʱ�䣺2018-9-28
*���ߣ�zmx
*����˵����
*����˵����
*��ע��
*/
int MainMakeRequestData(TCHAR *in_domain, size_t *out_data_len, char *out_DNS_Data) {
	/*�����ڲ�����*/
	TCHAR msg_t[ARRSIZE] = { NULL };
	char msg[ARRSIZE] = { NULL };
	char domain[ARRSIZE] = { NULL };
	size_t retVal = 0;
	size_t ddl = 0;
	UCHAR temp = 0;
	char DNS_Head[12] = { NULL };
	char DNS_Question[DNSQUESIZE] = { NULL };

	/*...*/
	ZeroMemory(DNS_Head, _countof(DNS_Head));
	ZeroMemory(DNS_Question, _countof(DNS_Question));
	wcstombs_s(&retVal, domain, _countof(domain), in_domain, _countof(domain));

	//---------------------------------------------
	//HEAD ����
	CopyMemory(&(DNS_Head[0]), "\x01\x23", 2);		//ID
	CopyMemory(&(DNS_Head[2]), "\x01\x0", 2);		//�ں�8�����࣬�ֱ���QR��1bit����opcode��4bit����AA��1bit����TC��1bit�� ��RD��1bit����RA��1bit����Z��3bit����rcode��4bit��
	CopyMemory(&(DNS_Head[4]), "\x0\x01", 2);		//QDCOUNT  question����
	CopyMemory(&(DNS_Head[6]), "\x0\x0", 2);		//ANCOUNT
	CopyMemory(&(DNS_Head[8]), "\x0\x0", 2);		//NSCOUNT
	CopyMemory(&(DNS_Head[10]), "\x0\x0", 2);		//ARCOUNT

	//---------------------------------------------
	//QUESTION ����
	DivideDomain(domain, &ddl, DNS_Question);
	CopyMemory(&(DNS_Question[ddl]), "\x0\x01", 2);
	CopyMemory(&(DNS_Question[ddl + 2]), "\x0\x01", 2);

	//---------------------------------------------
	//�ϲ�
	CopyMemory(out_DNS_Data, DNS_Head, _countof(DNS_Head));
	CopyMemory(&(out_DNS_Data[_countof(DNS_Head)]), DNS_Question, ddl + 4);
	*out_data_len = _countof(DNS_Head) + ddl + 4;

	return 0;
}
/*
*����ʱ�䣺2018-9-28
*���ߣ�zmx
*����˵����
*����˵����
*��ע��
*/
int MainSendRecv(SOCKET in_sock, char *in_data, size_t in_data_len, SOCKADDR_IN in_sai, char *out_filepath) {
	/*�����ڲ�����*/
	char DNS_recv[DNSMAXSIZE] = { NULL };
	int SenderAddrSize = (int)sizeof(in_sai);
	int iFuncStat = 0;
	TCHAR msg_t[ARRSIZE] = { NULL };
	FILE *wfile = NULL;
	time_t time_now = 0;
	char temp[FILEPATHSIZE] = { NULL };

	/*...*/
	iFuncStat = sendto(in_sock, in_data, (int)in_data_len, 0, (SOCKADDR *)&in_sai, sizeof(in_sai));
	if (SOCKET_ERROR == iFuncStat) {
		_stprintf_s(msg_t, _countof(msg_t), _T("sendto error, GetLastError:%lu, errno:%d\n"), GetLastError(), errno);
		_tprintf_s(msg_t);
		WSACleanup();
		system("pause");
		exit(1);
	}

	iFuncStat = recvfrom(in_sock, DNS_recv, _countof(DNS_recv), 0, (SOCKADDR *)&in_sai, &SenderAddrSize);
	if (SOCKET_ERROR == iFuncStat) {
		_stprintf_s(msg_t, _countof(msg_t), _T("recvfrom error, GetLastError:%lu, errno:%d\n"), GetLastError(), errno);
		_tprintf_s(msg_t);
		WSACleanup();
		system("pause");
		exit(1);
	}
	//---------------------------------------------
	//д���ļ�
	time(&time_now);
	CreateDirectory(_T("DNS_History"), NULL);
	sprintf_s(out_filepath, _countof(temp), "DNS_History/%lld.txt", time_now);
	sprintf_s(temp, _countof(temp), "DNS_History/%lld.txt", time_now);
	fopen_s(&wfile, temp, "wb");
	fwrite(DNS_recv, sizeof(char), _countof(DNS_recv), wfile);
	fclose(wfile);

	return 0;
}
/*
*����ʱ�䣺2018-9-28
*���ߣ�zmx
*����˵����
*����˵����
*��ע��
*/
int MainWinClose(SOCKET in_sock) {
	/*�����ڲ�����*/

	/*...*/
	shutdown(in_sock, SD_SEND);
	closesocket(in_sock);
	WSACleanup();

	return 0;
}
/*
*����ʱ�䣺2018-9-29
*���ߣ�zmx
*����˵����
*����˵����
*��ע��
*/
int MainAnlyRespData(char *in_fileName, DnsRr *out_dr) {
	/*�����ڲ�����*/
	FILE *rFile = NULL;
	TCHAR msg_t[ARRSIZE] = { NULL };
	char DnsData[DNSMAXSIZE] = { NULL };
	int iFuncStat = 0;

	/*...*/
	fopen_s(&rFile, in_fileName, "rb");
	if (NULL == rFile) {
		_stprintf_s(msg_t, _countof(msg_t), _T("�ļ���ʧ��\n"));
		_tprintf_s(msg_t);
		system("pause");
		exit(1);
	}
	iFuncStat = (int)fread(DnsData, sizeof(char), _countof(DnsData), rFile);
	if (iFuncStat <= 1) {
		_stprintf_s(msg_t, _countof(msg_t), _T("�ļ���ȡ�쳣\n"));
		_tprintf_s(msg_t);
		system("pause");
		exit(1);
	}
	ZeroMemory(out_dr, sizeof(DnsRr));
	GetIpArr(DnsData, (size_t)iFuncStat, out_dr);

	fclose(rFile);
	return 0;
}


/*
*����ʱ�䣺2018-9-28
*���ߣ�zmx
*����˵����
*����˵������������һ����'\0'��β���ַ����͸��ַ�������
*��ע��
*/
int DivideDomain(char *in_domain, size_t *out_len, char *out_c) {
	/*�����ڲ�����*/
	size_t index = 0;
	size_t ArrIndex = 0;
	size_t ArrLen = 0;
	UCHAR temp = 0;

	/*...*/
	for (int i = 0; in_domain[i] != '\0'; ++i) {
		*out_len += 1;			//��
		ArrLen += 1;
		if ('.' == in_domain[i]) {
			for (int j = (int)index; j < i; ++j) {
				if (j == index) {
					temp = (UCHAR)(ArrLen - 1);
					CopyMemory(&(out_c[ArrIndex]), &temp, 1);
					ArrIndex += 1;
					CopyMemory(&(out_c[ArrIndex]), &(in_domain[j]), 1);
					ArrIndex += 1;
					continue;
				}
				CopyMemory(&(out_c[ArrIndex]), &(in_domain[j]), 1);
				ArrIndex += 1;
			}
			index = i + 1;
			ArrLen = 0;
			if ('\0' == in_domain[i + 1]) {	
				//��β������������2��ĩλ��'\0'
				out_c[ArrIndex] = '\0';
				*out_len += 2;	//������ַ����ܳ���=�����յ��ַ����ܳ���+2
			}
			continue;
		}
		if ('\0' == in_domain[i + 1]) {
			for (int j = (int)index; j < i + 1; ++j) {
				if (j == index) {
					temp = (UCHAR)(ArrLen);
					CopyMemory(&(out_c[ArrIndex]), &temp, 1);
					ArrIndex += 1;
					CopyMemory(&(out_c[ArrIndex]), &(in_domain[j]), 1);
					ArrIndex += 1;
					continue;
				}
				CopyMemory(&(out_c[ArrIndex]), &(in_domain[j]), 1);
				ArrIndex += 1;
			}
			//��β������������2��ĩλ��'\0'
			out_c[ArrIndex] = '\0';
			*out_len += 2;	//������ַ����ܳ���=�����յ��ַ����ܳ���+2
		}
	}

	return 0;
}
/*
*����ʱ�䣺2018-9-29
*���ߣ�zmx
*����˵����
*����˵������������һ����'\0'��β���ַ����͸��ַ�������
*��ע��
*/
int GetIpArr(char *in_data, size_t in_len, DnsRr *out_ip) {
	/*�����ڲ�����*/
	UCHAR temp = 0;
	size_t IpLeft = 0;
	int index = 0;		//��λ�±�
	bool IsIp = FALSE;
	TCHAR msg_t[ARRSIZE] = { NULL };

	/*...*/
	out_ip->IpCount = in_data[6] * 256 + in_data[7];		//��ȡ�ش�����
	if (out_ip->IpCount < 1) {
		_stprintf_s(msg_t, _countof(msg_t), _T("Answer���������쳣\n"));
		_tprintf_s(msg_t);
		system("pause");
		exit(1);
	}
	IpLeft = out_ip->IpCount;

	CopyMemory(&temp, &(in_data[12]), 1);
	for (int i = 12;; ++i) {
		if ('\0' == in_data[i]) {
			index = i + 4 + 1;			//�ҵ�QNAME������־��+4�ֽ�(NSCOUNT(2bit), ARCOUNT(2bit))+1
			while (IpLeft > 0) {
				if ('\xc0' == in_data[index]) {		//����Answer���ֵ�NAME��ָ��ʽ
					IpLeft -= 1;					//����һ��Answer
					if ('\x00' == in_data[index + 2] && '\x05' == in_data[index + 3]) {			//�����ǹ淶����
						out_ip->IpCount -= 1;			//���ָ�Answer���ֲ�����ipʽ
						index += 10;					//PNAME(2bit)+TYPE(2bit)+CLASS(2bit)+TTL(4bit) �͵���RDLENGTHλ��
						index += (in_data[index] * 256 + in_data[index + 1] + 2);
						continue;
					}
					else if ('\x00' == in_data[index + 2] && '\x01' == in_data[index + 3]) {	//������ipʽ
						CopyMemory(&((out_ip->IpArr)[out_ip->IpCount - IpLeft - 1][0]), &(in_data[index + 12]), 4);
						index += 16;
						continue;
					}
					else {
						_stprintf_s(msg_t, _countof(msg_t), _T("��ѯ������δ����\n"));
						_tprintf_s(msg_t);
						system("pause");
						exit(1);
					}		
				}
				else {			//��ָ��ʽ
					_stprintf_s(msg_t, _countof(msg_t), _T("��ָ��ʽAnswer����δ����\n"));
					_tprintf_s(msg_t);
					system("pause");
					exit(1);
				}
			}
			break;
		}
	}

	return 0;
}