#pragma once
#ifndef MACOR_H
#define MACOR_H

#define ARRSIZE			256
#define DNSDATASIZE		256
#define DNSQUESIZE		256
#define DNSMAXSIZE		512		//DNS������󳤶�
#define DOMAINSIZE		256
#define IPARRHOR		16		//struct DnsRr�ṹ���
#define IPARRVER		8		//struct DnsRr�ṹ����
#define FILEPATHSIZE	256

struct DnsRr
{
	char domain[DOMAINSIZE];
	size_t IpCount;
	char IpArr[IPARRHOR][IPARRVER];
};

#endif // !MACOR_H
