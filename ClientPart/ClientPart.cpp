// ClientPart.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//

#include<stdio.h>
#include<stdlib.h>
//#include<winsock.h>
#include<winsock2.h>
#include"ws2tcpip.h"
#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

typedef struct ip_header
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR, * PIPV4_HDR, FAR* LPIPV4_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns : 1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR, * PTCP_HDR, FAR* LPTCP_HDR, TCPHeader, TCP_HEADER;

struct udp_header
{
	unsigned short   src_port; // номер порта отправителя 
	unsigned short   dst_port; // номер порта получателя 
	unsigned short   length; // длина датаграммы 
	unsigned short   crc;   // контрольная сумма заголовка
};

struct icmp_header
{
	unsigned char   type; // тип ICMP- пакета
	unsigned char   code; // код ICMP- пакета 
	unsigned short  crc; // контрольная сумма 
	unsigned long   orig_timestamp; // дополнительные поля 
	unsigned long   recv_timestamp; // уточняющие тип 
	unsigned long   trns_timestamp; //ICMP- пакета
};

struct pseudo_header //Для подсчета crc
{
	unsigned int src_addr; // адрес отправителя 
	unsigned int dst_addr; // адрес получателя 
	unsigned char zero; //начальная установка 
	unsigned char proto; // протокол
	unsigned short length; // длина заголовка 
};

enum ProtoEnum
{
	UDP_proto,
	TCP_proto,
	ICMP_proto
}; //for the future

unsigned short rs_crc(unsigned short* buffer, int length) //for IP and ICMP
{
	unsigned long crc = 0;

	// Вычисление CRC 
	while (length > 1)
	{
		crc += *buffer++;
		length -= sizeof(unsigned short);
	}
	if (length) crc += *(unsigned char*)buffer;

	// Закончить вычисления 
	crc = (crc >> 16) + (crc & 0xffff);
	crc += (crc >> 16);
	//Смещение CRC , если необходимо
	if (1) crc = crc << 1;
	// Возвращаем инвертированное значение 

	return (unsigned short)(crc);
}

unsigned short rs_pseudo_crc(char* data, int data_length, unsigned int src_addr,  //for UDP and TCP
	unsigned int dst_addr, int packet_length, unsigned char proto)
{
	char* buffer;
	unsigned int full_length;
	unsigned char header_length;
	struct pseudo_header ph;
	unsigned short p_crc = 0;

	// Заполнение структуры псевдозаголовка 
	ph.src_addr = src_addr;
	ph.dst_addr = dst_addr;
	ph.zero = 0;
	ph.proto = proto;
	ph.length = htons(packet_length);
	header_length = sizeof(struct pseudo_header);
	full_length = header_length + data_length;
	buffer = (char*)calloc(full_length, sizeof(char));

	// Генерация псевдозаголовка 
	memcpy(buffer, &ph, header_length);
	memcpy(buffer + header_length, data, data_length);

	// Вычисление CRC. 
	p_crc = rs_crc((unsigned short*)buffer, full_length);
	free(buffer);
	return p_crc;
}

//int rs_send_ip(SOCKET from, struct ip_header iph, unsigned char* data,
//	int data_length, unsigned short dst_port_raw)
//{
//	char* buffer;
//	int result;
//	SOCKADDR_IN target;
//	unsigned char header_length;
//	unsigned int packet_length;
//	memset(&target, 0, sizeof(target));
//	target.sin_family = AF_INET;
//	target.sin_addr.s_addr = iph.dst_addr;
//	target.sin_port = dst_port_raw;
//
//	// Вычисление длины и заголовка пакета 
//	header_length = sizeof(struct ip_header);
//	packet_length = header_length + data_length;
//	// Установка CRC. 
//	iph.crc = 0;
//	// Заполнение некоторых полей заголовка IP . 
//	iph.version = header_length / 4 + (unsigned char)atoi("4") * 16;
//
//	// Если длина пакета не задана , то 
//	//длина пакета приравнивается к длине заголовка 
//	if (!iph.length) iph.length = htons(packet_length);
//	buffer = (char*)calloc(packet_length, sizeof(char));
//
//	// Копирование заголовка пакета в буфер ( CRC равно 0). 
//	memcpy(buffer, &iph, sizeof(struct ip_header));
//	// Копирование данных в буфер 
//	if (data) memcpy(buffer + header_length, data, data_length);
//	// Вычисление CRC. 
//	iph.crc = rs_crc((unsigned short*)buffer, packet_length);
//	// Копирование заголовка пакета в буфер ( CRC посчитана). 
//	memcpy(buffer, &iph, sizeof(struct ip_header));
//	// Отправка IP пакета в сеть.
//	result = sendto(from, buffer, packet_length, 0, (struct sockaddr*)
//		&target, sizeof(target));
//	free(buffer);
//	return result;
//}

//int rs_send_tcp(SOCKET from, struct ip_header iph, struct tcp_header tcph,
//	unsigned char* data, int data_length)
//{
//	char* buffer;
//	int result;
//	unsigned char header_length;
//	unsigned int packet_length;
//
//	// вычисление длин пакета и заголовка.
//	header_length = sizeof(struct tcp_header);
//	packet_length = header_length + data_length;
//	// Установка CRC. 
//	tcph.crc = 0;
//	// Установка поля offset .
//	tcph.offset = (header_length / 4) << 4;
//	buffer = (char*)calloc(packet_length, sizeof(char));
//	// Копирование заголовка пакета в буфер ( CRC равно 0). 
//	memcpy(buffer, &tcph, sizeof(struct tcp_header));
//	// Копирование протокола более высокого уровня (данных) 
//	if (data) memcpy(buffer + header_length, data, data_length);
//	// Вычисление CRC. 
//	tcph.crc = rs_pseudo_crc(buffer, packet_length, iph.src_addr,
//		iph.dst_addr, packet_length, IPPROTO_TCP);
//	// Копирование заголовка пакета в буфер ( CRC посчитано). 
//	memcpy(buffer, &tcph, sizeof(struct tcp_header));
//	// Посылка IP пакета (в качестве данных передан заголовок TCP ) 
//	result = rs_send_ip(from, iph, buffer, packet_length, tcph.dst_port);
//	free(buffer);
//	return result;
//}

//int rs_send_udp(SOCKET from, struct ip_header iph, struct udp_header udph,
//	unsigned char* data, int data_length)
//{
//	char* buffer;
//	int result;
//	unsigned char header_length;
//	unsigned int packet_length;
//	//вычисление длин пакета и заголовка. 
//	header_length = sizeof(struct udp_header);
//	packet_length = header_length + data_length;
//	// Установка CRC. 
//	udph.crc = 0;
//	// Если длина пакета не задана , то
//	//длина пакета приравнивается к длине заголовка
//	if (!udph.length) udph.length = htons(packet_length);
//	buffer = (char*)calloc(packet_length, sizeof(char));
//	// Копирование заголовка пакета в буфер ( CRC равно 0). 
//	memcpy(buffer, &udph, sizeof(struct udp_header));
//	// Копирование протокола более высокого уровня (данных) 
//	if (data) memcpy(buffer + header_length, data, data_length);
//	// Вычисление CRC. 
//	udph.crc = rs_pseudo_crc(buffer, packet_length, iph.src_addr,
//		iph.dst_addr, packet_length, IPPROTO_UDP);
//	// Копирование заголовка пакета в буфер ( CRC посчитана). 
//	memcpy(buffer, &udph, sizeof(struct udp_header));
//	// Отправка IP пакета со вложенным UDP пакетом. 
//	result = rs_send_ip(from, iph, buffer, packet_length, udph.dst_port);
//	free(buffer);
//	return result;
//}

//int rs_send_icmp(SOCKET from, SOCKET to, struct ip_header iph, struct icmp_header icmph,
//	unsigned char* data, int data_length)
//{
//	char* buffer;
//	int result;
//	unsigned char header_length;
//	unsigned int packet_length;
//	data_length = 0;
//	// вычисление длин пакета и заголовка.
//	header_length = sizeof(struct icmp_header);
//	packet_length = header_length + data_length;
//	icmph.crc = 0;
//	buffer = (char*)calloc(packet_length, sizeof(char));
//	// Копирование заголовка пакета в буфер ( CRC равно 0).
//	memcpy(buffer, &icmph, sizeof(struct icmp_header));
//	// Вычисление CRC.
//	icmph.crc = rs_crc((unsigned short*)buffer, packet_length);
//	// Копирование заголовка пакета в буфер ( CRC посчитана). 
//	memcpy(buffer, &icmph, sizeof(struct icmp_header));
//	// Отправка IP пакета со вложенным ICMP пакетом.
//	result = rs_send_ip(from, iph, buffer, packet_length, 0);
//	free(buffer);
//	return result;
//}

SOCKET exchange(int port, char* addr, char* proto)
{
	WSADATA ws;
	if (WSAStartup(MAKEWORD(2, 2), &ws) != 0) {
		printf("%s\n", "Error");
		exit(1);
	}

	SOCKET sock = INVALID_SOCKET;

	/*if (proto == "tcp")
	{*/
	if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == SOCKET_ERROR)
	{
		printf("Creation of raw socket failed.");
		exit(1);
	}

	//}
	/*else if (proto == "udp") {
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	}
	else if (proto == "icmp") {
		sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	}*/

	//int optval = 1;
	//if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof optval) == SOCKET_ERROR)
	//{
	//	printf("%s\n", "Socket set opts Error");
	//	exit(1);
	//}//Set it to include the header

	if (sock == INVALID_SOCKET)
	{
		printf("%s\n", "Socket initialize Error");
		exit(1);
	}

	/*if (connect(sock, &sa, sizeof(sa)) != 0)
	{
		printf("%s\n", "Connection Error");
		exit(1);
	}*/

	return sock;
}


int close_sock(SOCKET sock) {
	closesocket(sock);
	return 0;
}

int send_data(SOCKET sock, void* send_data, int sz) {
	send(sock, send_data, sz, 0);
	return 0;
}

int client_listen(SOCKET sock) {
	//listen(sock, 100);

	char buf[1000];
	memset(buf, 0, sizeof(buf));
	recv(sock, buf, sizeof(buf), 0);
	printf(buf);

	/*SOCKET client_socket;
	SOCKADDR_IN client_addr;
	int client_addr_size = sizeof(client_addr);*/

	/*while (client_socket = accept(sock, &client_addr, &client_addr_size)) {
		while (recv(client_socket, buf, sizeof(buf), 0) > 0)
		{
			for (int i = 0; i < 20; i++) {
				printf("%d\n", buf[i]);
			}
		}
	}*/
	return 0;
}

int main(void) {
	char buf[1000], *data = NULL, source_ip[20];
	int payload = 512;

	SOCKET try_hard = exchange(53, "8.8.8.8", "tcp"); //192.168.234.172 //5.45.192.0 pp: 18 //htons(443), "8.8.8.8"

	IPV4_HDR* v4hdr = NULL;
	TCP_HDR* tcphdr = NULL;

	SOCKADDR_IN sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(53);
	sa.sin_addr.S_un.S_addr = inet_addr("8.8.8.8");

	if (connect(try_hard, &sa, sizeof(sa)) != 0)
	{
		printf("%s\n", "Connection Error");
		exit(1);
	}

	v4hdr = (IPV4_HDR*)buf; //lets point to the ip header portion
	v4hdr->ip_version = 4;
	v4hdr->ip_header_len = 5;
	v4hdr->ip_tos = 0;
	v4hdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(TCP_HDR) + payload);
	v4hdr->ip_id = htons(2);
	v4hdr->ip_frag_offset = 0;
	v4hdr->ip_frag_offset1 = 0;
	v4hdr->ip_reserved_zero = 0;
	v4hdr->ip_dont_fragment = 1;
	v4hdr->ip_more_fragment = 0;
	v4hdr->ip_ttl = 8;
	v4hdr->ip_protocol = IPPROTO_TCP;
	v4hdr->ip_srcaddr = inet_addr("192.168.232.133");
	v4hdr->ip_destaddr = inet_addr("8.8.8.8"); //inet_ntoa
	v4hdr->ip_checksum = 0;

	tcphdr = (TCP_HDR*)&buf[sizeof(IPV4_HDR)]; //get the pointer to the tcp header in the packet

	tcphdr->source_port = htons(1234);
	tcphdr->dest_port = htons(53);

	tcphdr->cwr = 0;
	tcphdr->ecn = 1;
	tcphdr->urg = 0;
	tcphdr->ack = 0;
	tcphdr->psh = 0;
	tcphdr->rst = 1;
	tcphdr->syn = 0;
	tcphdr->fin = 0;
	tcphdr->ns = 1;

	tcphdr->checksum = 0;

	// Initialize the TCP payload to some rubbish
	data = &buf[sizeof(IPV4_HDR) + sizeof(TCP_HDR)];
	memset(data, '^', payload);
	if (sendto(try_hard, buf, sizeof(IPV4_HDR) + sizeof(TCP_HDR) + payload, 0, (SOCKADDR*)&sa, sizeof(sa)) == SOCKET_ERROR)
	{
		printf("Error sending Packet : %d", WSAGetLastError());
		exit(1);
	}
	else {
		printf("%s", "bobercurwa");
	}
	//int bebra = rs_send_tcp(try_hard, ip_test, tcp_test, arr, sizeof(arr));
	//printf("%i", bebra);

		//crc, version, len, потом в функцию можно будет ничего не передавать, т.к. будут базовые значения
		//которые будут наполнять структуру, чтобы программа работала, или создать функцию set_std_values
	client_listen(main);
	/*send_data(main, arr, size);
	close_sock(main);*/
	WSACleanup();
	return 0;
}



//struct ip_header
//{
//	unsigned char   version; // номер версии протокола 
//	unsigned char   tos;     // тип сервиса 
//	unsigned short  length;  // общая длина пакета 
//	unsigned short  id;     // идентификатор пакета
//	unsigned short  flags;  // флаги 
//	unsigned char   ttl;   // Время жизни пакета 
//	unsigned char   proto;  // Протокол верхнего уровня 
//	unsigned short  crc;    // CRC заголовка 
//	unsigned int    src_addr; // IP- адрес отправителя 
//	unsigned int    dst_addr; // IP- адрес получателя 
//};
//
//struct tcp_header
//{
//	unsigned short   src_port;   // порт отправителя
//	unsigned short   dst_port;   // порт получателя 
//	unsigned int     seq_n;      // номер очереди 
//	unsigned int     ack_n;   // номер подтверждения 
//	unsigned char    offset;     // смещение 
//	unsigned char    flags;      // флаги 
//	unsigned short   win;        // окно 
//	unsigned short   crc;       // контрольная сумма заголовка 
//	unsigned short   urg_ptr; // указатель срочности 
//};