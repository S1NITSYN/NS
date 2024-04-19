#pragma once
#define HAVE_REMOTE
#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

#define IP_RESERVED_ZERO    0x8000  //
#define IP_DONT_FRAGMENT    0x4000 //
#define IP_MORE_FRAGMENT    0x2000//
#define TCP_DEFAULT_LEN     0x50//
#define IP_PROTO            0x0800
#define MAC_SIZE            6
#define STD_IP_VERLEN       0x45


#define PKT_GET_ETH_HDR(p)        \
    ((struct eth_header *)(p))
#define PKT_GET_IP_HDR(p)       \
    ((struct ip_header *) (((UINT8 *)(p)) + sizeof(struct eth_header)))
#define PKT_GET_TCP_HDR(p)       \
    ((struct tcp_header *) ((UINT8 *)(PKT_GET_IP_HDR(p)) + sizeof(struct ip_header)))
#define PKT_GET_UDP_HDR(p)       \
    ((struct udp_header *) ((UINT8 *)(PKT_GET_IP_HDR(p)) + sizeof(struct ip_header)))
#define PKT_GET_TCP_DATA(p)       \
    ((UINT8 *)(PKT_GET_TCP_HDR(p)) + sizeof(struct tcp_header))
#define PKT_GET_UDP_DATA(p)       \
    ((UINT8 *)(PKT_GET_UDP_HDR(p)) + sizeof(struct udp_header))
#define PKT_GET_UDP_DNS_DATA(p)     \
    ((UINT8 *)(PKT_GET_UDP_DATA(p)) + sizeof(struct dns_header))

struct eth_header {
    UINT8  h_dest[6];   /* destination eth addr */
    UINT8 h_source[6]; /* source ether addr    */
    UINT16 h_proto;            /* packet type ID field */
};

struct ip_header {
    UINT8  ip_ver_len;     /* version and header length */

#define GET_IP_VERSION(ver_len)     (fl >> 4) & 0xF
#define GET_IP_VERSION(ver_len)     (fl & 0xF)

    UINT8  ip_tos;         /* type of service */
    UINT16 ip_len;         /* total length */
    UINT16 ip_id;          /* identification */
    UINT16 ip_off;         /* fragment offset field */

#define GET_IP_NO_FRAG(fl)          (fl >> 14)
#define GET_IP_HAVE_FRAGS(fl)       (fl >> 13)

    UINT8  ip_ttl;         /* time to live */
    UINT8  ip_p;           /* protocol */
    UINT16 ip_sum;         /* checksum */
    UINT32 ip_src, ip_dst; /* source and destination address */
};

struct tcp_header {
    UINT16 th_sport;          /* source port */
    UINT16 th_dport;          /* destination port */
    UINT32 th_seq;            /* sequence number */
    UINT32 th_ack;            /* acknowledgment number */
    UINT16 th_offset_flags;   /* data offset, reserved 6 bits, */

#define GET_TH_FIN(fl)              (fl >> 0)
#define GET_TH_SYN(fl)              (fl >> 1)
#define GET_TH_RST(fl)              (fl >> 2)
#define GET_TH_PUSH(fl)             (fl >> 3)
#define GET_TH_ACK(fl)              (fl >> 4)
#define GET_TH_URG(fl)              (fl >> 5)
#define GET_TH_ECE(fl)              (fl >> 6)
#define GET_TH_CWR(fl)              (fl >> 7)
#define GET_TH_NS(fl)               (fl >> 8)
#define GET_TH_FLAGS(fl)            (0x7FF & fl)

#define GET_TH_OFF(fl)              (fl >> 11)

    UINT16 th_win;            /* window */
    UINT16 th_sum;            /* checksum */
    UINT16 th_urp;            /* urgent pointer */
};

struct pseudo_header
{
    UINT32 src_addr; // адрес отправителя 
    UINT32 dst_addr; // адрес получателя 
    UINT8 zero; //начальная установка 
    UINT8 proto; // протокол
    UINT16 length; // длина заголовка 
};

struct udp_header
{
    UINT16   udp_sport; // номер порта отправителя 
    UINT16   udp_dport; // номер порта получателя 
    UINT16   udp_length; // длина датаграммы 
    UINT16   udp_sum;   // контрольная сумма заголовка
};

struct icmp_header
{
    UINT8   type; // тип ICMP- пакета
    UINT8   code; // код ICMP- пакета 
    UINT16  crc; // контрольная сумма 
    UINT32  orig_timestamp; // дополнительные поля 
    UINT32  recv_timestamp; // уточняющие тип 
    UINT32  trns_timestamp; //ICMP- пакета
};

struct dns_header
{
    UINT16  id;
    UINT16  flags;

#define GET_DNS_QR(fl)              (fl >> 15)
#define GET_DNS_OPCODE(fl)          (fl >> 11)
#define GET_DNS_AA(fl)              (fl >> 10)
#define GET_DNS_TC(fl)              (fl >> 9)
#define GET_DNS_RD(fl)              (fl >> 8)
#define GET_DNS_RA(fl)              (fl >> 7)

#define GET_DNS_RD(fl)              (fl >> 8)
#define GET_DNS_QR(fl)              (fl >> 0)

    UINT16  qdcount;
    UINT16  ancount;
    UINT16  nscount;
    UINT16  arcount;
};

struct dns_question
{
    UINT16  qtype;
    UINT16  qclass;
};

struct dns_query
{
    UINT8* name;
    struct dns_question* ques;
};

struct dns_response
{
    UINT16  qname;
    UINT16  type;
    UINT16  class;
    UINT32  ttl;
    UINT16  rdlength;
};

struct dns_resp_query
{
    UINT8* name;
    struct dns_response* ques;
};

struct ip_packet
{
    struct eth_header eth_h_ex;
    struct ip_header ip_h_ex;
};

struct udp_packet
{
    struct ip_packet ip_p_ex;
    struct udp_header udp_h_ex;
};

struct tcp_packet
{
    struct ip_packet ip_p_ex;
    struct tcp_header tcp_h_ex;
};

//struct  eth_header* create_eth_header(UINT8*  h_dest, UINT8* h_source, UINT16 h_proto);
//
//struct  ip_header* create_ip_header(
//    UINT16 h_proto,
//    UINT8  ip_ver_len,
//    UINT8  ip_tos,        
//    UINT16 ip_len,        
//    UINT16 ip_id,          
//    UINT16 ip_off,
//    UINT8  ip_ttl,
//    UINT8  ip_p,
//    UINT16 ip_sum, 
//    UINT32 ip_src, 
//    UINT32 ip_dst);
//
//
//
//struct ip_packet* create_ip_packet(struct eth_header e, struct ip_header ip)
//{
//    struct   ip_packet packet;
//
//    packet.eth_h_ex = e;
//    packet.ip_h_ex = ip;
//    
//    return packet;
//}