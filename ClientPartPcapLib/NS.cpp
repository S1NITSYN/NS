#define HAVE_REMOTE
#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include "Headers.h"
#include "getopt.h"
//alternative name ClientPartPcapLib
#pragma comment (lib, "Ws2_32.lib")
#pragma warning(disable : 4996)

UINT16 IpCheckSum(UINT16* buffer, UINT32 size)
{
    unsigned long cksum = 0;
    while (size > 1)
    {
        cksum += *buffer++;
        size -= sizeof(UINT16);
    }
    if (size == 1)
        cksum += *(UINT8*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (UINT16)(~cksum);
}

struct pseudo_header* fill_pseudo_header(struct ip_header* iph, int proto_type,int size_of_header,UINT32 size)
{
    struct pseudo_header psd_header;
    
    psd_header.dst_addr = iph->ip_dst;
    psd_header.src_addr = iph->ip_src;
    psd_header.zero = 0;
    psd_header.proto = proto_type;
    psd_header.length = htons(size_of_header + size);
    
    return &psd_header;
}


/*
    I dont like these 3 functions.
    They're closest copies of each other
    exept main struct type
    Need to fox it
*/
UINT16 TcpCheckSum(struct ip_header* iph, struct tcp_header* tcph, UINT8* data, UINT32 size)
{
    tcph->th_sum = 0;
    
    struct pseudo_header* header = fill_pseudo_header(iph, IPPROTO_TCP, sizeof(struct tcp_header), size);

    UINT8 tcpBuf[65536];
    memcpy(tcpBuf, header, sizeof(struct pseudo_header));
    memcpy(tcpBuf + sizeof(struct pseudo_header), tcph, sizeof(struct tcp_header));
    memcpy(tcpBuf + sizeof(struct pseudo_header) + sizeof(struct tcp_header), data, size);
   
    return tcph->th_sum = IpCheckSum(tcpBuf,
        sizeof(struct pseudo_header) + sizeof(struct tcp_header) + size);
}

UINT16 UdpCheckSum(struct ip_header* iph, struct udp_header* udph, UINT8* data, UINT32 size) //refactor this with previous function
{
    udph->udp_sum = 0;

    struct pseudo_header* header = fill_pseudo_header(iph, IPPROTO_UDP, sizeof(struct udp_header), size);

    UINT8 tcpBuf[65536];
    memcpy(tcpBuf,  header, sizeof(struct pseudo_header));
    memcpy(tcpBuf + sizeof(struct pseudo_header), udph, sizeof(struct udp_header));
    memcpy(tcpBuf + sizeof(struct pseudo_header) + sizeof(struct udp_header), data, size);

    return udph->udp_sum = IpCheckSum(tcpBuf,
        sizeof(struct pseudo_header) + sizeof(struct udp_header) + size);
}

UINT16 IcmpCheckSum(struct ip_header* iph, struct icmp_header* icmph, UINT8* data, UINT32 size)
{
    icmph->crc = 0;

    UINT8 icmpBuf[65536];
    memcpy(icmpBuf, icmph, sizeof(struct icmp_header));
    memcpy(icmpBuf+ sizeof(struct icmp_header), data, size);

    return icmph->crc = IpCheckSum(icmpBuf, + sizeof(struct icmp_header) + size);
}

UINT16 TcpUdpCheckSum(struct ip_header* iph, UINT8* hdr, UINT8* data, UINT32 size, UINT32 proto)
{
    struct pseudo_header psd_header;
    psd_header.dst_addr = iph->ip_dst;
    psd_header.src_addr = iph->ip_src;
    psd_header.zero = 0;
    psd_header.proto = proto;

    UINT8 tcpBuf[65536];
    memcpy(tcpBuf, &psd_header, sizeof(struct pseudo_header));

    switch (proto)
    {
    case IPPROTO_TCP:
        struct tcp_header* tcph = hdr;
        tcph->th_sum = 0;
        psd_header.length = htons(sizeof(struct udp_header) + size);

        memcpy(tcpBuf + sizeof(struct pseudo_header), tcph, sizeof(struct tcp_header));
        memcpy(tcpBuf + sizeof(struct pseudo_header) + sizeof(struct tcp_header), data, size);

        return tcph->th_sum = IpCheckSum(tcpBuf,
            sizeof(struct pseudo_header) + sizeof(struct tcp_header) + size);
    case IPPROTO_UDP:
        struct udp_header* udph = hdr;
        udph->udp_sum = 0;
        psd_header.length = htons(sizeof(struct udp_header) + size);

        memcpy(tcpBuf + sizeof(struct pseudo_header), udph, sizeof(struct udp_header));
        memcpy(tcpBuf + sizeof(struct pseudo_header) + sizeof(struct udp_header), data, size);

        return udph->udp_sum = IpCheckSum(tcpBuf,
            sizeof(struct pseudo_header) + sizeof(struct udp_header) + size);
    case IPPROTO_ICMP:
        return 0;
    default:
        return 0;
    }
} //под вопросом

struct eth_header* create_ethernet_header(UINT8* mac_dst, UINT8* mac_src)
{
    struct eth_header* mac_hdr_ex = calloc(sizeof(struct eth_header), sizeof(UINT8));

    memcpy(mac_hdr_ex->h_dest, mac_dst, MAC_SIZE);
    memcpy(mac_hdr_ex->h_source, mac_src, MAC_SIZE);
    mac_hdr_ex->h_proto = htons(IP_PROTO);
    return mac_hdr_ex;
}

struct ip_header* create_ip_header(UINT8 tos, UINT16 ip_id,
    UINT16 offset, UINT8 ttl, UINT32 ip_p, UINT8* ip_src, UINT8* ip_dst)
{
    struct ip_header* ip4_header_ex = calloc(sizeof(struct ip_header), sizeof(UINT8));

    ip4_header_ex->ip_ver_len = STD_IP_VERLEN;
    ip4_header_ex->ip_tos = tos;
    ip4_header_ex->ip_len = 0;//htons(sizeof(struct ip_header) + sizeof(struct tcp_header) + datalen);
    ip4_header_ex->ip_id = htons(ip_id);
    ip4_header_ex->ip_off = htons(offset);
    /*ip4_header_ex->ip_reserved_zero = 0;
    ip4_header_ex->ip_dont_fragment = 1;
    ip4_header_ex->ip_more_fragment = 0;*/
    ip4_header_ex->ip_ttl = ttl;
    ip4_header_ex->ip_p = ip_p;
    ip4_header_ex->ip_sum = 0; //func that calculate ip chksum
    ip4_header_ex->ip_src = inet_addr(ip_src);
    ip4_header_ex->ip_dst = inet_addr(ip_dst); //inet_ntoa

    return ip4_header_ex;
}

struct tcp_header* create_tcp_header(UINT16 th_sport, UINT16 th_dport, UINT32 th_seq, UINT32 th_ack, //будет версия для консоли и веб, в веб сделать прием флагов массивом,
                      UINT16 th_win, UINT16 th_urp, UINT32* flags)                                   //тут сделать установку флагов поэлементно (пока что)
{
    struct tcp_header* tcp_header_ex = calloc(sizeof(struct tcp_header), sizeof(UINT8));;

    tcp_header_ex->th_sport = htons(th_sport);
    tcp_header_ex->th_dport = htons(th_dport);
    tcp_header_ex->th_ack = htonl(th_ack);
    tcp_header_ex->th_seq = htonl(th_seq);
    tcp_header_ex->th_offset_flags = TCP_DEFAULT_LEN; //
    //tcp_header_ex->th_offset_flags |=  htons();
    tcp_header_ex->th_win = htons(th_ack);
    tcp_header_ex->th_sum = 0; //func that calculate tcp chksum
    tcp_header_ex->th_urp = th_urp;

    for (int i = 0; i < 9; i++) {
        if (flags[i] == 1) {
            tcp_header_ex->th_offset_flags |= htons(1 << i);
        }
    }
    return tcp_header_ex;
}

struct udp_header* create_udp_header(UINT16 udp_sport, UINT16 udp_dport)
{
    struct udp_header* udp_header_ex = calloc(sizeof(struct udp_header), sizeof(UINT8));

    udp_header_ex->udp_sport = htons(udp_sport);
    udp_header_ex->udp_dport = htons(udp_dport);

    return udp_header_ex;
}

struct icmp_header* create_icmp_header(UINT8 type, UINT8 code, UINT16 identifier/*, UINT8* payload*/)
{
    struct icmp_header* icmp_header_ex = calloc(sizeof(struct icmp_header), sizeof(UINT8));

    icmp_header_ex->type = type;
    icmp_header_ex->code = code;
    icmp_header_ex->identifier = htons(identifier);
    icmp_header_ex->seq_num = 0;

    return icmp_header_ex;
}

//takes only default markers
UINT8* domain_name_to_dns_format(UINT8* dns, UINT8* host)
{
    UINT8* dst = (UINT8*)dns
        , * src = (UINT8*)host
        , * tick;

    for (tick = dst++; *dst = *src++; dst++) {
        if (*dst == '.') { *tick = (dst - tick - 1); tick = dst; }
    }
    *tick = (dst - tick - 1);
}

UINT8* create_dns_header(UINT16 id, UINT16 flags, UINT16 qdcount, UINT8* qname, UINT16 qtype, UINT16 qclass)
{
    UINT8* buf = calloc(1000, sizeof(UINT8));
    struct dns_header* dns_header_ex = (struct dns_header *)buf;

    dns_header_ex->id = htons(id);
    dns_header_ex->flags = htons(flags);
    dns_header_ex->qdcount = htons(qdcount);

    UINT8* name = buf + sizeof(struct dns_header);
    memcpy(name, qname, strlen(qname));

    struct dns_question* qinfo = buf + sizeof(struct dns_header) + strlen(name) + sizeof(UINT8);
    qinfo->qtype = htons(qtype);
    qinfo->qclass = htons(qclass);

    return buf;
} /////

UINT8* create_tcp_packet(struct eth_header* eth_filled_ex, struct ip_header* ip_filled_ex, struct tcp_header* tcp_ex, UINT8* data, UINT32 size_of_data)
{
    UINT8* buf = (UINT8*)calloc(1000, sizeof(UINT8));
    struct eth_header* eth_empty_ex = PKT_GET_ETH_HDR(buf);
    *eth_empty_ex = *eth_filled_ex;
    struct ip_header* ip4_empty_ex = PKT_GET_IP_HDR(buf);
    *ip4_empty_ex = *ip_filled_ex;
    struct tcp_header* tcp_empty_ex = PKT_GET_TCP_HDR(buf);
    *tcp_empty_ex = *tcp_ex;
    UINT8* data_empty = PKT_GET_TCP_DATA(buf);
    memcpy(data_empty, data, size_of_data);

    ip4_empty_ex->ip_len = htons(sizeof(struct ip_header) + sizeof(struct tcp_header) + size_of_data);
    ip4_empty_ex->ip_sum = IpCheckSum(ip4_empty_ex, sizeof(struct ip_header));
    tcp_empty_ex->th_sum = TcpCheckSum(ip4_empty_ex, tcp_empty_ex, data, size_of_data);

    return buf;
}

UINT8* create_udp_packet(struct eth_header* eth_filled_ex, struct ip_header* ip_filled_ex, struct udp_header* udp_ex, UINT8* data, UINT32 size_of_data)
{
    UINT8* buf = (UINT8*)calloc(1000, sizeof(UINT8));
    struct eth_header* eth_empty_ex = PKT_GET_ETH_HDR(buf);
    *eth_empty_ex = *eth_filled_ex;
    struct ip_header* ip4_empty_ex = PKT_GET_IP_HDR(buf);
    *ip4_empty_ex = *ip_filled_ex;
    struct udp_header* udp_empty_ex = PKT_GET_UDP_HDR(buf);
    *udp_empty_ex = *udp_ex;
    UINT8* data_empty = PKT_GET_UDP_DATA(buf);
    memcpy(data_empty, data, size_of_data);

    udp_empty_ex->udp_length = htons(sizeof(struct udp_header) + size_of_data);
    ip4_empty_ex->ip_len = htons(sizeof(struct ip_header) + sizeof(struct udp_header) + size_of_data);
    ip4_empty_ex->ip_sum = IpCheckSum(ip4_empty_ex, sizeof(struct ip_header));
    udp_empty_ex->udp_sum = UdpCheckSum(ip4_empty_ex, udp_empty_ex, data, size_of_data);

    return buf;
}

UINT8* create_icmp_packet(struct eth_header* eth_filled_ex, struct ip_header* ip_filled_ex, struct icmp_header* icmp_filled_ex, UINT8 * data, UINT32 size_of_data)
{
    UINT8* buf = (UINT8*)calloc(1000, sizeof(UINT8));
    struct eth_header* eth_empty_ex = PKT_GET_ETH_HDR(buf);
    *eth_empty_ex = *eth_filled_ex;
    struct ip_header* ip4_empty_ex = PKT_GET_IP_HDR(buf);
    *ip4_empty_ex = *ip_filled_ex;
    struct icmp_header* icmp_empty_ex = PKT_GET_ICMP_HDR(buf);
    *icmp_empty_ex = *icmp_filled_ex;
    UINT8* data_empty = PKT_GET_ICMP_DATA(buf);
    memcpy(data_empty, data, size_of_data);

    ip4_empty_ex->ip_len = htons(sizeof(struct ip_header) + sizeof(struct icmp_header) + size_of_data);
    ip4_empty_ex->ip_sum = IpCheckSum(ip4_empty_ex, sizeof(struct ip_header));
    icmp_empty_ex->crc = IcmpCheckSum(ip4_empty_ex, icmp_empty_ex, data, size_of_data);

    return buf;
}

//char* packet_fill_poor(unsigned char* mac_dst, unsigned char* mac_src, char* ip_src, char* ip_dst)
//{
//    return packet_fill(mac_dst, mac_src, 0, 0, 0, 0, ip_src, ip_dst, 0, 0, 0, 0, 0, 0, 0, 0);
//}
//
//char* packet_fill_fin_ack(unsigned char* mac_dst, unsigned char* mac_src, char* ip_src, char* ip_dst)
//{
//    return packet_fill(mac_dst, mac_src, 0, 0, 0, 0, ip_src, ip_dst, 0, 0, 0, 0, 0, 0, 0, 0);
//}
//
//char* useful_data_fill() {
//
//}

pcap_t* device_init(UINT8*device_name) {
    pcap_t* fp;
    UINT8 errbuf[PCAP_ERRBUF_SIZE];

    /* Check the validity of the command line */

    /* Open the output device */
    if ((fp = pcap_open(device_name,            // "rpcap://\\Device\\NPF_{6CD6BAA2-436D-4D3A-8639-BB65B246E7F9}"
        sizeof(sizeof(struct eth_header) + sizeof(struct ip_header) + sizeof(struct tcp_header)),    //            // portion of the packet to capture (only the first 100 bytes)
        PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
        1000,               // read timeout
        NULL,               // authentication on the remote machine
        errbuf              // error buffer
    )) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
        return;
    }
    /*fp = pcap_lookupdev(errbuf);
    if (fp == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return;
    }
    printf(fp);*/
    return fp;
}

void my_callback(UINT8* handle, struct pcap_pkthdr* pkthdr, UINT8* packet)
{
    struct eth_header* eth_hdr = PKT_GET_ETH_HDR(packet);
    struct ip_header* ip_hdr = PKT_GET_IP_HDR(packet);
    struct tcp_header* tcp_hdr = PKT_GET_TCP_HDR(packet);
   
    UINT16 flags = ntohs(tcp_hdr->th_offset_flags); 
    
    int own_flags[] = {0, 0, 0, 0, 1, 0, 0, 0, 0};
    UINT8 dst_addr_str[INET_ADDRSTRLEN];
    UINT8 src_addr_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_addr_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_addr_str, INET_ADDRSTRLEN);

    if ((GET_TH_SYN(flags) & 1) && (GET_TH_ACK(flags) & 1)) {
        struct eth_header* eth_ex = create_ethernet_header(eth_hdr->h_source, eth_hdr->h_dest);
        struct ip_header* ip_ex = create_ip_header(ntohl(ip_hdr->ip_tos), ntohl(ip_hdr->ip_id), ntohs(ip_hdr->ip_off), ip_hdr->ip_ttl,
                                                IPPROTO_TCP, dst_addr_str, src_addr_str);
        struct tcp_header* tcp_ex = create_tcp_header(ntohs(tcp_hdr->th_dport), ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_seq) + 1,
            ntohl(tcp_hdr->th_ack), ntohs(tcp_hdr->th_win), ntohs(tcp_hdr->th_urp), own_flags);
        UINT8* buf = create_tcp_packet(eth_ex, ip_ex, tcp_ex, "", 0);

        if (pcap_sendpacket(handle, buf, sizeof(struct eth_header) + sizeof(struct ip_header) + sizeof(struct tcp_header)/* size */) != 0)
        {
            fprintf(stderr, "\nError sending the packet\n"); //add error handler
            return;
        }
        return;
    } //need to check id and checksum also))))))
    //if ((GET_TH_FIN(flags) == 1) && (GET_TH_ACK(flags) == 1)) {
    //    char* buf = packet_fill(eth_hdr->h_source, eth_hdr->h_dest, ntohl(ip_hdr->ip_tos), ntohl(ip_hdr->ip_id), ntohs(ip_hdr->ip_off), ip_hdr->ip_ttl,
    //        "192.168.232.133", "77.88.55.242", tcp_hdr->th_dport, ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_seq) + 1, ntohl(tcp_hdr->th_ack), ntohs(tcp_hdr->th_win), ntohs(tcp_hdr->th_urp), own_flags, "");
    //    if (pcap_sendpacket(handle, buf, sizeof(struct eth_header) + sizeof(struct ip_header) + sizeof(struct tcp_header)/* size */) != 0)
    //    {
    //        fprintf(stderr, "\nError sending the packet\n"); //add error handler
    //        return;
    //    }
    //    return;
    //}
    //if (GET_TH_ACK(flags) == 1) {
    //    return;
    //}
}//here is json maybe?))

UINT8* capture_packet(UINT8* device_name, UINT8* filter, UINT8* ip) {
    pcap_t* handle;  /* Дескриптор сессии */
    UINT8* dev = device_name;  /* Устройство для сниффинга */
    UINT8 errbuf[PCAP_ERRBUF_SIZE]; /* Строка для хранения ошибок */
    struct bpf_program fp;  /* Скомпилированный фильтр */
    UINT8* filter_exp = filter;//"port 1234"; /* Выражение фильтра */
    bpf_u_int32 mask;  /* Сетевая маска устройства */
    bpf_u_int32 net = ntohl(inet_addr(ip));  /* IP устройства */
    //printf("%x\n", net);
    struct pcap_pkthdr header; /* Заголовок который нам дает PCAP */
    const UINT8* packet;  /* Пакет */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    //pcap_set_timeout(handle, 3000); how its actually work

    packet = pcap_dispatch(handle, 5, my_callback, handle);
    pcap_close(handle);

    return 0;
}

UINT8* capture_solo_packet(UINT8* device_name, UINT8* filter, UINT8* ip, UINT32* size) {
    pcap_t* handle;  /* Дескриптор сессии */
    UINT8*dev = device_name;  /* Устройство для сниффинга */
    UINT8 errbuf[PCAP_ERRBUF_SIZE]; /* Строка для хранения ошибок */
    struct bpf_program fp;  /* Скомпилированный фильтр */
    UINT8*filter_exp = filter;//"port 1234"; /* Выражение фильтра */
    bpf_u_int32 mask;  /* Сетевая маска устройства */
    bpf_u_int32 net = ip;  /* IP устройства */
    struct pcap_pkthdr header; /* Заголовок который нам дает PCAP */
    const u_char* packet;  /* Пакет */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    //pcap_set_timeout(handle, 3000);//

    packet = pcap_next(handle, &header);
    /* Вывод его длины */
    //printf("Jacked a packet with length of [%d]\n", header.len);
    *size = header.len;

    /* Закрытие сессии */
    pcap_close(handle);

    return packet;
}

void packet_print(UINT8* buf, int size)
{
    for (int i = 1; i < size + 1; i++) {
        printf("%02X ", buf[i - 1]);
        if (i % 8 == 0) {
            printf(" ");
        }
        if (i % 16 == 0) {
            printf("\n");
        }
    }
}

static UINT8* manual_information =
"       -manual - manual info\n\n\
        -udp - will be an add-on over ip packet\n\
        params:\n\
            source port - the port from which the packet will be sent\n\
            destination port - the port to which the packet will be sent\n\n\
        //-tcp\n\n\
        -dns - will be an add-on over udp packet\n\
        params:\n\
            Domain/ip - in addiction to opcode using domain to find ip or inversely\n\
            Opcode - query type; 0 - standart, 1 - invers\n\
            //Server status - \n\
            RD - do not return intermediate answers, only ip - the port to which the packet will be sent";


void main(UINT32 argc, UINT8** argv)
{
    setlocale(LC_ALL, "Rus");

    UINT8* dev = "rpcap://\\Device\\NPF_{7C48B9B9-A20D-4319-9391-990FFA7D0016}";

    UINT8* ip_src = "192.168.232.133"; //192.168.198.110 //получать ip устройства в сети с помощью какого-либо API
    UINT8* ip_dst = "208.67.222.222";

    pcap_t* handle = device_init(dev);

    //UINT8 mac_dst[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    UINT8 mac_dst[] = { 0x7c, 0x69, 0xf6 , 0xb3, 0x7d, 0xc7 };
    UINT8 mac_src[] = { 0x20, 0x4e, 0xf6, 0x9a, 0xfd, 0x73 };
    
    int dport = 53;
    int sport = 1234;

    struct eth_header* eth_ex = create_ethernet_header(mac_dst, mac_src);
    struct ip_header* ip_ex = create_ip_header(0, 1, 0, 64, IPPROTO_UDP, ip_src, ip_dst);
    struct udp_header* udp_ex = create_udp_header(sport, dport);

    UINT32 std_len = sizeof(struct eth_header) + sizeof(struct ip_header);


    //char* dns_params[] = {};

    UINT8* formatted_domain = calloc(100, sizeof(UINT8));
    UINT8* unformatted_domain = calloc(100, sizeof(UINT8));

    //UINT8* buf = calloc(4096, UINT8);

    UINT8* buf = create_udp_packet(eth_ex, ip_ex, udp_ex, "", 0);
    int std_length = sizeof(struct eth_header) + sizeof(struct ip_header);
    int length = std_length + sizeof(struct udp_header);

    int res = 0;

    const struct option options[] = { //questions with flag field
        {
            .name = "man",
            .has_arg = no_argument,
            .flag = 0,
            .val = 'm'
        },

        {
            .name = "manual",
            .has_arg = no_argument,
            .flag = 0,
            .val = 'l'
        },

        {
            .name = "udp",
            .has_arg = required_argument,
            .flag = 0,
            .val = 'u'
        },

        {
            .name = "tcp",
            .has_arg = required_argument,
            .flag = 0,
            .val = 't'
        },

        {
            .name = "icmp",
            .has_arg = required_argument, //required_argument
            .flag = 0,
            .val = 'i'
        },

        {
            .name = "dns",
            .has_arg = required_argument,
            .flag = 0,
            .val = 'd'
        },

        { NULL, 0, NULL, 0}
    };
    UINT8 for_ans = 'd';

    while ((res = getopt_long_only(argc, argv, "", options, NULL)) != -1) { //third param - short_opts, 
        for_ans = res;
        switch (res) //стоит добавить опцию ip пакета, где можно менять ip адреса, и другие параметры
        {
        case 'm':
        case 'l':
            printf(manual_information);
            return;

        case 'u':
            UINT8 * ports = strstr(optarg, "dport=");
            if (ports != NULL) {
                int DPORT = 0;
                sscanf(ports, "dport=%u", &DPORT);
                dport = DPORT;
            }
            ports = strstr(optarg, "sport=");
            if (ports != NULL) {
                int SPORT = 0;
                sscanf(ports, "sport=%u", &SPORT);
                sport = SPORT;
            }
            udp_ex = create_udp_header(sport, dport);
            break;

        case 't':

            break;

        case 'd':
            UINT16 type = 1;
            UINT8 name[100];
            UINT8* name_check = strstr(optarg, "name=");
            UINT8* dns_type_check = strstr(optarg, "type=");
            if (name_check != NULL && dns_type_check != NULL) {
                sscanf(name_check, "name=%[^,]", name);
            }
            else if (name_check != NULL) {
                sscanf(name_check, "name=%s", name);
            }
            //else { break; }
            UINT8* dns_type = calloc(100, sizeof(UINT8));
            if (dns_type_check != NULL) {
                sscanf(dns_type_check, "type=%s", dns_type);
                if (strcmp(dns_type, "ptr") == 0) {
                    type = DNS_TYPE_PTR;
                    UINT8 filter[113];
                    snprintf(filter, sizeof(filter), "%s%s", name, ".in-addr.arpa");
                    domain_name_to_dns_format(formatted_domain, filter);
                }
            } else {
                domain_name_to_dns_format(formatted_domain, name);
            }
            UINT8* dns_ex = create_dns_header(0x0001, 0x0100, 0x0001, formatted_domain, type, 0x0001);
            int dns_size = sizeof(struct dns_header) + strlen(formatted_domain) + sizeof(UINT8) + sizeof(struct dns_question);
            buf = create_udp_packet(eth_ex, ip_ex, udp_ex, dns_ex, dns_size);
            length = std_length + sizeof(struct udp_header) + dns_size;

            break;

        case 'i':
            ip_ex->ip_p = IPPROTO_ICMP;

            UINT8* ip_dst = calloc(20, sizeof(UINT8));
            UINT8* ip_dst_check = strstr(optarg, "ipdest=");
            if (ip_dst_check != NULL) {
                int DPORT = 0;
                sscanf(ip_dst_check, "ipdest=%s", ip_dst);
                ip_ex->ip_dst = inet_addr(ip_dst);
            }
            UINT8* icmp_ex = create_icmp_header(8, 0, 1);
            buf = create_icmp_packet(eth_ex, ip_ex, icmp_ex, "", 0);
            length = sizeof(struct icmp_header) + sizeof(struct ip_header) + sizeof(struct eth_header);
            break;

        default:
            printf("вы указали неверную опцию, попробуйте еще");
            return;
        }
    }

    if (pcap_sendpacket(handle, buf, length) != 0)
    {
        fprintf(stderr, "\nError sending the packet\n"); //add error handler
        return;
    }

    //Добавить фильтрацию данных по разным критериям к каждому кейсу
    UINT8 filter[100];
    switch (for_ans) //стоит добавить опцию ip пакета, где можно менять ip адреса, и другие параметры
    {
    case 'u':
    case 'd':
        UINT8 port[50];
        itoa(sport, port, 10);
        snprintf(filter, sizeof(filter), "%s%s", "port ", port);
        break;
    case 't':
        //рукопожатия, все дела
        break;
    case 'i':
        UINT8 mac_filter[50];

        snprintf(filter, sizeof(filter), "%s%s", "icmp[icmptype]", "== icmp-echoreply");

        break;

    default:
        printf("Ответа нет");
        return;
    }


    UINT32 receive_pckt_sz = 0;
    UINT8* received_packet = capture_solo_packet(dev, filter, ip_dst, &receive_pckt_sz);

    packet_print(received_packet, receive_pckt_sz);

    //char string[6];
    //itoa(sport, string, 10);
    //char filter[12];
    //snprintf(filter, sizeof(filter), "%s%s", "port ", string);

    //UINT32 receive_pckt_sz = 0;
    //UINT8* dns_receive = capture_solo_packet(dev, filter, ip_dst, &receive_pckt_sz); //уйти от зависимости к порту

    //printf("%s resolved to ", unformatted_domain);
    //for (int i = receive_pckt_sz - 4; i < receive_pckt_sz; i++) {
    //    printf("%u.", dns_receive[i]);
    //}

    //UINT8* dns_ex = create_dns_header(0x0001, 0x0100, 0x0001, domain_formatted, 0x0001, 0x0001);
    //UINT8* create_dns_header(UINT16 id, UINT8* flags, UINT16 qdcount, UINT8* qname, UINT16 qtype, UINT16 qclass)
    return;
}

//1. rpcap://\Device\NPF_{BBB6EC36-01CE-4841-8501-A84ABBC2132B} (Network adapter 'Microsoft' on local host)
//2. rpcap://\Device\NPF_{6CD6BAA2-436D-4D3A-8639-BB65B246E7F9} (Network adapter 'Realtek PCIe GbE Family Controller' on local host)
//3. rpcap://\Device\NPF_{7C48B9B9-A20D-4319-9391-990FFA7D0016} (Network adapter 'Microsoft' on local host)
//4. rpcap://\Device\NPF_{87ABF7B1-A6A1-4C7B-A6B2-3AF34E5DFAC2} (Network adapter 'Microsoft' on local host)
