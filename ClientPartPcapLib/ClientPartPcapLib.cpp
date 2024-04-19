#define HAVE_REMOTE
#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include "Headers.h"

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

UINT16 TcpCheckSum(struct ip_header* iph, struct tcp_header* tcph, UINT8* data, UINT32 size)
{
    tcph->th_sum = 0;
    
    struct pseudo_header* header = fill_pseudo_header(iph, IPPROTO_TCP, sizeof(struct tcp_header), size);

    char tcpBuf[65536];
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

    char tcpBuf[65536];
    memcpy(tcpBuf,  header, sizeof(struct pseudo_header));
    memcpy(tcpBuf + sizeof(struct pseudo_header), udph, sizeof(struct udp_header));
    memcpy(tcpBuf + sizeof(struct pseudo_header) + sizeof(struct udp_header), data, size);

    return udph->udp_sum = IpCheckSum(tcpBuf,
        sizeof(struct pseudo_header) + sizeof(struct udp_header) + size);
}

UINT16 TcpUdpCheckSum(struct ip_header* iph, UINT8* hdr, UINT8* data, UINT32 size, UINT32 proto)
{
    struct pseudo_header psd_header;
    psd_header.dst_addr = iph->ip_dst;
    psd_header.src_addr = iph->ip_src;
    psd_header.zero = 0;
    psd_header.proto = proto;

    char tcpBuf[65536];
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

struct tcp_header* create_tcp_header(UINT16 th_sport, UINT16 th_dport, UINT32 th_seq, UINT32 th_ack,
                      UINT16 th_win, UINT16 th_urp, UINT32* flags)
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

//takes only default markers
UINT8* domain_name_to_dns_format(UINT8** domain, UINT32 rows)
{
    UINT8* temp = (UINT8*)calloc(1000, sizeof(UINT8));
    UINT32 offset = 0;

    for (UINT32 i = 0; i < rows; i++) {
        UINT32 len = strlen(domain[i]);
        temp[offset++] = len; // write length as UINT8
        memcpy(temp + offset, domain[i], len); // copy domain name
        offset += len;
    }

    return temp;
}

UINT8* create_dns_header(UINT16 id, UINT8* flags, UINT16 qdcount, UINT8* qname, UINT16 qtype, UINT16 qclass)
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
    char dst_addr_str[INET_ADDRSTRLEN];
    char src_addr_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_addr_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_addr_str, INET_ADDRSTRLEN);

    if ((GET_TH_SYN(flags) & 1) && (GET_TH_ACK(flags) & 1)) {
        struct eth_header* eth_ex = create_ethernet_header(eth_hdr->h_source, eth_hdr->h_dest);
        struct ip_header* ip_ex = create_ip_header(ntohl(ip_hdr->ip_tos), ntohl(ip_hdr->ip_id), ntohs(ip_hdr->ip_off), ip_hdr->ip_ttl,
                                                IPPROTO_TCP, dst_addr_str, src_addr_str);
        struct tcp_header* tcp_ex = create_tcp_header(ntohs(tcp_hdr->th_dport), ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_seq) + 1,
            ntohl(tcp_hdr->th_ack), ntohs(tcp_hdr->th_win), ntohs(tcp_hdr->th_urp), own_flags);
        char* buf = create_tcp_packet(eth_ex, ip_ex, tcp_ex, "", 0);

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
    char* dev = device_name;  /* Устройство для сниффинга */
    char errbuf[PCAP_ERRBUF_SIZE]; /* Строка для хранения ошибок */
    struct bpf_program fp;  /* Скомпилированный фильтр */
    char* filter_exp = filter;//"port 1234"; /* Выражение фильтра */
    bpf_u_int32 mask;  /* Сетевая маска устройства */
    bpf_u_int32 net = ntohl(inet_addr(ip));  /* IP устройства */
    //printf("%x\n", net);
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

    pcap_set_timeout(handle, 3000);//

    packet = pcap_next(handle, &header);
    /* Вывод его длины */
    printf("Jacked a packet with length of [%d]\n", header.len);
    *size = header.len;

    /* Закрытие сессии */
    pcap_close(handle);

    return packet;
}

enum execution_params //hash codes of these words
{
    question_mark = 2142568280,
    manual = -1511601534,
    man = 1377619001,
    tcp = 1149449077,
    udp = 2009664236,
    dns = -1611228223,
};

int params_hash(char* param) {
    int sum = 0;
    for (int i = 0; i < strlen(param); i++) {
        sum += param[i];
    }
    return sum;
}

static char* manual_information =
"Manual:\n\
    \tcommands:\n\n\
        ? - manual info\n\n\
        -udp - will be an add-on over ip packet\n\
        params:\n\
            source port - the port from which the packet will be sent\n\
            destination port - the port to which the packet will be sent\n\n\
        //-tcp\n\n\
        -dns - will be an add-on over udp packet\n\
        params:\n\
            Opcode - query type; 0 - standart, 1 - invers\n\
            Domain/ip - in addiction to opcode using domain to find ip or inversely\n\
            //Server status - \n\
            RD - do not return intermediate answers, only ip - the port to which the packet will be sent";

void main(UINT32 argc, UINT8** argv)
{
    UINT8* dev = "rpcap://\\Device\\NPF_{7C48B9B9-A20D-4319-9391-990FFA7D0016}";

    UINT8* ip_src = "192.168.232.133";
    UINT8* ip_dst = "208.67.222.222";

    pcap_t* handle = device_init(dev);

    UINT8 mac_dst[] = { 0x7c, 0x69, 0xf6 , 0xb3, 0x7d, 0xc7 };
    UINT8 mac_src[] = { 0x20, 0x4e, 0xf6, 0x9a, 0xfd, 0x73 };

    struct eth_header* eth_ex = create_ethernet_header(mac_dst, mac_src);
    struct ip_header* ip_ex = create_ip_header(0, 1, 0, 64, IPPROTO_UDP, ip_src, ip_dst);

    UINT32 std_len = sizeof(struct eth_header) + sizeof(struct ip_header);

    int dport = 53;
    int sport = 1234;

    UINT8* domain[] = { "yandex", "ru" };

    for (int i = 0; i < argc; i++) {
        if (argv[0] == "?" || argv[0] == "help") {
            printf("%s", manual_information);
            return;
        }
        if (argv[i] == "-udp") {
            if ((i + 1) < argc && argv[i + 1] != "-dns") {
                i++;
                dport = atoi(argv[i]);
            }
            if ((i + 1) < argc && argv[i + 1] != "-dns") {
                i++;
                sport = atoi(argv[i]);
            }
        }
        if (argv[i] == "-tcp") {
            return; //temporary
            for (int j = i; j < argc; j++) {
                if (argv[j] == "-dns") {
                    i = j - 1;
                    break;
                }

            }
        }
        if (argv[i] == "-dns") {

        }
        struct udp_header* udp_ex = create_udp_header(sport, dport);
        UINT8* domain_formatted = domain_name_to_dns_format(domain, 2);
        UINT8* dns_ex = create_dns_header(0x0001, 0x0100, 0x0001, domain_formatted, 0x0001, 0x0001);
        UINT32 dns_size = sizeof(struct dns_header) + strlen(domain_formatted) + sizeof(UINT8) + sizeof(struct dns_question);
        UINT8* buf_dns = create_udp_packet(eth_ex, ip_ex, udp_ex, dns_ex, dns_size);

        if (pcap_sendpacket(handle, buf_dns, std_len + sizeof(struct udp_header) + dns_size) != 0)
        {
            fprintf(stderr, "\nError sending the packet\n"); //add error handler
            return;
        }

        UINT32 receive_pckt_sz = 0;
        UINT8* dns_receive = capture_solo_packet(dev, "port 1234", ip_dst, &receive_pckt_sz);

        for (int i = receive_pckt_sz - 4; i < receive_pckt_sz; i++) {
            printf("%u.", dns_receive[i]);
        }
    }
    //UINT8* dns_ex = create_dns_header(0x0001, 0x0100, 0x0001, domain_formatted, 0x0001, 0x0001);
    //UINT8* create_dns_header(UINT16 id, UINT8* flags, UINT16 qdcount, UINT8* qname, UINT16 qtype, UINT16 qclass)
    return;
}

//1. rpcap://\Device\NPF_{BBB6EC36-01CE-4841-8501-A84ABBC2132B} (Network adapter 'Microsoft' on local host)
//2. rpcap://\Device\NPF_{6CD6BAA2-436D-4D3A-8639-BB65B246E7F9} (Network adapter 'Realtek PCIe GbE Family Controller' on local host)
//3. rpcap://\Device\NPF_{7C48B9B9-A20D-4319-9391-990FFA7D0016} (Network adapter 'Microsoft' on local host)
//4. rpcap://\Device\NPF_{87ABF7B1-A6A1-4C7B-A6B2-3AF34E5DFAC2} (Network adapter 'Microsoft' on local host)
