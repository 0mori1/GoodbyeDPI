/*
 * GoodbyeDPI — Passive DPI blocker and Active DPI circumvention utility.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <in6addr.h>
#include <ws2tcpip.h>
#include "windivert.h"
#include "goodbyedpi.h"
#include "utils/repl_str.h"
#include "service.h"
#include "dnsredir.h"
#include "ttltrack.h"
#include "blackwhitelist.h" 
#include "fakepackets.h"
#include <pthread.h>    
#include <windows.h>
#define MAX_PACKET_SIZE 2048
#define SHOWSNI
#define FATASSMAXLIFE 256
#define DOLOCALNETS
// My mingw installation does not load inet_pton definition for some reason
WINSOCK_API_LINKAGE INT WSAAPI inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);

#define GOODBYEDPI_VERSION "v0.3.1"

#define die() do { sleep(20); exit(EXIT_FAILURE); } while (0)

#define MAX_FILTERS 4

#define DIVERT_NO_LOCALNETSv4_DST "(" \
                   "(ip.DstAddr < 127.0.0.1 or ip.DstAddr > 127.255.255.255) and " \
                   "(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and " \
                   "(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and " \
                   "(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and " \
                   "(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255)" \
                   ")"
#define DIVERT_NO_LOCALNETSv4_SRC "(" \
                   "(ip.SrcAddr < 127.0.0.1 or ip.SrcAddr > 127.255.255.255) and " \
                   "(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and " \
                   "(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and " \
                   "(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and " \
                   "(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255)" \
                   ")"

#define DIVERT_NO_LOCALNETSv6_DST "(" \
                   "(ipv6.DstAddr > ::1) and " \
                   "(ipv6.DstAddr < 2001::0 or ipv6.DstAddr > 2001:1::0) and " \
                   "(ipv6.DstAddr < fc00::0 or ipv6.DstAddr > fe00::0) and " \
                   "(ipv6.DstAddr < fe80::0 or ipv6.DstAddr > fec0::0) and " \
                   "(ipv6.DstAddr < ff00::0 or ipv6.DstAddr > ffff::0)" \
                   ")"
#define DIVERT_NO_LOCALNETSv6_SRC "(" \
                   "(ipv6.SrcAddr > ::1) and " \
                   "(ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr > 2001:1::0) and " \
                   "(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr > fe00::0) and " \
                   "(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr > fec0::0) and " \
                   "(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr > ffff::0)" \
                   ")"

/* #IPID# is a template to find&replace */
#define IPID_TEMPLATE "#IPID#"
#define MAXPAYLOADSIZE_TEMPLATE "#MAXPAYLOADSIZE#"
#ifndef DOLOCALNETS
#define FILTER_STRING_TEMPLATE \
        "(tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
        "((inbound and (" \
         "(" \
          "(" \
           "(ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF) " IPID_TEMPLATE \
           ") and " \
           "tcp.SrcPort == 80 and tcp.Ack" \
          ") or " \
          "((tcp.SrcPort == 80 or tcp.SrcPort == 443) and ((tcp.Ack and tcp.Syn) or tcp.Ack))" \
         ")" \
         " and (" DIVERT_NO_LOCALNETSv4_SRC " or " DIVERT_NO_LOCALNETSv6_SRC "))) or " \
        "(outbound and " \
         "(tcp.DstPort == 80 or tcp.DstPort == 443) and (tcp.Ack or (!tcp.Ack and tcp.Syn)) and " \
         "(" DIVERT_NO_LOCALNETSv4_DST " or " DIVERT_NO_LOCALNETSv6_DST "))" \
        "))"
        
#define FILTER_PASSIVE_STRING_TEMPLATE "inbound and ip and tcp and " \
        "!impostor and !loopback and " \
        "(true " IPID_TEMPLATE ") and " \
        "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and " \
        DIVERT_NO_LOCALNETSv4_SRC
#else
#define FILTER_STRING_TEMPLATE \
        "(tcp and !impostor " MAXPAYLOADSIZE_TEMPLATE " and " \
        "((inbound and (" \
         "(" \
          "(" \
           "(ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF) " IPID_TEMPLATE \
           ") and " \
           "tcp.SrcPort == 80 and tcp.Ack" \
          ") or " \
          "((tcp.SrcPort == 80 or tcp.SrcPort == 443) and ((tcp.Ack and tcp.Syn) or tcp.Ack))" \
         ")" \
         ")) or " \
        "(outbound and " \
         "(tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.Ack" \
         ")" \
        "))"

#define FILTER_PASSIVE_STRING_TEMPLATE "inbound and ip and tcp and " \
        "!impostor and !loopback and " \
        "(true " IPID_TEMPLATE ") and " \
        "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst"
#endif
#define FILTER_PASSIVE_BLOCK_QUIC "outbound and !impostor and !loopback and udp " \
        "and udp.DstPort == 443 and udp.PayloadLength >= 1200 " \
        "and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01"

#define SET_HTTP_FRAGMENT_SIZE_OPTION(fragment_size) do { \
    if (!http_fragment_size) { \
        http_fragment_size = (unsigned int)fragment_size; \
    } \
    else if (http_fragment_size != (unsigned int)fragment_size) { \
        printf( \
            "WARNING: HTTP fragment size is already set to %u, not changing.\n", \
            http_fragment_size \
        ); \
    } \
} while (0)

#define TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() \
    if ((packet_v4 && tcp_handle_outgoing(&ppIpHdr->SrcAddr, &ppIpHdr->DstAddr, \
                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort, \
                        &tcp_conn_info, 0)) \
        || \
        (packet_v6 && tcp_handle_outgoing(ppIpV6Hdr->SrcAddr, ppIpV6Hdr->DstAddr, \
                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort, \
                        &tcp_conn_info, 1)))

#define TCP_HANDLE_OUTGOING_FAKE_PACKET(func) do { \
    should_send_fake = 1; \
    if (do_auto_ttl || ttl_min_nhops) { \
        TCP_HANDLE_OUTGOING_TTL_PARSE_PACKET_IF() { \
            if (do_auto_ttl) { \
                /* If Auto TTL mode */ \
                ttl_of_fake_packet = tcp_get_auto_ttl(tcp_conn_info.ttl, auto_ttl_1, auto_ttl_2, \
                                                      ttl_min_nhops, auto_ttl_max); \
                if (do_tcp_verb) { \
                    printf("Connection TTL = %d, Fake TTL = %d\n", tcp_conn_info.ttl, ttl_of_fake_packet); \
                } \
            } \
            else if (ttl_min_nhops) { \
                /* If not Auto TTL mode but --min-ttl is set */ \
                if (!tcp_get_auto_ttl(tcp_conn_info.ttl, 0, 0, ttl_min_nhops, 0)) { \
                    /* Send only if nhops >= min_ttl */ \
                    should_send_fake = 0; \
                } \
            } \
        } \
    } \
    if (should_send_fake) \
        func(w_filter, &addr, packet, packetLen, packet_v6, \
             ttl_of_fake_packet, do_wrong_chksum, do_wrong_seq); \
} while (0)

enum ERROR_CODE{
    ERROR_DEFAULT = 1,
    ERROR_PORT_BOUNDS,
    ERROR_DNS_V4_ADDR,
    ERROR_DNS_V6_ADDR,
    ERROR_DNS_V4_PORT,
    ERROR_DNS_V6_PORT,
    ERROR_BLACKLIST_LOAD,
    ERROR_AUTOTTL,
    ERROR_ATOUSI,
    ERROR_AUTOB
};

static int running_from_service = 0;
static int exiting = 0;
static HANDLE filters[MAX_FILTERS];
static int filter_num = 0;
static const char http10_redirect_302[] = "HTTP/1.0 302 ";
static const char http11_redirect_302[] = "HTTP/1.1 302 ";
static const char http_host_find[] = "\r\nHost: ";
static const char http_host_replace[] = "\r\nhoSt: ";
static const char http_useragent_find[] = "\r\nUser-Agent: ";
static const char location_http[] = "\r\nLocation: http://";
static const char connection_close[] = "\r\nConnection: close";
static const char *http_methods[] = {
    "GET ",
    "HEAD ",
    "POST ",
    "PUT ",
    "DELETE ",
    "CONNECT ",
    "OPTIONS ",
};

static struct option long_options[] = {
    {"help",        no_argument,       0,  'H' },
    {"port",        required_argument, 0,  'z' },
    {"dns-addr",    required_argument, 0,  'd' },
    {"dns-port",    required_argument, 0,  'g' },
    {"dnsv6-addr",  required_argument, 0,  '!' },
    {"dnsv6-port",  required_argument, 0,  '@' },
    {"dns-verb",    no_argument,       0,  'v' },
    {"drop-unsecure-dns", no_argument, 0,  '?' },
    {"blacklist",   required_argument, 0,  '^' },
    {"whitelist",   required_argument, 0,  '&' },
    {"allow-no-sni",no_argument,       0,  ']' },
    {"frag-by-sni", no_argument,       0,  '>' },
    {"sni-frag-size",required_argument,0,  '#' },
    {"tls-force-native", no_argument,  0,  ';' },
    {"ip-id",       required_argument, 0,  'i' },
    {"set-ttl",     required_argument, 0,  '$' },
    {"min-ttl",     required_argument, 0,  '[' },
    {"auto-ttl",    optional_argument, 0,  '+' },
    {"wrong-chksum",no_argument,       0,  '%' },
    {"wrong-seq",   no_argument,       0,  ')' },
    {"native-frag", no_argument,       0,  '*' },
    {"reverse-frag",no_argument,       0,  '(' },
    {"super-reverse",no_argument,      0,  '_' },
    {"max-payload", optional_argument, 0,  '|' },
    {"fake-from-hex",required_argument,0,  'u' },
    {"fake-with-sni",required_argument,0,  '}' },
    {"fake-gen",    required_argument, 0,  'j' },
    {"fake-resend", required_argument, 0,  'T' },
    {"debug-exit",  optional_argument, 0,  'x' },
    {"discord-vc",  optional_argument, 0,  '-' },
    {"smart-frag",  no_argument,       0,  'h' },
    {"compound-frag",no_argument,      0,  'o' },
    {"tls-segmentation",required_argument,0,'b'},
    {"ext-frag-size",required_argument,0,  '=' },
    {"vortex-frag", no_argument,       0,  '0' },
    {"vortex-frag-by-sni",no_argument, 0,  'V' },
    {"tls-segment-size",required_argument,0,'M'},
    {"tls-absolute-frag",required_argument,0,'O'},
    {"tls-rando-frag",no_argument,     0,  'R' },
    {"vortex-left-bias",required_argument,0,'A'},
    {"vortex-right-bias",required_argument,0,'D'},
    {"rplrr",       no_argument,       0,  'P' },
    {"rplrr-by-sni",no_argument,       0,  'S' },
    {"mss",         required_argument, 0,  'J' },
    {"record-frag", no_argument,       0,  'E' },
    {"allow-sni-overlap",no_argument,  0,  'G' },
    {"disable-sack",no_argument,       0,  'Z' },
    {"tls-recseg-size",required_argument,0,'C' },
    {"cleave-sni",  no_argument,       0,  'N' },
    {"host-shiftback",required_argument,0, 'K' },
    {"reverse-fix", no_argument,       0,  'Q' },
    {"fnroor",      no_argument,       0,  'W' },
    {"illegal-segments",required_argument,0,'B'},
    {0,             0,                 0,   0  }
};

static char *filter_string = NULL;
static char *filter_passive_string = NULL;

static void add_filter_str(int proto, int port) {
    const char *udp = " or (udp and !impostor and !loopback and " \
                      "(udp.SrcPort == %d or udp.DstPort == %d))";
    const char *tcp = " or (tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
                      "(tcp.SrcPort == %d or tcp.DstPort == %d))";

    char *current_filter = filter_string;
    size_t new_filter_size = strlen(current_filter) +
            (proto == IPPROTO_UDP ? strlen(udp) : strlen(tcp)) + 16;
    char *new_filter = malloc(new_filter_size);

    strcpy(new_filter, current_filter);
    if (proto == IPPROTO_UDP)
        sprintf(new_filter + strlen(new_filter), udp, port, port);
    else
        sprintf(new_filter + strlen(new_filter), tcp, port, port);

    filter_string = new_filter;
    free(current_filter);
}

static void add_ip_id_str(int id) {
    char *newstr;
    const char *ipid = " or ip.Id == %d";
    char *addfilter = malloc(strlen(ipid) + 16);

    sprintf(addfilter, ipid, id);

    newstr = repl_str(filter_string, IPID_TEMPLATE, addfilter);
    free(filter_string);
    filter_string = newstr;

    newstr = repl_str(filter_passive_string, IPID_TEMPLATE, addfilter);
    free(filter_passive_string);
    filter_passive_string = newstr;
}

static void add_maxpayloadsize_str(unsigned short maxpayload) {
    char *newstr;
    /* 0x47455420 is "GET ", 0x504F5354 is "POST", big endian. */
    const char *maxpayloadsize_str =
        "and (tcp.PayloadLength ? tcp.PayloadLength < %hu " \
          "or tcp.Payload32[0] == 0x47455420 or tcp.Payload32[0] == 0x504F5354 " \
          "or (tcp.Payload[0] == 0x16 and tcp.Payload[1] == 0x03 and tcp.Payload[2] <= 0x03): true)";
    char *addfilter = malloc(strlen(maxpayloadsize_str) + 16);

    sprintf(addfilter, maxpayloadsize_str, maxpayload);

    newstr = repl_str(filter_string, MAXPAYLOADSIZE_TEMPLATE, addfilter);
    free(filter_string);
    filter_string = newstr;
}

static void finalize_filter_strings() {
    char *newstr, *newstr2;

    newstr2 = repl_str(filter_string, IPID_TEMPLATE, "");
    newstr = repl_str(newstr2, MAXPAYLOADSIZE_TEMPLATE, "");
    free(filter_string);
    free(newstr2);
    filter_string = newstr;

    newstr = repl_str(filter_passive_string, IPID_TEMPLATE, "");
    free(filter_passive_string);
    filter_passive_string = newstr;
}

unsigned short epoch = 0;
unsigned short genrand16(unsigned short seed) { //This is possibly the most important function in this code.
    unsigned short localepoch = epoch;
    unsigned short shift;
    unsigned short num = seed; 
    for (unsigned int i = 0; i <= epoch; i++) {
        shift = num & 0xFF + (num >> 8 & 0xFF);
        if (num & 1 == 0) num = (num >> (shift % 16 + 1)) + (num << (16 - (shift % 16 + 1)));
        else num = (num << (shift % 16 + 1)) + (num >> (16 - (shift % 16 + 1)));
        num += (num >> 4);
        num += (num * num & 0xA + (num >> 6) & 0xB);
    }
    epoch++;
    return num;
}
unsigned short genrand4(unsigned short seed) {
    return (genrand16(seed) & 0xF ^ ((genrand16(seed) >> 4) & 0xF) ^ ((genrand16(seed) >> 8) & 0xF) ^ ((genrand16(seed) >> 12) & 0xF));
}
unsigned short genrand2(unsigned short seed) {
    unsigned short rand = 0;
    unsigned char num = 0;
    while (num == 0) {
        rand = genrand16(seed);
        num = (rand & 3 ^ ((rand >> 2 & 3)) ^ ((rand >> 4 & 3)) ^ ((rand >> 6 & 3)) ^ ((rand >> 8 & 3)) ^ ((rand >> 10 & 3)) ^ ((rand >> 12 & 3)) ^ ((rand >> 14 & 3)));
    }
    return num;
}

static char* dumb_memmem(const char* haystack, unsigned int hlen,
                         const char* needle, unsigned int nlen)
{
    // naive implementation
    if (nlen > hlen) return NULL;
    size_t i;
    for (i=0; i<hlen-nlen+1; i++) {
        if (memcmp(haystack+i,needle,nlen)==0) {
            return (char*)(haystack+i);
        }
    }
    return NULL;
}

unsigned short int atousi(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    enum {
        limitValue=0xFFFFu
    };

    if(res > limitValue) {
        puts(msg);
        exit(ERROR_ATOUSI);
    }
    return (unsigned short int)res;
}

BYTE atoub(const char *str, const char *msg) {
    long unsigned int res = strtoul(str, NULL, 10u);
    enum {
        limitValue=0xFFu
    };

    if(res > limitValue) {
        puts(msg);
        exit(ERROR_AUTOB);
    }
    return (BYTE)res;
}
static HANDLE init(char *filter, UINT64 flags) {
    LPTSTR errormessage = NULL;
    DWORD errorcode = 0;
    filter = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 1, flags);
    if (filter != INVALID_HANDLE_VALUE)
        return filter;
    errorcode = GetLastError();
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS,
                  NULL, errorcode, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
                  (LPTSTR)&errormessage, 0, NULL);
    printf("Error opening filter: %d %s\n", errorcode, errormessage);
    LocalFree(errormessage);
    switch (errorcode) {
        case 2:
            printf("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
            break;
        case 654:
            printf("An incompatible version of the WinDivert driver is currently loaded.\n"
                   "Please unload it with the following commands ran as administrator:\n\n"
                   "sc stop windivert\n"
                   "sc delete windivert\n"
                   "sc stop windivert14"
                   "sc delete windivert14\n");
            break;
        case 1275:
            printf("This error occurs for various reasons, including:\n"
                   "the WinDivert driver is blocked by security software; or\n"
                   "you are using a virtualization environment that does not support drivers.\n");
            break;
        case 1753:
            printf("This error occurs when the Base Filtering Engine service has been disabled.\n"
                   "Enable Base Filtering Engine service.\n");
            break;
        case 577:
            printf("Could not load driver due to invalid digital signature.\n"
                   "Windows Server 2016 systems must have secure boot disabled to be \n"
                   "able to load WinDivert driver.\n"
                   "Windows 7 systems must be up-to-date or at least have KB3033929 installed.\n"
                   "https://www.microsoft.com/en-us/download/details.aspx?id=46078\n\n"
                   "WARNING! If you see this error on Windows 7, it means your system is horribly "
                   "outdated and SHOULD NOT BE USED TO ACCESS THE INTERNET!\n"
                   "Most probably, you don't have security patches installed and anyone in your LAN or "
                   "public Wi-Fi network can get full access to your computer (MS17-010 and others).\n"
                   "You should install updates IMMEDIATELY.\n");
            break;
    }
    return NULL;
}

static int deinit(HANDLE handle) {
    if (handle) {
        WinDivertShutdown(handle, WINDIVERT_SHUTDOWN_BOTH);
        WinDivertClose(handle);
        return TRUE;
    }
    return FALSE;
}

void deinit_all() {
    for (int i = 0; i < filter_num; i++) {
        deinit(filters[i]);
    }
}
unsigned char activate_thrash = 0;
unsigned char doing_conntrack = 0;
unsigned char synning = 0;
HANDLE thrash_filter;
HANDLE conntrack_filter;
HANDLE synner_filter;
static void sigint_handler(int sig __attribute__((unused))) {
    //printf("Attempting shutdown...\n");
    exiting = 1;
    deinit_all();
    if (activate_thrash) {
	    WinDivertShutdown(thrash_filter, WINDIVERT_SHUTDOWN_BOTH);
	    WinDivertClose(thrash_filter);
    }
    if (doing_conntrack) {
	    WinDivertShutdown(conntrack_filter, WINDIVERT_SHUTDOWN_BOTH);
	    WinDivertClose(conntrack_filter);
    }
    if (synning) {
	    WinDivertShutdown(synner_filter, WINDIVERT_SHUTDOWN_BOTH);
	    WinDivertClose(synner_filter);
    }
    exit(EXIT_SUCCESS);
}
static void sigsegv_handler(int sig __attribute__((unused))) {
    exiting = 1;
    deinit_all();
    if (activate_thrash) {
	    WinDivertShutdown(thrash_filter, WINDIVERT_SHUTDOWN_BOTH);
	    WinDivertClose(thrash_filter);
    }
    if (doing_conntrack) {
	    WinDivertShutdown(conntrack_filter, WINDIVERT_SHUTDOWN_BOTH);
	    WinDivertClose(conntrack_filter);
    }
    if (synning) {
	    WinDivertShutdown(synner_filter, WINDIVERT_SHUTDOWN_BOTH);
	    WinDivertClose(synner_filter);
    }
    printf("Segmentation Fault\n");
    #ifndef DEBUG
    exit(0xC0000005);
    #endif
}
static void mix_case(char *pktdata, unsigned int pktlen) {
    unsigned int i;
    if (pktlen <= 0) return;
    for (i = 0; i < pktlen; i++) {
        if (i % 2) {
            pktdata[i] = (char) toupper(pktdata[i]);
        }
    }
}

static int is_passivedpi_redirect(const char *pktdata, unsigned int pktlen) {
    /* First check if this is HTTP 302 redirect */
    if (memcmp(pktdata, http11_redirect_302, sizeof(http11_redirect_302)-1) == 0 ||
        memcmp(pktdata, http10_redirect_302, sizeof(http10_redirect_302)-1) == 0)
    {
        /* Then check if this is a redirect to new http site with Connection: close */
        if (dumb_memmem(pktdata, pktlen, location_http, sizeof(location_http)-1) &&
            dumb_memmem(pktdata, pktlen, connection_close, sizeof(connection_close)-1)) {
            return TRUE;
        }
    }
    return FALSE;
}

static int find_header_and_get_info(const char *pktdata, unsigned int pktlen,
                const char *hdrname,
                char **hdrnameaddr,
                char **hdrvalueaddr, unsigned int *hdrvaluelen) {
    char *data_addr_rn;
    char *hdr_begin;

    *hdrvaluelen = 0u;
    *hdrnameaddr = NULL;
    *hdrvalueaddr = NULL;

    /* Search for the header */
    hdr_begin = dumb_memmem(pktdata, pktlen,
                hdrname, strlen(hdrname));
    if (!hdr_begin) return FALSE;
    if (pktdata > hdr_begin) return FALSE;

    /* Set header address */
    *hdrnameaddr = hdr_begin;
    *hdrvalueaddr = hdr_begin + strlen(hdrname);

    /* Search for header end (\r\n) */
    data_addr_rn = dumb_memmem(*hdrvalueaddr,
                        pktlen - (uintptr_t)(*hdrvalueaddr - pktdata),
                        "\r\n", 2);
    if (data_addr_rn) {
        *hdrvaluelen = (uintptr_t)(data_addr_rn - *hdrvalueaddr);
        if (*hdrvaluelen >= 3 && *hdrvaluelen <= HOST_MAXLEN)
            return TRUE;
    }
    return FALSE;
}

/**
 * Very crude Server Name Indication (TLS ClientHello hostname) extractor.
 */
static int extract_sni(const char *pktdata, unsigned int pktlen,
                    unsigned char **hostnameaddr, unsigned int *hostnamelen) {
    unsigned int ptr = 0;
    unsigned const char *d = (unsigned const char *)pktdata;
    unsigned const char *hnaddr = 0;
    int hnlen = 0;

    while (ptr + 8 < pktlen) {
        /* Search for specific Extensions sequence */
        if (d[ptr] == '\0' && d[ptr+1] == '\0' && d[ptr+2] == '\0' &&
            d[ptr+4] == '\0' && d[ptr+6] == '\0' && d[ptr+7] == '\0' &&
            /* Check Extension length, Server Name list length
            *  and Server Name length relations
            */
            d[ptr+3] - d[ptr+5] == 2 && d[ptr+5] - d[ptr+8] == 3)
            {
                if (ptr + 8 + d[ptr+8] > pktlen) {
                    return FALSE;
                }
                hnaddr = &d[ptr+9];
                hnlen = d[ptr+8];
                /* Limit hostname size up to 253 bytes */
                if (hnlen < 3 || hnlen > HOST_MAXLEN) {
                    return FALSE;
                }
                /* Validate that hostname has only ascii lowercase characters */
                for (int i=0; i<hnlen; i++) {
                    if (!( (hnaddr[i] >= '0' && hnaddr[i] <= '9') ||
                         (hnaddr[i] >= 'a' && hnaddr[i] <= 'z') ||
                         hnaddr[i] == '.' || hnaddr[i] == '-'))
                    {
                        return FALSE;
                    }
                }
                *hostnameaddr = (char*)hnaddr;
                *hostnamelen = (unsigned int)hnlen;
                return TRUE;
            }
        ptr++;
    }
    return FALSE;
}

static inline void change_window_size(const PWINDIVERT_TCPHDR ppTcpHdr, unsigned int size) {
    if (size >= 1 && size <= 0xFFFFu) {
        ppTcpHdr->Window = htons((u_short)size);
    }
}

/* HTTP method end without trailing space */
static PVOID find_http_method_end(const char *pkt, unsigned int http_frag, int *is_fragmented) {
    unsigned int i;
    for (i = 0; i<(sizeof(http_methods) / sizeof(*http_methods)); i++) {
        if (memcmp(pkt, http_methods[i], strlen(http_methods[i])) == 0) {
            if (is_fragmented)
                *is_fragmented = 0;
            return (char*)pkt + strlen(http_methods[i]) - 1;
        }
        /* Try to find HTTP method in a second part of fragmented packet */
        if ((http_frag == 1 || http_frag == 2) &&
            memcmp(pkt, http_methods[i] + http_frag,
                   strlen(http_methods[i]) - http_frag) == 0
           )
        {
            if (is_fragmented)
                *is_fragmented = 1;
            return (char*)pkt + strlen(http_methods[i]) - http_frag - 1;
        }
    }
    return NULL;
}
unsigned int nothinging = 0;
void do_nothing() { //Behold, the do-nothinginator!
    nothinging = 0;
}
unsigned char analyze_ver, analyze_hlen, analyze_typeofservice, analyze_ttl, analyze_protocol;
uint16_t analyze_totallength, analyze_ID, analyze_fragoff, analyze_hdrchksum, analyze_srcport, analyze_dstport, analyze_udplen, analyze_chksum;
unsigned char analyze_reserved, analyze_dontfragment, analyze_morefragments;
char charholder[2];
void charputter(char charr) {
    charholder[1] = (char) 0;
    charholder[0] = charr;
    printf("%s", charholder);
}
void xprint(char* pchar, unsigned int size, unsigned int wrap) {
    for (int i = 0; i < size; i++) {
        if (wrap && i % wrap == 0) charputter('\n');
        if (pchar[i] > 31 && pchar[i] < 127) charputter(pchar[i]);
        else charputter('.');
    }
}
const char hex[16] = "0123456789ABCDEF";
char hexholder[3] = "00\0";
void hexprint(unsigned char* pchar, unsigned int size) {
    for (int i = 0; i < size; i++) {
        hexholder[0] = hex[pchar[i] / 16];
        hexholder[1] = hex[pchar[i] % 16];
        printf("%s ", hexholder);
    }
    charputter('\n');
}
void convert_endian(void *dest, void *src, unsigned int size) {
    for (unsigned int i = size - 1; i >= 0; i--) {
        ((unsigned char*) dest)[size - i - 1] = ((unsigned char*) src)[i];
        //memcpy(dest + (size - i - 1), src + i, 1);
        if (i == 0) break;
    }
}
void analyze_ip_header(unsigned char* packet) {
    analyze_ver = packet[0] >> 4;
    analyze_hlen = packet[0] & 0b00001111;
    analyze_typeofservice = packet[1];
    convert_endian(&analyze_totallength, packet + 2, 2);
    if ((packet[6] & 0b10000000) > 0) analyze_reserved = 1;
    else analyze_reserved = 0;
    if ((packet[6] & 0b01000000) > 0) analyze_dontfragment = 1;
    else analyze_dontfragment = 0;
    if ((packet[6] & 0b00100000) > 0) analyze_morefragments = 1;
    else analyze_morefragments = 0;
    //memcpy(&analyze_totallength, packet + 2, 2);
    convert_endian(&analyze_ID, packet + 4, 2);
    convert_endian(&analyze_fragoff, packet + 6, 2);
    (&analyze_fragoff)[0] = (&analyze_fragoff)[0] & 0b00011111; //Let's hope this works!
    analyze_ttl = packet[8];
    analyze_protocol = packet[9];
    memcpy(&analyze_hdrchksum, packet + 10, 2);
    printf("Version: %u\nHeader length: %u\nType of Service: %u\nTotal length: %u\nID: %u\nReserved bit: %u\nDon't Fragment: %u\nMore Fragments: %u\nFragment offset: %u\nTTL: %u\nProtocol: %u\nHeader checksum: %u\nSource IP: %u.%u.%u.%u\nDestination IP: %u.%u.%u.%u\n\n", 
        analyze_ver, analyze_hlen, analyze_typeofservice, analyze_totallength, analyze_ID, analyze_reserved, analyze_dontfragment, analyze_morefragments, analyze_fragoff, analyze_ttl, analyze_protocol, analyze_hdrchksum, packet[12], packet[13], packet[14], packet[15], packet[16], packet[17], packet[18], packet[19]);
}
void analyze_udp_header(unsigned char* packet, unsigned char iphdrlen) {
    convert_endian(&analyze_srcport, packet + iphdrlen, 2);
    convert_endian(&analyze_dstport, packet + iphdrlen + 2, 2);
    convert_endian(&analyze_udplen, packet + iphdrlen + 4, 2);
    convert_endian(&analyze_chksum, packet + iphdrlen + 6, 2);
    printf("Source port: %u\nDestination port: %u\nUDP Payload length: %u\nChecksum: %u\n\n", analyze_srcport, analyze_dstport, analyze_udplen, analyze_chksum);
}
unsigned int analyze_seq = 0, analyze_ack = 0;
unsigned char analyze_dataoffset = 0;
unsigned short analyze_window = 0, analyze_tcpchecksum = 0, analyze_urgentpointer = 0;
char empty[4] = "...\0";
void analyze_tcp_header(unsigned char* packet) {
    unsigned char iphdrlen = (packet[0] & 0xF) * 4;
    convert_endian(&analyze_srcport, packet + iphdrlen, 2);
    convert_endian(&analyze_dstport, packet + iphdrlen + 2, 2);
    convert_endian(&analyze_seq, packet + iphdrlen + 4, 4);
    convert_endian(&analyze_ack, packet + iphdrlen + 8, 4);
    convert_endian(&analyze_window, packet + iphdrlen + 14, 2);
    convert_endian(&analyze_tcpchecksum, packet + iphdrlen + 16, 2);
    convert_endian(&analyze_urgentpointer, packet + iphdrlen + 18, 2);
    analyze_dataoffset = (packet + iphdrlen)[12] >> 4;
    printf("Flags: %s.%s.%s.%s.%s.%s.%s.%s\nSource port: %u\nDestination port: %u\nSequence number: %u\nAcknowledgement number: %u\nData offset: %u\nReserved: %u\nWindow: %u\nChecksum: %u\nUrgent pointer: %u\n\n", ((packet + iphdrlen)[13] & 0x80) > 0 ? "CWR" : empty, ((packet + iphdrlen)[13] & 0x40) > 0 ? "ECE" : empty, ((packet + iphdrlen)[13] & 0x20) > 0 ? "URG" : empty, ((packet + iphdrlen)[13] & 0x10) > 0 ? "ACK" : empty, ((packet + iphdrlen)[13] & 0x8) > 0 ? "PSH" : empty, ((packet + iphdrlen)[13] & 0x4) > 0 ? "RST" : empty, ((packet + iphdrlen)[13] & 0x2) > 0 ? "SYN" : empty, ((packet + iphdrlen)[13] & 0x1) > 0 ? "FIN" : empty,
    analyze_srcport, analyze_dstport, analyze_seq, analyze_ack, analyze_dataoffset, analyze_reserved, analyze_window, analyze_tcpchecksum, analyze_urgentpointer);
}
unsigned short ciphersuitelen = 0, extlen = 0, analyze_progress = 0, analyze_extlen = 0, analyze_exttype = 0, progress = 0;
unsigned char session_len = 0, compresslen = 0;
//unsigned char mockPacket[250] = {0x45, 0x0, 0x0, 0xD2, 0x0, 0x0, 0x40, 0x0, 0x80, 0x6, 0x0, 0x0, 0x7F, 0x0, 0x0, 0x1, 0x7F, 0x0, 0x0, 0x1, 0xFF, 0xFF, 0x01, 0xBB, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x50, 0b00010000, 0xFF, 0xFF, 0x0, 0x0, 0x0, 0x0, 0x16, 0x3, 0x1, 0x0, 0xA5, 0x1, 0x0, 0x0, 0xA1, 0x3, 0x3, 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x0, 0x0, 0x20, 0xCC, 0xA8, 0xCC, 0xA9, 0xC0, 0x2F, 0xC0, 0x30, 0xC0, 0x2B, 0xC0, 0x2C, 0xC0, 0x13, 0xC0, 0x9, 0xC0, 0x14, 0xC0, 0x0A, 0x0, 0x9C, 0x0, 0x9D, 0x00, 0x2F, 0x0, 0x35, 0xC0, 0x12, 0x0, 0xA, 0x1, 0x0, 0x0, 0x58, 0x0, 0x0, 0x0, 0x18, 0x0, 0x16, 0x0, 0x0, 0x13, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x75, 0x6C, 0x66, 0x68, 0x65, 0x69, 0x6D, 0x2E, 0x6E, 0x65, 0x74, 0x0, 0x5, 0x0, 0x5, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0xA, 0x0, 0xA, 0x0, 0x8, 0x0, 0x1D, 0x0, 0x17, 0x0, 0x18, 0x0, 0x19, 0x0, 0xB, 0x0, 0x2, 0x1, 0x0, 0x0, 0xD, 0x0, 0x12, 0x0, 0x10, 0x4, 0x1, 0x4, 0x3, 0x5, 0x1, 0x5, 0x3, 0x6, 0x1, 0x6, 0x3, 0x2, 0x1, 0x2, 0x3, 0xFF, 0x1, 0x0, 0x1, 0x0, 0x0, 0x12, 0x0, 0x0};
void analyze_tls_clienthello(unsigned char* packet) {
    analyze_hlen = (packet[0] & 0b00001111) * 4;
    analyze_dataoffset = ((packet + analyze_hlen)[12] >> 4) * 4;
    printf("Version: %u.%u\n", packet[analyze_hlen + analyze_dataoffset + 9] - 2, packet[analyze_hlen + analyze_dataoffset + 10] - 1);
    convert_endian(&analyze_totallength, packet + 2, 2);
    session_len = packet[analyze_hlen + analyze_dataoffset + 43];
    convert_endian(&ciphersuitelen, packet + analyze_hlen + analyze_dataoffset + 44 + session_len, 2);
    compresslen = packet[analyze_hlen + analyze_dataoffset + 46 + session_len + ciphersuitelen];
    convert_endian(&extlen, packet + analyze_hlen + analyze_dataoffset + session_len + ciphersuitelen + compresslen + 47, 2);
    analyze_progress = session_len + ciphersuitelen + compresslen + 49;
    //xprint(packet, analyze_totallength, 40);
    printf("Session Length: %u\nCipher Suite Length: %u\nCompression Method Length: %u\nExtensions Length: %u\n", session_len, ciphersuitelen, compresslen, extlen);
    printf("Extensions:\n");
    printf("%u, %u\n", analyze_progress, analyze_totallength - analyze_hlen - analyze_dataoffset);
    while (analyze_progress < analyze_totallength - analyze_hlen - analyze_dataoffset) {
        if (analyze_totallength - analyze_dataoffset - analyze_hlen - analyze_progress >= 4) {
            convert_endian(&analyze_exttype, packet + analyze_dataoffset + analyze_hlen + analyze_progress, 2);
            convert_endian(&analyze_extlen, packet + analyze_dataoffset + analyze_hlen + analyze_progress + 2, 2);
            printf("Type: %u, Length: %u%s\n", analyze_exttype, analyze_extlen, analyze_exttype == 65037 ? " [ECH DETECTED]" : (analyze_exttype == 1 ? "[MAX_FRAGMENT_LENGTH SPECIFIED]" : ""));
            if (analyze_exttype == 64768) {
                xprint(packet + analyze_dataoffset + analyze_hlen + analyze_progress + 4, analyze_extlen, 0);
                printf("\n");
            }
            if (analyze_exttype == 0) {
                xprint(packet + analyze_dataoffset + analyze_hlen + analyze_progress + 9, analyze_extlen - 5, 0);
                printf("\n");
            }
            analyze_progress += 4 + analyze_extlen;
        }
    }
    printf("\n");
}
unsigned int diffs = 0;
void differentiate(unsigned char* compared, unsigned int comparedsize, unsigned char* compare, unsigned int comparesize, char showmatching) {
    if (comparedsize != comparesize) printf("Data size has a %u byte difference %s.\n", comparedsize < comparesize ? comparesize - comparedsize : comparedsize - comparesize, comparedsize < comparesize ? "to the right" : "to the left");
    diffs = 0;
    for (int i = 0; i < comparedsize && i < comparesize; i++) {
        if (compared[i] != compare[i]) {
            printf("MISMATCH AT BYTE %u: ", i + 1);
            printf("%u %u\n", compared[i], compare[i]);
            diffs++;
        }
        else if (showmatching) {
            printf("BYTE %d: %u %u\n", i, compared[i], compare[i]);
        }
    }
    printf("\n\n Data has %u differences.\n", diffs);
}
/** Fragment and send the packet.
 *
 * This function cuts off the end of the packet (step=0) or
 * the beginning of the packet (step=1) with fragment_size bytes.
 */
static void send_native_fragment(HANDLE w_filter, WINDIVERT_ADDRESS addr,
                        char *packet, UINT packetLen, unsigned char* packet_data,
                        UINT packet_dataLen, int packet_v4, int packet_v6,
                        PWINDIVERT_IPHDR ppIpHdr, PWINDIVERT_IPV6HDR ppIpV6Hdr,
                        PWINDIVERT_TCPHDR ppTcpHdr,
                        unsigned int fragment_size, int step) {
    char packet_bak[MAX_PACKET_SIZE];
    //analyze_ip_header(packet);
    memcpy(packet_bak, packet, packetLen);
    UINT orig_packetLen = packetLen;
    if (fragment_size >= packet_dataLen) {
        if (step == 1)
            fragment_size = 0;
        else
            return;
    }

    if (step == 0) {
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) -
                packet_dataLen + fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) -
                packet_dataLen + fragment_size
            );
        //printf("step0 (%d:%d), pp:%d, was:%d, now:%d\n",
        //                packet_v4, packet_v6, ntohs(ppIpHdr->Length),
        //                packetLen, packetLen - packet_dataLen + fragment_size);
        packetLen = packetLen - packet_dataLen + fragment_size;
    }

    else if (step == 1) {
        if (packet_v4)
            ppIpHdr->Length = htons(
                ntohs(ppIpHdr->Length) - fragment_size
            );
        else if (packet_v6)
            ppIpV6Hdr->Length = htons(
                ntohs(ppIpV6Hdr->Length) - fragment_size
            );
        //printf("step1 (%d:%d), pp:%d, was:%d, now:%d\n", packet_v4, packet_v6, ntohs(ppIpHdr->Length),
                        //packetLen, packetLen - fragment_size);
        memmove(packet_data,
                (char*)packet_data + fragment_size,
                packet_dataLen - fragment_size);
        packetLen -= fragment_size;

        ppTcpHdr->SeqNum = htonl(ntohl(ppTcpHdr->SeqNum) + fragment_size);
    }
    addr.IPChecksum = 0;
    addr.TCPChecksum = 0;
    WinDivertHelperCalcChecksums(
        packet, packetLen, &addr, 0
    );
    //analyze_ip_header(packet);
    WinDivertSend(
        w_filter, packet,
        packetLen,
        NULL, &addr
    );
    memcpy(packet, packet_bak, orig_packetLen);
    //printf("Sent native fragment of %d size (step%d)\n", packetLen, step);
}
const char chrome_useragent[16] = "Chrome/135.0.0.0";
unsigned int testsum = 0;
uint16_t wordhold = 0;
uint16_t finalized_chksum_ignr = 0;
uint16_t finalized_chksum = 0;
uint16_t alleged_chksum = 0;
unsigned char matched = 0;
void checksumtest(unsigned char *packet, unsigned int hdrLen) {
    testsum = 0;
    wordhold = 0;
    finalized_chksum_ignr = 0;
    finalized_chksum = 0;
    matched = 0;
    //Ignore checksum
    for (unsigned int i = 0; i < hdrLen; i += 2) {
        if (i != 10 && i != 11) {
            memcpy(&wordhold, packet + i, 2);
            testsum += wordhold;
        }
    }
    if (testsum > 0xFFFF) {
        wordhold = testsum & 0x0000FFFF;
        finalized_chksum_ignr += wordhold;
        wordhold = testsum >> 16;
        finalized_chksum_ignr += wordhold;
    }
    else finalized_chksum_ignr = testsum;
    finalized_chksum_ignr = finalized_chksum_ignr ^ 0xFFFF;
    //Don't ignore checksum
    testsum = 0;
    for (unsigned int i = 0; i < hdrLen; i += 2) {
        memcpy(&wordhold, packet + i, 2);
        testsum += wordhold;
    }
    if (testsum > 0xFFFF) {
        wordhold = testsum & 0x0000FFFF;
        finalized_chksum += wordhold;
        wordhold = testsum >> 16;
        finalized_chksum += wordhold;
    }
    else finalized_chksum = testsum;
    finalized_chksum = finalized_chksum ^ 0xFFFF;
    memcpy(&alleged_chksum, packet + 10, 2);
    printf("Generated sums: %u, %u\nChecksums: %u, %u\n", finalized_chksum_ignr ^ 0xFFFF, finalized_chksum ^ 0xFFFF, finalized_chksum_ignr, finalized_chksum);
    printf("Alleged checksum: %u\n", alleged_chksum);
    if (alleged_chksum + (finalized_chksum_ignr ^ 0xFFFF) == 0xFFFF) {
        printf("Checksumless operation match! (%u)\n", alleged_chksum + (finalized_chksum_ignr ^ 0xFFFF));
        matched = 1;
    }
    if (alleged_chksum + (finalized_chksum ^ 0xFFFF) == 0xFFFF) {
        printf("Operation with checksum match! (%u)\n", alleged_chksum + (finalized_chksum ^ 0xFFFF));
        matched = 1;
    }
    if (!matched) printf("No match! Bad checksum! (%u)\n", alleged_chksum + (finalized_chksum ^ 0xFFFF));
}
//I hate this, but we shouldn't be making more new bullshit on the stack every microsecond.
uint16_t fragoff = 0, fragLen = 0, packetPos = 0, overload = 0, totalLength = 0, octet = 0;
unsigned char hdrLen = 0, *fragmentHolder = NULL, DF = 0, *reassemblePacket;
void bytestep(void *in, unsigned int size) {
    for (int i = 0; i < size; i++) {
        printf("%u\n", ((unsigned char*)in)[i]);
    }
}
unsigned int verify_sum = 0, verify_checksum = 0, verify_finalizedsum;
uint16_t verify_wordhold = 0, verify_totallength, verify_payloadlength = 0, verify_fragoff = 0, reassemble_totallength;
unsigned char verify_firstFragHdrLen = 0, verify_hdrLen;
bool reassemble_packet(unsigned char* workfragment, unsigned char* out) {   
    //Verify the IP header checksum.
    verify_sum = 0;
    verify_finalizedsum = 0;
    verify_hdrLen = (workfragment[0] & 0x0F) * 4;
    for (unsigned int i = 0; i < verify_hdrLen; i += 2) {
        if (i != 10 && i != 11) {
            memcpy(&verify_wordhold, workfragment + i, 2);
            verify_sum += verify_wordhold;
        }
    }
    if (verify_sum > 0xFFFF) {
        verify_wordhold = verify_sum & 0x0000FFFF;
        verify_finalizedsum += verify_wordhold;
        verify_wordhold = verify_sum >> 16;
        verify_finalizedsum += verify_wordhold;
    }
    else verify_finalizedsum = verify_sum;
    memcpy(&verify_checksum, workfragment + 10, 2);
    if (verify_checksum + verify_finalizedsum != 0xFFFF) {
        printf("Checksum fail!\n");
        return false;
    }
    convert_endian(&verify_fragoff, workfragment + 6, 2);
    verify_fragoff = verify_fragoff & 0x1FFF;
    //Verify that its actually a fragment, and its allowed to be a fragment
    if (!(((workfragment[6] & 0b01000000) == 0) && ((verify_fragoff > 0) || ((workfragment[6] & 0x20) > 0)))) {
        printf("Packet is not a fragment or it wasnt allowed to be a fragment! [%u && (%u || %u)]\n", ((workfragment[6] & 0b01000000) == 0), (verify_fragoff > 0), ((workfragment[6] & 0x20) > 0));
        return false;
    }
    printf("GO!");
    convert_endian(&verify_totallength, workfragment + 2, 2);
    verify_payloadlength = verify_totallength - verify_hdrLen;
    if (verify_fragoff == 0) {
        memcpy(out, workfragment, verify_hdrLen); //Copy the IP header of the first fragment.
        printf("1");
        out[6] = 0; //Did you think I would forget this?
        printf("2");
        verify_firstFragHdrLen = verify_hdrLen;
    }
    else { //Add the fragment's total length to the total length of the packet.
        convert_endian(&reassemble_totallength, out + 2, 2);
        printf("3");
        if ((reassemble_totallength - verify_firstFragHdrLen) > (verify_fragoff * 8)) { //Handle edgecases
            printf("Fragment Overwrite Warning!\n"); //The giant enemy line
            reassemble_totallength += (verify_fragoff * 8 + verify_payloadlength) > (reassemble_totallength - verify_firstFragHdrLen) ? (verify_fragoff * 8 + verify_payloadlength) - (reassemble_totallength - verify_firstFragHdrLen) : 0;
        }
        else if ((reassemble_totallength - verify_firstFragHdrLen) < (verify_fragoff * 8)) {
            printf("Fragment Overstep Warning!\n");
            reassemble_totallength += (verify_payloadlength + (verify_fragoff * 8 - (reassemble_totallength - verify_firstFragHdrLen)));
        }
        else {
            reassemble_totallength += verify_payloadlength;
            convert_endian(out + 2, &reassemble_totallength, 2);
            printf("4");
        }
    }
    printf("%p, %p, %u", out + verify_firstFragHdrLen + (verify_fragoff * 8), workfragment + verify_hdrLen, verify_payloadlength);
    memcpy(out + verify_firstFragHdrLen + (verify_fragoff * 8), workfragment + verify_hdrLen, verify_payloadlength);
    printf("Fragment integrated!");
    if ((workfragment[6] & 0x20) == 0) { //If that was the final fragment, recalculate the header checksum
        printf("Checksum recalculated!");
        verify_sum = 0;
        verify_finalizedsum = 0;
        for (unsigned int i = 0; i < verify_firstFragHdrLen; i += 2) {
            if (i != 10 && i != 11) {
                memcpy(&verify_wordhold, out + i, 2);
                verify_sum += verify_wordhold;
            }
        }
        if (verify_sum > 0xFFFF) {
            verify_wordhold = verify_sum & 0x0000FFFF;
            verify_finalizedsum += verify_wordhold;
            verify_wordhold = verify_sum >> 16;
            verify_finalizedsum += verify_wordhold;
        }
        else verify_finalizedsum = verify_sum;
        verify_checksum = verify_finalizedsum ^ 0xFFFF;
        memcpy(out + 10, &verify_checksum, 2);
    }
    return true;
}
unsigned int tcpSeq = 0;
unsigned char dataOffset = 0;
void reassemble_segments(unsigned char* packet, unsigned char* reassembleOut, unsigned int baseSeq) {
    //Skip over to the whole reassembly part, assume packet is valid
    hdrLen = (packet[0] & 0x0F) * 4;
    dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    convert_endian(&tcpSeq, packet + hdrLen + 4, 4);
    convert_endian(&totalLength, packet + 2, 2);
    //We acquired enough information to start reassembling the data.
    memcpy(reassembleOut + (tcpSeq - baseSeq), packet + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
}
void reassemble_and_compare(unsigned char* packet, unsigned char* reassembleOut, unsigned int baseSeq, unsigned char* knowngood) {
    char corrupted = 0;
    char overlapping = 0;
    hdrLen = (packet[0] & 0x0F) * 4;
    dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    convert_endian(&tcpSeq, packet + hdrLen + 4, 4);
    convert_endian(&totalLength, packet + 2, 2);
    #ifdef DEBUG
    printf("TRACE, OFFSET: %u, LEN: %u\n", tcpSeq - baseSeq, totalLength - hdrLen - dataOffset);
    #endif
    //We acquired enough information to start reassembling the data, but we gotta check it.
    for (unsigned int i = 0; i < totalLength - hdrLen - dataOffset; i++) {
        //printf("STEP: %u, %u, %u, %u\n", i, tcpSeq - baseSeq, tcpSeq, baseSeq);
        if (knowngood[i + (tcpSeq - baseSeq)] != packet[hdrLen + dataOffset + i]) corrupted = 1;
        if (reassembleOut[i + (tcpSeq - baseSeq)] != 255) overlapping = 1; //I'm an idiot.
    }
    if (!corrupted) memcpy(reassembleOut + (tcpSeq - baseSeq), packet + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
    else printf("This segment is corrupted! Not reinjecting.\n");
    if (overlapping) printf("Overlap Detected\n");
}
unsigned short tls_reassembly_progress = 0;
unsigned short tls_recordLen = 0;
unsigned char reassembleTls[65536];
unsigned char istlshandshake(unsigned char* packet_data) {
    tls_recordLen = ntohs(*((unsigned short*)(packet_data + 3)));
    if (packet_data[0] == 0x16 && packet_data[1] == 3 && packet_data[2] < 4 && packet_data[2] >= 1 && tls_recordLen <= 16384) return TRUE;
    else return FALSE;
}
void reassemble_tls(unsigned char* packet) {
    hdrLen = (packet[0] & 0x0F) * 4;
    dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    totalLength = ntohs(*((unsigned short*)(packet + 2)));
    //This must be as strict as the destination.
    if (packet[hdrLen + dataOffset] != 0x16) {
        printf("REASSEMBLY ERROR: Not a handshake message. (%u)\n", packet[hdrLen + dataOffset]);
        return;
    }
    if (packet[hdrLen + dataOffset + 1] != 3 || packet[hdrLen + dataOffset + 2] > 4 || packet[hdrLen + dataOffset + 2] < 1) {
        printf("REASSEMBLY ERROR: Not a TLS 1.0 - 1.3 record. (%u)\n", packet[hdrLen + dataOffset]);
        return;
    }
    tls_recordLen = ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + 3)));
    if (tls_recordLen != totalLength - hdrLen - dataOffset - 5) {
        printf("REASSEMBLY ERROR: Record is smaller or larger than this packet can contain.\n");
        return;
    }
    memcpy(reassembleTls + tls_reassembly_progress, packet + hdrLen + dataOffset + 5, tls_recordLen);
    tls_reassembly_progress += tls_recordLen;
}
void reassemble_tls_bald(unsigned char* record) { //Headerless. Amazing.
    //This must be as strict as the destination.
    if (record[0] != 0x16) {
        printf("REASSEMBLY ERROR: Not a handshake message. (%u)\n", record[0]);
        return;
    }
    if (record[1] != 3 || record[2] > 4 || record[2] < 1) {
        printf("REASSEMBLY ERROR: Not a TLS 1.0 - 1.3 record. (%u.%u)\n", record[1], record[2]);
        return;
    }
    tls_recordLen = ntohs(*((unsigned short*)(record + 3)));
    if (tls_recordLen > 16384) {
        printf("REASSEMBLY ERROR: Record is larger than 2^14 (16384) bytes.\n");
        return;
    }
    memcpy(reassembleTls + tls_reassembly_progress, record + 5, tls_recordLen);
    tls_reassembly_progress += tls_recordLen;
}
struct extension {
    unsigned short type;
    unsigned short length;
    unsigned char* data;
};
struct clienthello {
    unsigned int length;
    unsigned short version;
    unsigned char random[32];
    unsigned char sessionidlen;
    unsigned char* sessionid;
    unsigned short ciphersuiteslen;
    unsigned short* ciphersuites;
    unsigned char compressionmethodslen;
    unsigned char* compressionmethods;
    unsigned short extensionCount;
    struct extension* extensions;
};
struct connection {
    unsigned int ip;
    unsigned int seq;
    unsigned short mss;
    unsigned short life;
    unsigned char taken;
};
int parse_clienthello(unsigned char* packet, struct clienthello* clienthello) {
    unsigned short progress = 5; //Things get messy if this isnt here.
    unsigned char hdrLen = (packet[0] & 0x0F) * 4;
    unsigned char dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    unsigned short totalLength = ntohs(*((unsigned short*)(packet + 2)));
    if (ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + 3))) + 5 > totalLength - hdrLen - dataOffset) {
        printf("ERROR: Incomplete packet.\n");
        return 0;
    }
    clienthello->length = ntohl(*((unsigned int*)(packet + hdrLen + dataOffset + progress)) & 0xFFFFFF00);
    progress += 4;
    clienthello->version = ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + progress)));
    progress += 2;
    memcpy(clienthello->random, packet + hdrLen + dataOffset + progress, 32);
    progress += 32;
    clienthello->sessionidlen = packet[hdrLen + dataOffset + progress];
    progress++;
    if (clienthello->sessionidlen > 0) {
        clienthello->sessionid = malloc(clienthello->sessionidlen);
        memcpy(clienthello->sessionid, packet + hdrLen + dataOffset + progress, clienthello->sessionidlen);
        progress += clienthello->sessionidlen;
    }
    clienthello->ciphersuiteslen = ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + progress)));
    progress += 2;
    if (clienthello->ciphersuiteslen > 0) { //There's no way this condition isn't true, but nobody knows.
        clienthello->ciphersuites = malloc(clienthello->ciphersuiteslen);
        memcpy(clienthello->ciphersuites, packet + hdrLen + dataOffset + progress, clienthello->ciphersuiteslen);
        progress += clienthello->ciphersuiteslen;
    }
    clienthello->compressionmethodslen = packet[hdrLen + dataOffset + progress];
    progress++;
    if (clienthello->compressionmethodslen > 0) { //Why must I have to add robustness to shit that never needed it...
        clienthello->compressionmethods = malloc(clienthello->compressionmethodslen);
        memcpy(clienthello->compressionmethods, packet + hdrLen + dataOffset + progress, clienthello->compressionmethodslen);
        progress += clienthello->compressionmethodslen;
    }
    progress += 2; //The extensions length is irrelevant due to the nature of the clienthello struct.
    unsigned short progressbackup = progress;
    clienthello->extensionCount = 0;
    while (progress < totalLength - hdrLen - dataOffset) { //Count the extensions.
        progress += 2; //Ignore the extension type for this moment as it is irrelevant.
        progress += ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + progress))) + 2;
        clienthello->extensionCount++;
    }
    clienthello->extensions = calloc(clienthello->extensionCount, sizeof(struct extension));
    unsigned short step = 0;
    progress = progressbackup;
    while (progress < totalLength - hdrLen - dataOffset) { //NOW we can get to work.
        clienthello->extensions[step].type = ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + progress)));
        progress += 2;
        clienthello->extensions[step].length = ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + progress))); 
        progress += 2;
        clienthello->extensions[step].data = malloc(clienthello->extensions[step].length);
        memcpy(clienthello->extensions[step].data, packet + hdrLen + dataOffset + progress, clienthello->extensions[step].length);
        progress += clienthello->extensions[step++].length;
    }
    return 1;
}
unsigned short rebuild_clienthello(struct clienthello* clienthello, unsigned char* destPacketPayload) { //Builds a handshake record that contains a ClientHello out of that struct.
    *((unsigned int*)(destPacketPayload)) = 0x00010316;
    unsigned short progress = 9;
    *((unsigned short*)(destPacketPayload + progress)) = htons(clienthello->version);
    //printf("VER: %u\n", clienthello->version);
    progress += 2;
    memcpy(destPacketPayload + progress, clienthello->random, 32);
    progress += 32;
    destPacketPayload[progress] = clienthello->sessionidlen;
    progress++;
    if (clienthello->sessionidlen > 0) {
        memcpy(destPacketPayload + progress, clienthello->sessionid, clienthello->sessionidlen);
        progress += clienthello->sessionidlen;
    }
    *((unsigned short*)(destPacketPayload + progress)) = htons(clienthello->ciphersuiteslen);
    progress += 2;
    if (clienthello->ciphersuiteslen > 0) { //There's no way this condition isn't true, but nobody knows.
        memcpy(destPacketPayload + progress, clienthello->ciphersuites, clienthello->ciphersuiteslen);
        progress += clienthello->ciphersuiteslen;
    }
    destPacketPayload[progress] = clienthello->compressionmethodslen;
    progress++;
    if (clienthello->compressionmethodslen > 0) { //Why must I have to add robustness to shit that never needed it...
        memcpy(destPacketPayload + progress, clienthello->compressionmethods, clienthello->compressionmethodslen);
        progress += clienthello->compressionmethodslen;
    }
    unsigned short extensionsLen = 0; //Gotta discover the extensions length based on the struct.
    unsigned short progressbackup = progress;
    progress += 2;
    for (unsigned short i = 0; i < clienthello->extensionCount; i++) {
        //printf("Constructing extension %u with length %u\n", clienthello->extensions[i].type, clienthello->extensions[i].length);
        *((unsigned short*)(destPacketPayload + progress)) = htons(clienthello->extensions[i].type);
        progress += 2;
        *((unsigned short*)(destPacketPayload + progress)) = htons(clienthello->extensions[i].length);
        progress += 2;
        memcpy(destPacketPayload + progress, clienthello->extensions[i].data, clienthello->extensions[i].length);
        progress += clienthello->extensions[i].length;
        extensionsLen += 4 + clienthello->extensions[i].length;
    }
    unsigned short length = progress - 5;
    *((unsigned short*)(destPacketPayload + 3)) = htons(length);
    *((unsigned int*)(destPacketPayload + 5)) = htonl(length - 4) | 0x00000001;
    progress = progressbackup;
    *((unsigned short*)(destPacketPayload + progress)) = htons(extensionsLen);
    //printf("Record length: %u\n", length);
    return length + 5;
}
void delete_clienthello(struct clienthello* clienthello) { //Memory management!!!!!
    printf("Freeing sessionid (if there is one)\n");
    if (clienthello->sessionidlen > 0) free(clienthello->sessionid);
    printf("Freeing cipher suites\n");
    if (clienthello->ciphersuiteslen > 0) free(clienthello->ciphersuites);
    printf("Freeing compression methods\n");
    if (clienthello->compressionmethodslen > 0) free(clienthello->compressionmethods);
    printf("Freeing extensions\n");
    for (unsigned short i = 0; i < clienthello->extensionCount; i++) 
    if (clienthello->extensions[i].length > 0) free(clienthello->extensions[i].data);
    printf("Freeing structs\n");
    free(clienthello->extensions);
    printf("Finish\n");
}
void newpacketid(unsigned char* packet) {
    unsigned short packetid;
    #ifndef SIGNATURE
    packetid = genrand16(ntohs(*((unsigned short*)(packet + 4))));
    convert_endian(packet + 4, &packetid, 2);
    #else
    packetid = 12345;
    convert_endian(packet + 4, &packetid, 2);
    #endif
}
//bigass pile of useless shit
/*
bool send_native_fragments_udp(HANDLE w_filter, unsigned char *packet, UINT packetLen, uint16_t packet_dataLen, unsigned char fragments, WINDIVERT_ADDRESS addr) {
    if (packet[0] >> 4 != 4) return false; //Non-IPv4 packet, This function doesn't know how to handle these.
    DF = packet[6] & 0b01000000;
    #ifdef UDPDEBUG
    printf("DF: %u\n", DF);
    #endif
    if (DF) { //Fragmenting is forbidden for this packet.
        return false;
    }
    //printf("DF: %u\n", DF);
    //analyze_ip_header(packet);
    fragoff = 0;
    hdrLen = (packet[0] & 0b00001111);
    //analyze_udp_header(packet, hdrLen * 4);
    packet[10] = 0; packet[11] = 0;
    packet[hdrLen * 4 + 6] = 0; packet[hdrLen * 4 + 7] = 0;
    WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
    //analyze_ip_header(packet);
    //analyze_udp_header(packet, hdrLen * 4);
    packetPos = hdrLen * 4;
    fragLen = (packet_dataLen / 8) / fragments;
    overload = packet_dataLen - (fragLen * 8 * fragments); //Packets will likely not be separated into fragments evenly, so we have an overload.
    memcpy(fragmentHolder, packet, hdrLen * 4); //Copy over the IP header.
    if (fragLen < 1) return false; //Packet too small to fragment.
    for (int i = 0; i < fragments; i++) {
        addr.IPChecksum = 0;
        if (i == 0) {
            #ifdef UDPDEBUG
            printf("initial length: %u, fragment length: %u, overload: %u\n", packetLen, fragLen * 8, overload);
            #endif
            if (fragments > 1) totalLength = (hdrLen * 4) + (fragLen * 8);
            else totalLength = (hdrLen * 4) + (fragLen * 8) + overload;
            memcpy(fragmentHolder + (hdrLen * 4), packet + packetPos, totalLength); //Put the rest of the fragment in.
            convert_endian(fragmentHolder + 2, &totalLength, 2); //Update the total length.
            //memcpy(fragmentHolder + 6, &fragoff, 2); //Set the fragment offset.
            #ifdef UDPDEBUG
            printf("PRE:\n");
            bytestep((void*)&fragoff, 2);
            printf("POST:\n");
            bytestep((void*)(fragmentHolder + 6), 2);
            #endif
            if (fragments > 1) fragmentHolder[6] = fragmentHolder[6] | 0b00100000; //Set the "More Fragments" flag to 1.
            #ifdef UDPDEBUG
            printf("F:\n");
            bytestep((void*)(fragmentHolder + 6), 2);
            #endif
            fragmentHolder[10] = 0; fragmentHolder[11] = 0;
            WinDivertHelperCalcChecksums(
                fragmentHolder, totalLength, &addr, WINDIVERT_HELPER_NO_UDP_CHECKSUM
            );
            #ifdef UDPDEBUG
            analyze_ip_header(fragmentHolder);
            analyze_udp_header(fragmentHolder, hdrLen * 4);
            checksumtest(fragmentHolder, hdrLen * 4);
            //differentiate(fragmentHolder, totalLength, packet, packetLen);
            #endif
            WinDivertSend(
                w_filter, fragmentHolder,
                totalLength,
                NULL, &addr
            );
            #ifdef UDPDEBUG
            if (!reassemble_packet(fragmentHolder, reassemblePacket)) printf("Bad fragment!");
            #endif
        }
        else if (i + 1 != fragments) { //If we didn't hit the desired amount of fragments.
            totalLength = (hdrLen * 4) + (fragLen * 8);
            memcpy(fragmentHolder + hdrLen * 4, packet + packetPos, fragLen * 8); //Put the rest of the fragment in.
            convert_endian(fragmentHolder + 2, &totalLength, 2); //Update the total length.
            convert_endian(fragmentHolder + 6, &fragoff, 2); //Set the fragment offset.
            #ifdef UDPDEBUG
            printf("PRE:\n");
            bytestep((void*)&fragoff, 2);
            printf("POST:\n");
            bytestep((void*)(fragmentHolder + 6), 2);
            #endif
            fragmentHolder[6] = fragmentHolder[6] | 0b00100000; //Set the "More Fragments" flag to 1.
            #ifdef UDPDEBUG
            printf("F:\n");
            bytestep((void*)(fragmentHolder + 6), 2);
            #endif
            WinDivertHelperCalcChecksums(
                fragmentHolder, fragLen * 8, &addr, WINDIVERT_HELPER_NO_UDP_CHECKSUM
            );
            #ifdef UDPDEBUG
            analyze_ip_header(fragmentHolder);
            checksumtest(fragmentHolder, hdrLen * 4);
            //differentiate(fragmentHolder, fragLen * 8, packet, packetLen);
            #endif
            WinDivertSend(
                w_filter, fragmentHolder,
                totalLength,
                NULL, &addr
            );
            #ifdef UDPDEBUG
            if (!reassemble_packet(fragmentHolder, reassemblePacket)) printf("Bad fragment!");
            #endif
        }
        else { //Something is VERY WRONG with this part.
            totalLength = (hdrLen * 4) + (fragLen * 8) + overload;
            //printf("access 1: %p, %p, %u, %u, %u", fragmentHolder + hdrLen * 4, packet + packetPos, fragLen * 8 + overload - 8, fragLen, overload);
            memcpy(fragmentHolder + hdrLen * 4, packet + packetPos, totalLength); //Put the rest of the fragment in, and take the overload into account.
            //printf("access 2");
            convert_endian(fragmentHolder + 2, &totalLength, 2); //Update the total length.
            //printf("access 3");
            convert_endian(fragmentHolder + 6, &fragoff, 2); //Set the fragment offset.
            //printf("access 4");
            #ifdef UDPDEBUG
            printf("PRE:\n");
            bytestep((void*)&fragoff, 2);
            printf("POST:\n");
            bytestep((void*)(fragmentHolder + 6), 2);
            #endif
            fragmentHolder[6] = fragmentHolder[6] & 0b00011111; //Set the "More Fragments" flag to 0.
            #ifdef UDPDEBUG
            printf("F:\n");
            bytestep((void*)(fragmentHolder + 6), 2);
            #endif
            //printf("finishing up");
            WinDivertHelperCalcChecksums(
                fragmentHolder, totalLength, &addr, WINDIVERT_HELPER_NO_UDP_CHECKSUM
            );
            #ifdef UDPDEBUG
            analyze_ip_header(fragmentHolder);
            checksumtest(fragmentHolder, hdrLen * 4);
            #endif
            //differentiate(fragmentHolder, fragLen * 8 + overload, packet, packetLen);
            WinDivertSend(
                w_filter, fragmentHolder,
                totalLength,
                NULL, &addr
            );
            #ifdef UDPDEBUG
            if (!reassemble_packet(fragmentHolder, reassemblePacket)) printf("Bad fragment!");
            #endif
        }
        packetPos += fragLen * 8;
        fragoff += fragLen;
    }
    #ifdef UDPDEBUG
    convert_endian(&totalLength, reassemblePacket + 2, 2);
    differentiate(reassemblePacket, totalLength, packet, packetLen, 0);
    checksumtest(reassemblePacket, hdrLen * 4);
    #endif
    return true;
}*/
/*
char hexbuff[3];
char commonTLDs[3][3] = {"com", "net", "org"};
bool domainScan(char* packet_data, UINT packet_dataLen, unsigned char** domainOut, unsigned int *domainLenOut) {
    uint16_t domainLen = 3;
    uint16_t dotCount = 0;
    if (packet_dataLen > 4) {
        for (uint16_t i = 0; i < packet_dataLen; i++) {
            if (packet_data[i] == 46) dotCount++;
        }
        if (dotCount > 1) {
            for (char tld = 0; tld < 3; tld++) {
                for (uint16_t i = 0; i < packet_dataLen - 2; i++) {
                    if (memcmp(packet_data + i, commonTLDs[tld], 3) == 0) {  //We've got a match, now we figure out where it starts.
                        for (uint16_t x = i - 1; i - x < 45 && x > 0; x--) {
                            if (packet_data[x] == 46 || packet_data[x] == 45 || (packet_data[x] > 47 && packet_data[x] < 58) || (packet_data[x] > 96 && packet_data[x] < 123)) domainLen++;
                            else {
                                if (domainLen > 10) {
                                    puts("Success! Writing domain length.");
                                    memset(domainLenOut, domainLen, 2);
                                    puts("Returning!");
                                    memset(domainOut, (long long)packet_data + x, sizeof(char*)); //I hate this.
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}
*/
unsigned short beginSni = 0;
unsigned short endSni = 0;
unsigned short fragmentInfoLen = 0;
struct fragmentInfoChunk {
    unsigned int seq;
    uint16_t payloadLen;
};
struct fragmentInfo {
    unsigned short length;
    struct fragmentInfoChunk fragments[MAX_PACKET_SIZE - 40];
};
struct clientHelloSearchChunk {
    unsigned int seq;
    unsigned int ip;
    unsigned char life;
    unsigned short exttype;
    unsigned short extlen;
    unsigned short stage; //stage 0: sent first byte of ext type, stage 1: interrupted by incomplete payload, sent second byte of ext type, stage 2: sent second byte of ext type and first byte of ext len, stage 3: sent second byte of ext len, proceed with fragmenting along ext len, stage 4: perfectly fragmented, initiate as usual
};
struct conntracksig { //Rudimentary conntrack. This also means that if you shut down goodbyeDPI, all goes to shit and everything needs to reconnect.
    WINDIVERT_ADDRESS addr;
    int offset;
    unsigned int ip;
    unsigned int upperseq; //SEQ upper bound
    unsigned int lowerseq; //SEQ lower bound
    unsigned int originseq;
    unsigned int remoteseq;
    unsigned short clientport;
    unsigned short nextpacketid;
    unsigned short mss;
    unsigned short illegalsegmentlen;
    unsigned char busy;
    unsigned char retransmits;
    unsigned char outfin;
    unsigned char infin;
    unsigned char illegalsegment[MAX_PACKET_SIZE * 2];
    char associatedsni[256];
};
struct fatasssig {
    unsigned short life;
    unsigned int ip;
    unsigned int seq;
    unsigned int originseq;
    unsigned short recordlength;
    unsigned short expectedlength;
    unsigned char iphdrlen;
    unsigned char dOffset;
    unsigned char packet[4216];
};
struct fatasssig* fatass = NULL;
unsigned short fatasslen = 0;
struct conntracksig* conntrack;
unsigned int conntrack_ip;
unsigned int conntrack_seq;
struct fragmentInfoChunk* fragmentInfo;
struct clientHelloSearchChunk* clientHelloSearch;
void add_fragment(unsigned char* packet, struct fragmentInfoChunk* fragmentInfo, unsigned short* pfragmentInfoLen) {
    //Skip over to the whole- yeah, this is just copied code from reassemble_segments
    hdrLen = (packet[0] & 0x0F) * 4;
    dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    convert_endian(&tcpSeq, packet + hdrLen + 4, 4);
    convert_endian(&totalLength, packet + 2, 2);
    fragmentInfo[*pfragmentInfoLen].seq = tcpSeq;
    fragmentInfo[*pfragmentInfoLen].payloadLen = totalLength - hdrLen - dataOffset;
    //printf("DEBUGGUS: %u, %u; %u, %u\n", fragmentInfo[*pfragmentInfoLen].seq, fragmentInfo[*pfragmentInfoLen].payloadLen, tcpSeq, totalLength - hdrLen - dataOffset);
    fragmentInfoLen++;
}
int main(int argc, char *argv[]) {
    //hexbuff[2] = (char)0;
    fragmentHolder = calloc(MAX_PACKET_SIZE, sizeof(char));
    reassemblePacket = calloc(MAX_PACKET_SIZE, sizeof(char));
    fatass = calloc(512, sizeof(struct fatasssig));
    unsigned char* illegalSegment = calloc(MAX_PACKET_SIZE * 2, sizeof(unsigned char));
    unsigned short illegalSegmentLen = 0;
    unsigned char fakehost[HOST_MAXLEN];
    unsigned char* reassembleSegments = calloc(4216, sizeof(unsigned char));
    unsigned char* packetBACK = calloc(MAX_PACKET_SIZE * 8, sizeof(unsigned char));
    fragmentInfo = calloc(MAX_PACKET_SIZE - 40, sizeof(struct fragmentInfoChunk));
    clientHelloSearch = calloc(25, sizeof(struct clientHelloSearchChunk));
    struct connection* connections = calloc(512, sizeof(struct connection));
    unsigned short connectionslen = 0;
    static enum packet_type_e {
        unknown,
        ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
        ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
    } packet_type;
    //uint16_t domainLen = 0;
    int i, should_reinject, should_recalc_checksum = 0,
    sni_ok = 0,
    opt,
    packet_v4, packet_v6;
    HANDLE w_filter = NULL;
    WINDIVERT_ADDRESS addr;
    unsigned char realpacket[MAX_PACKET_SIZE];
    unsigned char extendedpacket[MAX_PACKET_SIZE * 8];
    unsigned char* packet = NULL;
    unsigned char ctrack_fragmentHolder[MAX_PACKET_SIZE];
    unsigned char recordbuffer[65535]; //The giant enemy record.
    unsigned char* packet_data;
    UINT packetLen, packetBACKLen;
    UINT packet_dataLen;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_IPV6HDR ppIpV6Hdr;
    PWINDIVERT_TCPHDR ppTcpHdr;
    PWINDIVERT_UDPHDR ppUdpHdr;
    conntrack_info_t dns_conn_info;
    tcp_conntrack_info_t tcp_conn_info;
    unsigned int conntrack_maxlen = 0, disable_sack = 0, conntrack_curlen = 0, findmss = 0;
    int do_passivedpi = 0, do_block_quic = 0,
        do_fragment_http = 0,
        do_fragment_http_persistent = 0,
        do_fragment_http_persistent_nowait = 0,
        do_fragment_https = 0, do_host = 0,
        do_host_removespace = 0, do_additional_space = 0,
        do_http_allports = 0,
        do_host_mixedcase = 0,
        do_dnsv4_redirect = 0, do_dnsv6_redirect = 0,
        do_dns_verb = 0, drop_unsecure_dns = 0, do_tcp_verb = 0, do_blacklist = 0, do_whitelist = 0,
        do_allow_no_sni = 0,
        do_fragment_by_sni = 0,
        do_fake_packet = 0,
        do_auto_ttl = 0,
        do_wrong_chksum = 0,
        do_wrong_seq = 0,
        allow_sni_overlap = 0,
        tls_segmentation = 0,
        tls_rando_frag = 0,
        fragging_sni = 0,
        tls_len = 0,
        illegal_segments = 0,
        wacky_frag = 0, do_native_frag = 0, do_reverse_frag = 0, record_frag = 0, super_reverse = 0, rplrr = 0, rplrr_by_sni, reusable = 0, mss = 0, smart_frag = 0, compound_frag = 0, tls_force_native = 0, /*udp_fragments = 0, */proceed = 0, totalHdrLength = 0, acted = 0,
        vortex_frag = 0, vortex_frag_by_sni = 0, vortex_step = 0, vortex_left = 0, vortex_direction = 0, vortex_right = 0, vortex_step_left = 1, vortex_step_right = 1, vortex_relevant = 0, freeWaiting = 0; //"Big boy words" my ass, it's literally vortex shaped.
    unsigned int http_fragment_size = 0, https_fragment_size = 0, tls_segment_size = 0, sni_fragment_size = 0, ext_frag_size = 0, tls_absolute_frag = 0, tls_recseg_size = 0, current_fragment_size = 0, udp_fakes = 0, progress = 0, addoffset = 0, alter_max_record_len = 0;
    unsigned short max_payload_size = 0, extensionLen = 0, extensionType = 0, sni_padding = 0, cleave_sni = 0;
    short host_shiftback = 0;
    BYTE should_send_fake = 0;
    BYTE ttl_of_fake_packet = 0;
    BYTE ttl_min_nhops = 0;
    BYTE auto_ttl_1 = 0;
    BYTE auto_ttl_2 = 0;
    BYTE auto_ttl_max = 0;
    uint32_t dnsv4_addr = 0;
    struct in6_addr dnsv6_addr = {0};
    struct in6_addr dns_temp_addr = {0};
    uint16_t dnsv4_port = htons(53);
    uint16_t dnsv6_port = htons(53);
    unsigned char *host_addr, *useragent_addr, *method_addr, reverse_fix = 0, fnroor = 0;
    unsigned int host_len, useragent_len, faketotallength = 0, tcpBaseSeq = 0, tcpBaseSeqTrue = 0;
    int http_req_fragmented;
    uint16_t fragmentLength = 0;
    char *hdr_name_addr = NULL, *hdr_value_addr = NULL, iphdrlen;
    unsigned int hdr_value_len;
    //Meet the thrash machine!
    unsigned char thrash_packet[65536];
    unsigned char thrash_fake[65536];
    UINT thrash_packetLen;
    WINDIVERT_ADDRESS thrash_addr;
    void xorinate(char* victim, unsigned int victimLen, char* key, unsigned int keyLen) {
        for (unsigned int vicPtr = 0; vicPtr < victimLen; vicPtr++) { //Very clever!
            victim[vicPtr] = victim[vicPtr] ^ key[vicPtr % keyLen];
        }
    }
    unsigned int checked[2048], checkedLen = 0;
    unsigned char mode = 0;
    char overlapping = 0;
    void do_fragmentation(unsigned char* packet) { //By moving fragmentation into this function, I can put it in many other things.

    }
    void do_super_reverse_frag(unsigned char mode, struct fragmentInfoChunk* fragmentInfo, unsigned short fragmentInfoLen, unsigned char* srcPacket, unsigned int tcpBaseSeq, unsigned short baseid) {
        unsigned char hdrLen = (srcPacket[0] & 0b00001111) * 4;
        unsigned char dataOffset = (srcPacket[hdrLen + 12] >> 4) * 4;
        unsigned short totalLength;
        unsigned short vortex_left = 0;
        unsigned short vortex_right = 0;
        unsigned short vortex_step = 0;
        unsigned short vortex_direction = 0;
        unsigned short vortex_relevant = 0;
        //printf("Begin Super Reverse\n");
        for (int i = 0; i < 2048; i++) {
            reassembleSegments[i] = 255;
            checked[i] = 0;
        }
        switch (mode) {
            case 1: // --vortex-frag
                vortex_left = vortex_frag_by_sni ? beginSni : 0;
                vortex_right = fragmentInfoLen - 1;
                vortex_step = 0;
                vortex_direction = 0;
                while (vortex_left != vortex_right) {
                    if (vortex_direction == 0 && vortex_step == vortex_step_left) {
                        vortex_relevant = vortex_right;
                        //printf("Alternating to RIGHT\n");
                        vortex_step = 0;
                        vortex_direction = 1;
                    }
                    else if (vortex_direction == 1 && vortex_step == vortex_step_right) {
                        vortex_relevant = vortex_left;
                        //printf("Alternating to LEFT\n");
                        vortex_step = 0;
                        vortex_direction = 0;
                    }
                    else {
                        //printf("Not alternating.\n");
                        if (vortex_direction == 1) vortex_relevant = vortex_right;
                        if (vortex_direction == 0) vortex_relevant = vortex_left;
                    }
                    //begin frag
                    tcpSeq = fragmentInfo[vortex_relevant].seq;
                    totalLength = hdrLen + dataOffset + fragmentInfo[vortex_relevant].payloadLen;
                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                    memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                    newpacketid(fragmentHolder);
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, &addr, 0
                    );
                    //reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, srcPacket + hdrLen + dataOffset);
                    WinDivertSend(
                        w_filter, fragmentHolder,
                        totalLength,
                        NULL, &addr
                    );
                    //ending sequence
                    if (vortex_direction == 0) vortex_left++;
                    else vortex_right--;
                    vortex_step++;
                }
                if (vortex_frag_by_sni) {
                    for (int i = beginSni - 1; i >= 0; i--) {
                        tcpSeq = fragmentInfo[i].seq;
                        totalLength = hdrLen + dataOffset + fragmentInfo[i].payloadLen;
                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                        memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                        newpacketid(fragmentHolder);
                        WinDivertHelperCalcChecksums(
                            fragmentHolder, totalLength, &addr, 0
                        );
                        //reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, srcPacket + hdrLen + dataOffset);
                        //differentiate(fragmentHolder + hdrLen + dataOffset, totalLength - dataOffset - hdrLen, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset, 1);
                        WinDivertSend(
                            w_filter, fragmentHolder,
                            totalLength,
                            NULL, &addr
                        );
                    }
                }
                break;
            case 2: // --rplrr
                //printf("Begin RPLRR\n");
                for (int i = 0; i < 2048; i++) {
                    reassembleSegments[i] = 255;
                    checked[i] = 0;
                }
                vortex_left = rplrr_by_sni ? beginSni : 0;
                vortex_step = 0;
                unsigned int backupInfoLen = fragmentInfoLen;
                if (rplrr_by_sni) fragmentInfoLen -= beginSni;
                while (fragmentInfoLen > 0) {
                    i = genrand16(ntohs(*((unsigned short*)(packet + 4)))) % fragmentInfoLen;
                    tcpSeq = fragmentInfo[i + vortex_left].seq;
                    totalLength = hdrLen + dataOffset + fragmentInfo[i + vortex_left].payloadLen;
                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                    memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                    newpacketid(fragmentHolder);
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, &addr, 0
                    );
                    //reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, srcPacket + hdrLen + dataOffset);
                    //differentiate(fragmentHolder + hdrLen + dataOffset, totalLength - dataOffset - hdrLen, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset, 1);
                    WinDivertSend(
                        w_filter, fragmentHolder,
                        totalLength,
                        NULL, &addr
                    );
                    if (i == 0) {
                        vortex_left++;
                        goto skipCondLeft;
                    }
                    else if (i == fragmentInfoLen - 1) {
                        fragmentInfoLen--;
                        goto skipAll;
                    }
                    else {
                        //printf("REPLACING\n");
                        //printf("PRE:  %u, %u\n", fragmentInfo[i + vortex_left].seq, fragmentInfo[i + vortex_left].payloadLen);
                        reusable = vortex_step % 2 == 0 ? vortex_left : fragmentInfoLen - 1 + vortex_left;
                        fragmentInfo[i + vortex_left].seq = fragmentInfo[reusable].seq;
                        fragmentInfo[i + vortex_left].payloadLen = fragmentInfo[reusable].payloadLen;
                        //printf("POST: %u, %u\n", fragmentInfo[i + vortex_left].seq, fragmentInfo[i + vortex_left].payloadLen);
                    }
                    if (vortex_step % 2 == 0) vortex_left++;
                    skipCondLeft:
                    fragmentInfoLen--;
                    skipAll:
                    vortex_step++;
                    //printf("Popped %u, Offset: %u\n", i + vortex_left, vortex_left);
                }
                if (rplrr_by_sni) {
                    for (int i = beginSni - 1; i >= 0; i--) {
                        tcpSeq = fragmentInfo[i].seq;
                        totalLength = hdrLen + dataOffset + fragmentInfo[i].payloadLen;
                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                        memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                        newpacketid(fragmentHolder);
                        WinDivertHelperCalcChecksums(
                            fragmentHolder, totalLength, &addr, 0
                        );
                        //reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, srcPacket + hdrLen + dataOffset);
                        //differentiate(fragmentHolder + hdrLen + dataOffset, totalLength - dataOffset - hdrLen, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset, 1);
                        WinDivertSend(
                            w_filter, fragmentHolder,
                            totalLength,
                            NULL, &addr
                        );
                    }
                }
                break;
            case 3: // --record-frag
                //Before this thing causes everything to go to shit, check if theres already a conntrack entry for this connection.
                for (int i = 0; i < conntrack_curlen; i++) {
                    if (conntrack[i].originseq == tcpBaseSeq) {
                        #ifdef TLSDEBUG
                        printf("DUPLICATE\n");
                        #endif
                        return;
                    }
                }
                //Find a free conntrack space. (REUSING VARIABLES!!!)
                freeWaiting = -1;
                for (int i = 0; i < conntrack_curlen; i++) {
                    if (conntrack[i].lowerseq == 0 && conntrack[i].ip == 0) {
                        freeWaiting = i;
                        break;
                    }
                }
                if (conntrack_curlen == conntrack_maxlen) {
                    printf("SHIT SHIT SHIT SHIT SHIT SHIT\n");
                    return;
                }
                if (freeWaiting == -1) {
                    freeWaiting = conntrack_curlen++;
                }
                //printf("Expecting SEQ %u\n", tcpBaseSeq + (packetLen + 5 - hdrLen - dataOffset) + (fragmentInfoLen - 1) * 5);
                conntrack[freeWaiting].busy = 1;
                conntrack[freeWaiting].ip = *((unsigned int*)(packet + 16));
                conntrack[freeWaiting].lowerseq = tcpBaseSeq + (packetLen + 5 - hdrLen - dataOffset) - (alter_max_record_len > 0 ? 6 : 0);
                conntrack[freeWaiting].upperseq = tcpBaseSeq + (packetLen + 5 - hdrLen - dataOffset) - (alter_max_record_len > 0 ? 6 : 0);
                conntrack[freeWaiting].offset = (fragmentInfoLen - 1) * 5 + addoffset;
                conntrack[freeWaiting].originseq = tcpBaseSeq;
                conntrack[freeWaiting].illegalsegmentlen = 0;
                conntrack[freeWaiting].mss = 1200;
                for (int i = 0; i < host_len; i++) {
                    conntrack[freeWaiting].associatedsni[i] = host_addr[i];
                }
                conntrack[freeWaiting].clientport = ntohs((*((unsigned short*)(srcPacket + hdrLen))));
                conntrack[freeWaiting].associatedsni[host_len] = 0;
                conntrack[freeWaiting].nextpacketid = ntohs(*((unsigned short*)(srcPacket + 4)));
                conntrack[freeWaiting].outfin = 0; 
                conntrack[freeWaiting].infin = 0;
                conntrack[freeWaiting].busy = 0;
                //printf("Packets beginning from SEQ %u will now have their SEQ shifted by %u bytes.\n", conntrack[freeWaiting].lowerseq, conntrack[freeWaiting].offset);
                #ifdef TLSDEBUG
                printf("Expecting an inbound ACK of %u, Relative ACK: %u\n", conntrack[freeWaiting].upperseq + conntrack[freeWaiting].offset, conntrack[freeWaiting].upperseq + conntrack[freeWaiting].offset - conntrack[freeWaiting].originseq);
                #endif
                tls_reassembly_progress = 0;
                progress = 0;
                unsigned short begin_sni;
                unsigned short end_sni;
                for (int i = 0; i < fragmentInfoLen; i++) {
                    memcpy(recordbuffer + progress + 5, srcPacket + hdrLen + dataOffset + (fragmentInfo[i].seq - tcpBaseSeq), fragmentInfo[i].payloadLen);
                    *((unsigned int*)(recordbuffer + progress)) = 0x00010316; //Clever, not clever.
                    *((unsigned short*)(recordbuffer + progress + 3)) = htons(fragmentInfo[i].payloadLen + (i == fragmentInfoLen - 1 ? overload : 0));
                    reassemble_tls_bald(recordbuffer + progress);
                    if (i == beginSni) begin_sni = progress;
                    if (i == endSni) end_sni = progress + 5 + fragmentInfo[i].payloadLen;
                    progress += 5 + fragmentInfo[i].payloadLen;
                }
                unsigned short midpoint = begin_sni + ((end_sni - begin_sni) / 2);
                tls_len = progress;
                progress = 0;
                //for (int i = 0; i < fragmentInfoLen; i++) {
                //    reassemble_tls_bald(recordbuffer + progress); //BALD! BALD! MY EYEEEEEEEEEES!!!!!
                //    progress += fragmentInfo[i].payloadLen + 5;
                //}
                unsigned int headercatch = 0;
                memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                fragmentInfoLen = 0;
                while (progress != tls_len) {
                    if (fragmentInfoLen == 1) {
                        beginSni = fragmentInfoLen;
                    }
                    current_fragment_size = (!reverse_fix || progress != 0) ? tls_recseg_size : tls_len % tls_recseg_size;
                    if (begin_sni > progress && ((begin_sni - (progress + tls_recseg_size) < tls_recseg_size) || (begin_sni < (progress - tls_recseg_size)))) {
                        current_fragment_size = midpoint - progress;
                    }
                    if (progress + current_fragment_size >= tls_len) { //Uh oh.
                        current_fragment_size = tls_len - progress;
                        if (current_fragment_size == 0) break;
                    }
                    memcpy(fragmentHolder + hdrLen + dataOffset, recordbuffer + progress, current_fragment_size);
                    totalLength = hdrLen + dataOffset + current_fragment_size;
                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                    tcpSeq = tcpBaseSeq + progress;
                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                    newpacketid(fragmentHolder);
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, &addr, 0
                    );
                    if (!tls_force_native) {
                        add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                        fragmentInfoLen++;
                    }
                    else 
                    WinDivertSend(
                        w_filter, fragmentHolder,
                        totalLength,
                        NULL, &addr
                    );
                    progress += current_fragment_size;
                }
                conntrack[freeWaiting].nextpacketid = ntohs(*((unsigned short*)(srcPacket + 4))) + fragmentInfoLen;
                memmove(recordbuffer + hdrLen + dataOffset, recordbuffer, tls_len);
                memcpy(recordbuffer, packetBACK, hdrLen + dataOffset);
                mode = 0;
                if (vortex_frag) mode = 1;
                else if (rplrr) mode = 2;
                else if (illegal_segments && illegalSegmentLen > 0) mode = 4;
                //printf("Sending %u fragments.\n", fragmentInfoLen);
                if (!tls_force_native)
                do_super_reverse_frag(mode, fragmentInfo, fragmentInfoLen, recordbuffer, tcpBaseSeqTrue, 0);
                #ifdef TLSPRINT
                xprint(srcPacket + hdrLen + dataOffset + 5, packetLen - dataOffset - hdrLen, 40);
                printf("\n\n");
                xprint(reassembleTls, packetLen - dataOffset - hdrLen, 40);
                printf("\n");
                differentiate(srcPacket + hdrLen + dataOffset + 5, packetLen - dataOffset - hdrLen, reassembleTls, packetLen - dataOffset - hdrLen, 0);
                if (tls_reassembly_progress != packetLen - dataOffset - hdrLen) printf("ERROR: MESSAGE LENGTH MISMATCH\n");
                #endif
                break;
            case 4: // Internal fragmentation mode for record fragmentation.
                tcpBaseSeqTrue = tcpBaseSeq;
                unsigned short mss = 1200;
                for (int i = 0; i < connectionslen; i++) {
                    if (connections[i].taken && connections[i].ip == *((unsigned int*)(srcPacket + 16)) && connections[i].seq == ntohl(*((unsigned int*)(srcPacket + hdrLen + 4)))) {
                        mss = connections[i].mss;
                        connections[i].taken = 0;
                        break;
                    }
                }
                if (mss == 1200) printf("ERROR: CONNECTION TRACKING FAIL\n");
                tcpBaseSeq -= illegalSegmentLen - hdrLen - dataOffset;
                for (int i = 0; i < fragmentInfoLen; i++) {
                    printf("fragment %u\n", i + 1);
                    totalLength = illegalSegmentLen + fragmentInfo[i].payloadLen;
                    memcpy(illegalSegment + illegalSegmentLen, srcPacket + hdrLen + dataOffset + (fragmentInfo[i].seq - tcpBaseSeqTrue), fragmentInfo[i].payloadLen);
                    progress = 0;
                    static unsigned short auxTotalLength = 0;
                    while (progress != totalLength - hdrLen - dataOffset) {
                        printf("processing %u/%u\n", progress, totalLength - hdrLen - dataOffset);
                        current_fragment_size = mss;
                        if (progress + current_fragment_size >= totalLength - hdrLen - dataOffset) { //Uh oh.
                            current_fragment_size = (unsigned int) (totalLength - hdrLen - dataOffset - progress);
                            printf("Uh oh! %u\n", current_fragment_size);
                            if (current_fragment_size == 0) break;
                        }
                        memcpy(fragmentHolder + hdrLen + dataOffset, illegalSegment + hdrLen + dataOffset + progress, current_fragment_size);
                        auxTotalLength = hdrLen + dataOffset + current_fragment_size;
                        convert_endian(fragmentHolder + 2, &auxTotalLength, 2);
                        tcpSeq = tcpBaseSeq + progress;
                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                        newpacketid(fragmentHolder);
                        WinDivertHelperCalcChecksums(
                            fragmentHolder, auxTotalLength, &addr, 0
                        );
                        WinDivertSend(
                            w_filter, fragmentHolder,
                            auxTotalLength,
                            NULL, &addr
                        );
                        progress += current_fragment_size;
                    }
                }
                break;
            default:
                memcpy(fragmentHolder, srcPacket, hdrLen + dataOffset);
                for (int i = fragmentInfoLen - 1; i >= 0; i--) {
                    tcpSeq = fragmentInfo[i].seq;
                    totalLength = hdrLen + dataOffset + fragmentInfo[i].payloadLen;
                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                    memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                    if (!baseid) newpacketid(fragmentHolder);
                    else {
                        *((unsigned short*)(srcPacket + 4)) = htons(baseid++);
                    }
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, &addr, 0
                    );
                    //differentiate(fragmentHolder + hdrLen + dataOffset, totalLength - dataOffset - hdrLen, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset, 1);
                    WinDivertSend(
                        w_filter, fragmentHolder,
                        totalLength,
                        NULL, &addr
                    );
                }
                break;
        }
        //printf("Finish reverse\n");
    }
    void* thrash() { //Why do I need a void* function instead of a void? Oh well.
        thrash_filter = WinDivertOpen("outbound and udp and !impostor and !loopback and udp.DstPort > 49999 and udp.DstPort < 50100\0", WINDIVERT_LAYER_NETWORK, 1, 0);
        if (thrash_filter != INVALID_HANDLE_VALUE)
        while (!exiting) {
            if (WinDivertRecv(thrash_filter, thrash_packet, 65536, &thrash_packetLen, &thrash_addr)) {
			    WinDivertHelperCalcChecksums(thrash_packet, thrash_packetLen, &thrash_addr, 0);
                memcpy(thrash_fake, thrash_packet, thrash_packetLen);
                //Encapsulate in trash
                xorinate(thrash_fake + 28, 20 % (thrash_packetLen - 28), "IAMTHRASH", 9);
			    WinDivertHelperCalcChecksums(thrash_fake, thrash_packetLen, &thrash_addr, 0);
                for (int i = 0; i < (udp_fakes / 2 + udp_fakes % 2); i++) {
                    WinDivertSend(thrash_filter, thrash_fake, thrash_packetLen, NULL, &thrash_addr);
                }
                WinDivertSend(thrash_filter, thrash_packet, thrash_packetLen, NULL, &thrash_addr);
                for (int i = 0; i < (udp_fakes / 2); i++) {
                    WinDivertSend(thrash_filter, thrash_fake, thrash_packetLen, NULL, &thrash_addr);
                }
            }
        }
    }
    unsigned char synner_packet[256]; //SYN packets cannot possibly be any larger than this.
    UINT synner_packetLen;
    WINDIVERT_ADDRESS synner_addr;
    //'tis hardcoded.
    unsigned char synnerhdrLen = 0, synnerdataOffset = 0;
    #ifndef DOLOCALNETS
    char synner_filter_str_default[] = "!impostor && !loopback && tcp.Syn && ((outbound && tcp.DstPort == 443) || (inbound && tcp.Ack && tcp.SrcPort == 443))\0";
    char synner_filter_str_discord_vc[] = "!impostor && !loopback && tcp.Syn && ((outbound && (tcp.DstPort == 443 || (tcp.DstPort > 1999 && tcp.DstPort < 2100))) || (inbound && tcp.Ack && (tcp.SrcPort == 443 || (tcp.SrcPort > 1999 && tcp.SrcPort < 2100))))\0";
    #else
    char synner_filter_str_default[] = "!impostor && tcp.Syn && ((outbound && tcp.DstPort == 443) || (inbound && tcp.Ack && tcp.SrcPort == 443))\0";
    char synner_filter_str_discord_vc[] = "!impostor && tcp.Syn && ((outbound && (tcp.DstPort == 443 || (tcp.DstPort > 1999 && tcp.DstPort < 2100))) || (inbound && tcp.Ack && (tcp.SrcPort == 443 || (tcp.SrcPort > 1999 && tcp.SrcPort < 2100))))\0";
    #endif
    char* synner_filter_str = synner_filter_str_default;
    short connfreewaiting;
    void* synner() { //For accessing SYN packets without the clutter of main()
        synner_filter = WinDivertOpen(synner_filter_str, WINDIVERT_LAYER_NETWORK, 2, 0);
        if (synner_filter != INVALID_HANDLE_VALUE)
        while (!exiting) {
            if (WinDivertRecv(synner_filter, synner_packet, 256, &synner_packetLen, &synner_addr)) {
                synnerhdrLen = (synner_packet[0] & 0xF) * 4;
                synnerdataOffset = (synner_packet[synnerhdrLen + 12] >> 4) * 4;
                connfreewaiting = -1;
                if (!synner_addr.Outbound) {
                    for (int i = 0; i < connectionslen; i++) {
                        if (!connections[i].taken && connfreewaiting == -1) {
                            connfreewaiting = i;
                        }
                        else if (connections[i].taken) {
                            connections[i].life += 1;
                            if (connections[i].life > 256) connections[i].taken = 0;
                        }
                    }
                    if (connfreewaiting == -1 && connectionslen == 512) {
                        printf("FATAL SYNNING ERROR\n");
                        break;
                    }
                    else if (connfreewaiting == -1) {
                        connfreewaiting = connectionslen++;
                    }
                    if (connfreewaiting != -1) {
                        connections[connfreewaiting].ip = *((unsigned int*)(synner_packet + 12));
                        connections[connfreewaiting].seq = ntohl(*((unsigned int*)(synner_packet + synnerhdrLen + 8)));
                    }
                }
                findmss = 0;
                //Locate the MSS option.
                for (int i = synnerhdrLen; i < synnerdataOffset; i += synner_packet[synnerhdrLen + i] > 1 ? synner_packet[synnerhdrLen + i + 1] : 1) { //Actually cramming logic in there. Amazing.
                    if (synner_packet[synnerhdrLen + i] == 2) {
                        findmss = i + 2;
                        break;
                    }
                }
                if (findmss != 0) {
                    if (mss > 0) {
                        if (ntohs(*((unsigned short*)(synner_packet + synnerhdrLen + findmss))) > mss && synner_addr.Outbound) { //Now not stupid!
                            *((unsigned short*)(synner_packet + synnerhdrLen + findmss)) = htons(mss);
                        }
                    }
                    if (!synner_addr.Outbound) {
                        connections[connfreewaiting].mss = ntohs(*((unsigned short*)(synner_packet + synnerhdrLen + findmss)));
                        printf("Associating connection with SEQ %u with IP %u.%u.%u.%u to MSS %u\n", connections[connfreewaiting].seq, ((unsigned char*)&(connections[connfreewaiting].ip))[0], ((unsigned char*)&(connections[connfreewaiting].ip))[1], ((unsigned char*)&(connections[connfreewaiting].ip))[2], ((unsigned char*)&(connections[connfreewaiting].ip))[3], connections[connfreewaiting].mss);
                    }
                }
                if (disable_sack && synner_addr.Outbound) { //Remove SACK_PERM.
                    for (int i = synnerhdrLen; i < synnerdataOffset; i += synner_packet[synnerhdrLen + i] > 1 ? synner_packet[synnerhdrLen + i + 1] : 1) { //Actually cramming logic in there. Amazing.
                        if (synner_packet[synnerhdrLen + i] == 4) {
                            synner_packet[synnerhdrLen + i] = 1; //Replace Option-Kind with NOP.
                            synner_packet[synnerhdrLen + i + 1] = 1; //Replace Option-Length with NOP.
                        }
                    }
                }
                WinDivertHelperCalcChecksums(synner_packet, synner_packetLen, &synner_addr, 0);
                WinDivertSend(synner_filter, synner_packet, synner_packetLen, NULL, &synner_addr);
                if (!synner_addr.Outbound) connections[connfreewaiting].taken = 1;
            }
            else {
                printf("synning error: %u\n", GetLastError());
                break;
            }
        }
        else printf("synner init error %u\n", GetLastError());
    }
    unsigned char conntrack_packet[65536], conntrack_fragholder[65536];
    UINT conntrack_packetLen;
    WINDIVERT_ADDRESS conntrack_addr;
    unsigned short conntrack_progress = 0;
    //'tis hardcoded.
    unsigned char conntrack_should_reinject = 0, conntrackhdrLen = 0, conntrackdataOffset = 0;
    #ifndef DOLOCALNETS
    char conntrack_filter_str_default[] = "!tcp.Syn && !impostor and !loopback and ((inbound and tcp.SrcPort == 443 and tcp.Ack) or (outbound and tcp.DstPort == 443))\0",
         conntrack_filter_str_discord_vc[] = "!tcp.Syn && !impostor and !loopback and ((inbound and tcp.SrcPort == 443) or (outbound and tcp.DstPort == 443) or (outbound and tcp.DstPort > 1999 and tcp.DstPort < 2100))\0";
    #else
    char conntrack_filter_str_default[] = "!tcp.Syn && !impostor and (((inbound or loopback) and tcp.SrcPort == 443 and tcp.Ack) or (outbound and tcp.DstPort == 443))\0",
         conntrack_filter_str_discord_vc[] = "!tcp.Syn && !impostor and (((inbound or loopback) and tcp.SrcPort == 443) or (outbound and tcp.DstPort == 443) or (outbound and tcp.DstPort > 1999 and tcp.DstPort < 2100))\0";
    #endif
    char *conntrack_filter_str = conntrack_filter_str_default, final_ack = 0, conntrack_outbound = 0;
    unsigned int ctrack_tcpSeq = 0;
    void* do_conntrack() { //The backbone of advanced GoodbyeDPI functionality. It's also crazy slow. But neater now.
        conntrack_filter = WinDivertOpen(conntrack_filter_str, WINDIVERT_LAYER_NETWORK, 2, 0);
        if (conntrack_filter != INVALID_HANDLE_VALUE)
        while (!exiting) {
            if (WinDivertRecv(conntrack_filter, conntrack_packet, 65536, &conntrack_packetLen, &conntrack_addr)) {
                final_ack = 0;
                conntrack_should_reinject = 1;
                conntrackhdrLen = (conntrack_packet[0] & 0xF) * 4;
                conntrackdataOffset = (conntrack_packet[conntrackhdrLen + 12] >> 4) * 4;
                convert_endian(&conntrack_packetLen, conntrack_packet + 2, 2);
                conntrack_outbound = conntrack_addr.Outbound && ntohs(*((unsigned short*)(conntrack_packet + conntrackhdrLen))) != 443;
                conntrack_ip = *(conntrack_outbound ? (unsigned int*)(conntrack_packet + 16) : (unsigned int*)(conntrack_packet + 12));
                conntrack_seq = conntrack_outbound ? ntohl(*((unsigned int*)(conntrack_packet + conntrackhdrLen + 4))) : ntohl(*((unsigned int*)(conntrack_packet + conntrackhdrLen + 8)));
                for (int i = 0; i < conntrack_curlen; i++) {
                    if (!conntrack[i].busy && conntrack[i].ip == conntrack_ip && ((conntrack_outbound ? conntrack_seq : conntrack_seq - conntrack[i].offset) >= conntrack[i].lowerseq && (conntrack_outbound ? conntrack_seq : conntrack_seq - conntrack[i].offset) <= conntrack[i].upperseq)) {
                        if (*(conntrack_packet + conntrackhdrLen + 13) & 0b00000001) {
                            if (conntrack_outbound) {
                                printf("OUTBOUND FIN\n");
                                conntrack[i].outfin = 1;
                            }
                            else {
                                printf("INBOUND FIN\n");
                                conntrack[i].infin = 1;
                            }
                        }
                        if (conntrack[i].infin && conntrack[i].outfin && (*(conntrack_packet + conntrackhdrLen + 13) & 0b00010000) > 0) {
                            printf("FINALIZING\n");
                            final_ack = 1;
                            *((unsigned int*)(conntrack_packet + conntrackhdrLen + 8)) = htonl(conntrack_seq - conntrack[i].offset);
                        }
                        if (conntrack_outbound) {
                            //*((unsigned short*)(conntrack_packet + 4)) = htons(conntrack[i].nextpacketid++);
                            newpacketid(conntrack_packet);
                            *((unsigned int*)(conntrack_packet + conntrackhdrLen + 4)) = htonl(conntrack_seq + conntrack[i].offset);
                            if (conntrack_seq + (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset) == conntrack[i].upperseq + (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset)) { //A healthy packet. Connection tracking can be done safely.
                                if ((conntrack[i].upperseq + (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset)) < conntrack[i].upperseq) { //Wrapping around...
                                    printf("Wrapping around.\n");
                                    conntrack[i].lowerseq = conntrack[i].upperseq + (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset);
                                }
                                conntrack[i].upperseq += (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset);
                                conntrack[i].retransmits = 0;
                            }
                            else if (conntrack_seq + (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset) > conntrack[i].upperseq) //A traffic anomaly. Not something that should ever happen, but I am not hoping for everything to be valid.
                                conntrack[i].upperseq = conntrack_seq + (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset);
                            else { //It's a retransmit. It should probably be handled somehow.
                                switch (conntrack[i].retransmits++) {
                                    case 0: //Try doing reverse fragmentation.
                                        if (https_fragment_size && https_fragment_size < (conntrack_packetLen - conntrackhdrLen - conntrackdataOffset)) {
                                            conntrack_should_reinject = 0;
                                            memcpy(conntrack_fragholder, conntrack_packet, conntrackhdrLen + conntrackdataOffset);
                                            //Thinking with pointers.
                                            memcpy(conntrack_fragholder + conntrackhdrLen + conntrackdataOffset, conntrack_packet + conntrackhdrLen + conntrackdataOffset + https_fragment_size, conntrack_packetLen - conntrackhdrLen - conntrackdataOffset - https_fragment_size);
                                            *((unsigned int*)(conntrack_fragholder + conntrackhdrLen + 4)) = htonl(conntrack_seq + conntrack[i].offset + https_fragment_size);
                                            *((unsigned int*)(conntrack_fragholder + 2)) = htons(conntrack_packetLen - https_fragment_size);
                                            WinDivertHelperCalcChecksums(conntrack_fragholder, conntrack_packetLen - https_fragment_size, &conntrack_addr, 0);
                                            WinDivertSend(conntrack_filter, conntrack_fragholder, conntrack_packetLen - https_fragment_size, NULL, &conntrack_addr);
                                            //Now the second one.
                                            memcpy(conntrack_fragholder + conntrackhdrLen + conntrackdataOffset, conntrack_packet + conntrackhdrLen + conntrackdataOffset, https_fragment_size);
                                            *((unsigned int*)(conntrack_fragholder + conntrackhdrLen + 4)) = htonl(conntrack_seq + conntrack[i].offset);
                                            *((unsigned int*)(conntrack_fragholder + 2)) = htons(https_fragment_size + conntrackhdrLen + conntrackdataOffset);
                                            //*((unsigned short*)(conntrack_fragholder + 4)) = htons(conntrack[i].nextpacketid++);
                                            newpacketid(conntrack_fragholder);
                                            WinDivertHelperCalcChecksums(conntrack_fragholder, https_fragment_size + conntrackhdrLen + conntrackdataOffset, &conntrack_addr, 0);
                                            WinDivertSend(conntrack_filter, conntrack_fragholder, https_fragment_size + conntrackhdrLen + conntrackdataOffset, NULL, &conntrack_addr);
                                        }
                                        break;
                                    default: //Nothing's working, so let's fuck around and see what information we can gather.
                                        *((unsigned short*)(conntrack_packet + 4)) = 12345; //Sign it.
                                        *((unsigned int*)(conntrack_packet + conntrackhdrLen + 4)) = htonl(conntrack_seq - 200); //Send it in the past. See what happens.
                                        *((unsigned int*)(conntrack_packet + conntrackhdrLen + 8)) = htonl(ntohl(*((unsigned int*)(conntrack_packet + conntrackhdrLen + 8))) + 200); //Send it also acknowledging the future. See what happens.
                                }
                            }
                        }
                        else {
                            conntrack[i].remoteseq = ntohl(*((unsigned int*)(conntrack_packet + conntrackhdrLen + 4)));
                            *((unsigned int*)(conntrack_packet + conntrackhdrLen + 8)) = htonl(conntrack_seq - conntrack[i].offset);
                        }
                        if (final_ack || ((*(conntrack_packet + conntrackhdrLen + 13) & 0b00000100) > 0)) { //Annihilate the conntrack connection if this packet fully terminates the connection.
                            conntrack[i].busy = 0; conntrack[i].ip = 0; conntrack[i].lowerseq = 0; 
                            conntrack[i].upperseq = 0; conntrack[i].offset = 0; conntrack[i].originseq = 0; 
                            conntrack[i].nextpacketid = 0;
                            conntrack[i].outfin = 0; conntrack[i].infin = 0;
                            conntrack[i].retransmits = 0;
                        }
                        break; //WHY DID I FORGET THIS??????????????????????????????
                    }
                    else if (conntrack[i].ip == conntrack_ip) {
                        if (conntrack_outbound && conntrack_seq > conntrack[i].upperseq && conntrack_seq - conntrack[i].upperseq < 600) printf("proximity alert, this likely means a missed packet and conntrack is failing. (%s)\n", (conntrack_addr.Outbound && ntohs(*((unsigned short*)(conntrack_packet + conntrackhdrLen))) != 443) ? "Outbound" : "Inbound");
                        if (conntrack_seq < conntrack[i].lowerseq && conntrack_seq >= conntrack[i].originseq) conntrack_should_reinject = 0;
                    }
                }
                WinDivertHelperCalcChecksums(conntrack_packet, conntrack_packetLen, &conntrack_addr, 0);
                if (conntrack_should_reinject) {
                    WinDivertSend(conntrack_filter, conntrack_packet, conntrack_packetLen, NULL, &conntrack_addr);
                }
            }
            else {
                printf("conntrack receive error %u\n", GetLastError());
                break;
            }
        }
        else printf("conntrack init error %u\n", GetLastError());
    }
    // Make sure to search DLLs only in safe path, not in current working dir.
    SetDllDirectory("");
    SetSearchPathMode(BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE | BASE_SEARCH_PATH_PERMANENT);

    if (!running_from_service) {
        running_from_service = 1;
        if (service_register(argc, argv)) {
            /* We've been called as a service. Register service
             * and exit this thread. main() would be called from
             * service.c next time.
             *
             * Note that if service_register() succeedes it does
             * not return until the service is stopped.
             * That is why we should set running_from_service
             * before calling service_register and unset it
             * afterwards.
             */
            return 0;
        }
        running_from_service = 0;
    }

    if (filter_string == NULL)
        filter_string = strdup(FILTER_STRING_TEMPLATE);
    if (filter_passive_string == NULL)
        filter_passive_string = strdup(FILTER_PASSIVE_STRING_TEMPLATE);

    printf(
        "GoodbyeDPI " GOODBYEDPI_VERSION
        ": Passive DPI blocker and Active DPI circumvention utility\n"
        "https://github.com/0mori1/GoodbyeDPI, Fork of https://github.com/ValdikSS/GoodbyeDPI\n\n"
    );

    if (argc == 1) {
        /* enable mode -9 by default */
        do_fragment_http = do_fragment_https = 1;
        do_reverse_frag = do_native_frag = 1;
        http_fragment_size = https_fragment_size = 2;
        do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
        do_fake_packet = 1;
        do_wrong_chksum = 1;
        do_wrong_seq = 1;
        do_block_quic = 1;
        max_payload_size = 1200;
    }

    while ((opt = getopt_long(argc, argv, "123456789pqrsafy:e:mwk:n", long_options, NULL)) != -1) {
        switch (opt) {
            case '0':
                vortex_frag = 1;
                break;
            case '1':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                break;
            case '2':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_http = do_fragment_https \
                = do_fragment_http_persistent \
                = do_fragment_http_persistent_nowait = 1;
                https_fragment_size = 40u;
                break;
            case '3':
                do_passivedpi = do_host = do_host_removespace \
                = do_fragment_https = 1;
                https_fragment_size = 40u;
                break;
            case '4':
                do_passivedpi = do_host = do_host_removespace = 1;
                break;
            case '5':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_auto_ttl = 1;
                max_payload_size = 1200;
                break;
            case '6':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_seq = 1;
                max_payload_size = 1200;
                break;
            case '9': // +7+8
                do_block_quic = 1;
                // fall through
            case '8': // +7
                do_wrong_seq = 1;
                // fall through
            case '7':
                do_fragment_http = do_fragment_https = 1;
                do_reverse_frag = do_native_frag = 1;
                http_fragment_size = https_fragment_size = 2;
                do_fragment_http_persistent = do_fragment_http_persistent_nowait = 1;
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                max_payload_size = 1200;
                break;
            case 'p':
                do_passivedpi = 1;
                break;
            case 'P': // --rplrr
                rplrr = 1;
                break;
            case 'N': // --cleave-sni
                cleave_sni = 1;
                break;
            case 'q':
                do_block_quic = 1;
                break;
            case 'Q': // --reverse-fix
                reverse_fix = 1;
                break;
            case 'r':
                do_host = 1;
                break;
            case 's':
                do_host_removespace = 1;
                break;
            case 'a':
                do_additional_space = 1;
                do_host_removespace = 1;
                break;
            case '_':
                super_reverse = 1;
                break;
            case 'h':
                smart_frag = 1;
                if (!ext_frag_size) ext_frag_size = 4;
                break;
            case 'm':
                do_host_mixedcase = 1;
                break;
            case 'C': // --tls-recseg-size
                tls_recseg_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case '-': // --discord-vc
                const char *tcp = " or (outbound and tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
                                  "(tcp.DstPort > 1999 and tcp.DstPort < 2100))";
                char *current_filter = filter_string;
                size_t new_filter_size = strlen(current_filter) + strlen(tcp) + 16;
                char *new_filter = malloc(new_filter_size);

                strcpy(new_filter, current_filter);
                sprintf(new_filter + strlen(new_filter), tcp);

                filter_string = new_filter;
                free(current_filter);
                activate_thrash = 1;
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg && atousi(optarg, "UDP Fake packet assignment error!") > 0)
                    udp_fakes = atousi(optarg, "UDP Fake packet assignment error!");
                else
                    udp_fakes = 1;
                conntrack_filter_str = conntrack_filter_str_discord_vc;
                break;
            case 'd': // --dns-addr
                if ((inet_pton(AF_INET, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv4_redirect)
                {
                    do_dnsv4_redirect = 1;
                    if (inet_pton(AF_INET, optarg, &dnsv4_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V4_ADDR);
                    }
                    add_filter_str(IPPROTO_UDP, 53);
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V4_ADDR);
                break;
            case 'J': // --mss
                mss = atousi(optarg, "MSS should be in range [0 - 65535]\n");
                synning = 1;
                break;
            case 'f':
                do_fragment_http = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case '#':
                sni_fragment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case 'k':
                do_fragment_http_persistent = 1;
                do_native_frag = 1;
                SET_HTTP_FRAGMENT_SIZE_OPTION(atousi(optarg, "Fragment size should be in range [0 - 0xFFFF]\n"));
                break;
            case 'K':
                host_shiftback = atoi(optarg);
                break;
            case 'n':
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                do_native_frag = 1;
                break;
            case 'e':
                do_fragment_https = 1;
                https_fragment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case '^':
                do_blacklist = 1;
                if (!blackwhitelist_load_list(optarg, 0)) {
                    printf("Can't load blacklist from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case '&':
                if (!do_blacklist) {
                    do_whitelist = 1;
                    if (!blackwhitelist_load_list(optarg, 1)) {
                        printf("Can't load whitelist from file!\n");
                        exit(ERROR_BLACKLIST_LOAD);
                    }
                }
                else {
                    printf("WARNING: Whitelist and blacklist specified. Whitelist has no effect.");
                }
                break;
            case 'B':
                illegal_segments = 1;
                if (!blackwhitelist_load_list(optarg, 3)) {
                    printf("Can't load fake SNI map from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case 'w':
                do_http_allports = 1;
                break;
            case 'W':
                fnroor = 1;
                break;
            case 'V': // --vortex-frag-by-sni
                vortex_frag_by_sni = 1;
                break;
            case 'z': // --port
                /* i is used as a temporary variable here */
                i = atoi(optarg);
                if (i <= 0 || i > 65535) {
                    printf("Port parameter error!\n");
                    exit(ERROR_PORT_BOUNDS);
                }
                if (i != 80 && i != 443)
                    add_filter_str(IPPROTO_TCP, i);
                i = 0;
                break;
            case 'Z':
                disable_sack = 1;
                synning = 1;
                break;
            case 'i': // --ip-id
                /* i is used as a temporary variable here */
                i = atousi(optarg, "IP ID parameter error!\n");
                add_ip_id_str(i);
                i = 0;
                break;
            case 'A':
                vortex_step_left = atousi(optarg, "Step bias should be in range [1 - 4]\n") > 0 ? atousi(optarg, "Step bias should be in range [1 - 4]\n") : 1;
                break;
            case 'D':
                vortex_step_right = atousi(optarg, "Step bias should be in range [1 - 4]\n") > 0 ? atousi(optarg, "Step bias should be in range [1 - 4]\n") : 1;
                break;
            case 'M':
                tls_segment_size = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case '!': // --dnsv6-addr
                if ((inet_pton(AF_INET6, optarg, dns_temp_addr.s6_addr) == 1) &&
                    !do_dnsv6_redirect)
                {
                    do_dnsv6_redirect = 1;
                    if (inet_pton(AF_INET6, optarg, dnsv6_addr.s6_addr) != 1) {
                        puts("DNS address parameter error!");
                        exit(ERROR_DNS_V6_ADDR);
                    }
                    add_filter_str(IPPROTO_UDP, 53);
                    flush_dns_cache();
                    break;
                }
                puts("DNS address parameter error!");
                exit(ERROR_DNS_V6_ADDR);
                break;
            case 'g': // --dns-port
                if (!do_dnsv4_redirect) {
                    puts("--dns-port should be used with --dns-addr!\n"
                        "Make sure you use --dns-addr and pass it before "
                        "--dns-port");
                    exit(ERROR_DNS_V4_PORT);
                }
                dnsv4_port = atousi(optarg, "DNS port parameter error!");
                if (dnsv4_port != 53) {
                    add_filter_str(IPPROTO_UDP, dnsv4_port);
                }
                dnsv4_port = htons(dnsv4_port);
                break;
            case ';': //tls-force-native
                tls_force_native = 1;
                break;
            case 'E': // --record-frag
                record_frag = 1;
                conntrack_maxlen = (atousi(optarg, "Connection tracking buffer sizing error!") > 0 ? atousi(optarg, "Connection tracking buffer sizing error!") : 1024);
                doing_conntrack = 1;
                break;
            case '@': // --dnsv6-port
                if (!do_dnsv6_redirect) {
                    puts("--dnsv6-port should be used with --dnsv6-addr!\n"
                        "Make sure you use --dnsv6-addr and pass it before "
                        "--dnsv6-port");
                    exit(ERROR_DNS_V6_PORT);
                }
                dnsv6_port = atousi(optarg, "DNS port parameter error!");
                if (dnsv6_port != 53) {
                    add_filter_str(IPPROTO_UDP, dnsv6_port);
                }
                dnsv6_port = htons(dnsv6_port);
                break;
            case 'v':
                do_dns_verb = 1;
                do_tcp_verb = 1;
                break;
            case 'O':
                tls_absolute_frag = atousi(optarg, "Fragment size should be in range [0 - 65535]\n");
                break;
            case '?':
                drop_unsecure_dns = 1;
                break;
            case ']': // --allow-no-sni
                do_allow_no_sni = 1;
                break;
            case '>': // --frag-by-sni
                do_fragment_by_sni = 1;
                break;
            case 'R': // --tls-rando-frag
                tls_rando_frag = 1;
            case '$': // --set-ttl
                do_auto_ttl = auto_ttl_1 = auto_ttl_2 = auto_ttl_max = 0;
                do_fake_packet = 1;
                ttl_of_fake_packet = atoub(optarg, "Set TTL parameter error!");
                break;
            case '[': // --min-ttl
                do_fake_packet = 1;
                ttl_min_nhops = atoub(optarg, "Set Minimum TTL number of hops parameter error!");
                break;
            case '+': // --auto-ttl
                do_fake_packet = 1;
                do_auto_ttl = 1;

                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];

                if (optarg) {
                    char *autottl_copy = strdup(optarg);
                    if (strchr(autottl_copy, '-')) {
                        // token "-" found, start X-Y parser
                        char *autottl_current = strtok(autottl_copy, "-");
                        auto_ttl_1 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_2 = atoub(autottl_current, "Set Auto TTL parameter error!");
                        autottl_current = strtok(NULL, "-");
                        if (!autottl_current) {
                            puts("Set Auto TTL parameter error!");
                            exit(ERROR_AUTOTTL);
                        }
                        auto_ttl_max = atoub(autottl_current, "Set Auto TTL parameter error!");
                    }
                    else {
                        // single digit parser
                        auto_ttl_2 = atoub(optarg, "Set Auto TTL parameter error!");
                        auto_ttl_1 = auto_ttl_2;
                    }
                    free(autottl_copy);
                }
                break;
            case '%': // --wrong-chksum
                do_fake_packet = 1;
                do_wrong_chksum = 1;
                break;
            case 'S': // --rplrr-by-sni
                rplrr = 1;
                rplrr_by_sni = 1;
            case ')': // --wrong-seq
                do_fake_packet = 1;
                do_wrong_seq = 1;
                break;
            case '*': // --native-frag
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case 'G': // --allow-sni-overlap
                allow_sni_overlap = 1;
                break;
            case '(': // --reverse-frag
                do_reverse_frag = 1;
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
                break;
            case 'o': // --compound-frag
                compound_frag = 1;
                break;
            case '=': // --ext-frag-size
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                ext_frag_size = (atousi(optarg, "Extension fragment size parameter error!") > 0 ? atousi(optarg, "\0") : 0);
                break;
            case 'b': // --tls-segmentation
                tls_segmentation = (atousi(optarg, "TLS Record segment amount parameter error!") > 1 ? atousi(optarg, "\0") : 0);
                break;
            case '|': // --max-payload
                if (!optarg && argv[optind] && argv[optind][0] != '-')
                    optarg = argv[optind];
                if (optarg)
                    max_payload_size = atousi(optarg, "Max payload size parameter error!");
                else
                    max_payload_size = 1200;
                break;
            case '}': // --fake-with-sni
                if (fake_load_from_sni(optarg)) {
                    printf("WARNING: bad domain name for SNI: %s\n", optarg);
                }
                break;
            case 'j': // --fake-gen
                if (fake_load_random(atoub(optarg, "Fake generator parameter error!"), 200)) {
                    puts("WARNING: fake generator has failed!");
                }
                break;
            case 'T': // --fake-resend
                fakes_resend = atoub(optarg, "Fake resend parameter error!");
                if (fakes_resend == 1)
                    puts("WARNING: fake-resend is 1, no resending is in place!");
                else if (!fakes_resend)
                    puts("WARNING: fake-resend is 0, fake packet mode is disabled!");
                else if (fakes_resend > 100)
                    puts("WARNING: fake-resend value is a little too high, don't you think?");
                break;
            default:
                puts("Usage: goodbyedpi.exe [OPTION...]\n"
                " -p          block passive DPI\n"
                " -q          block QUIC/HTTP3\n"
                " -r          replace Host with hoSt\n"
                " -s          remove space between host header and its value\n"
                " -a          additional space between Method and Request-URI (enables -s, may break sites)\n"
                " -m          mix Host header case (test.com -> tEsT.cOm)\n"
                " -f <value>  set HTTP fragmentation to value\n"
                " -k <value>  enable HTTP persistent (keep-alive) fragmentation and set it to value\n"
                " -n          do not wait for first segment ACK when -k is enabled\n"
                " -e <value>  set HTTPS fragmentation to value\n"
                " -w          try to find and parse HTTP traffic on all processed ports (not only on port 80)\n"
                " --port        <value>    additional TCP port to perform fragmentation on (and HTTP tricks with -w)\n"
                " --ip-id       <value>    handle additional IP ID (decimal, drop redirects and TCP RSTs with this ID).\n"
                " --dns-addr    <value>    redirect UDPv4 DNS requests to the supplied IPv4 address (experimental)\n"
                " --dns-port    <value>    redirect UDPv4 DNS requests to the supplied port (53 by default)\n"
                " --dnsv6-addr  <value>    redirect UDPv6 DNS requests to the supplied IPv6 address (experimental)\n"
                " --dnsv6-port  <value>    redirect UDPv6 DNS requests to the supplied port (53 by default)\n"
                " --dns-verb               print verbose DNS redirection messages\n"
                " --blacklist   <txtfile>  perform circumvention tricks only to host names and subdomains from\n"
                "                          supplied text file (HTTP Host/TLS SNI).\n"
                "                          This option can be supplied multiple times.\n"
                " --whitelist   <txtfile>  do not perform circumvention tricks to host names and subdomains from\n"
                "                          supplied text file (HTTP Host/TLS SNI).\n"
                "                          This option can be supplied multiple times.\n"
                " --allow-no-sni           perform circumvention if TLS SNI can't be detected with --blacklist enabled.\n"
                " --frag-by-sni            if SNI is detected in TLS packet, fragment the packet right before SNI value.\n"
                " --set-ttl     <value>    activate Fake Request Mode and send it with supplied TTL value.\n"
                "                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).\n"
                " --auto-ttl    [a1-a2-m]  activate Fake Request Mode, automatically detect TTL and decrease\n"
                "                          it based on a distance. If the distance is shorter than a2, TTL is decreased\n"
                "                          by a2. If it's longer, (a1; a2) scale is used with the distance as a weight.\n"
                "                          If the resulting TTL is more than m(ax), set it to m.\n"
                "                          Default (if set): --auto-ttl 1-4-10. Also sets --min-ttl 3.\n"
                "                          DANGEROUS! May break websites in unexpected ways. Use with care (or --blacklist).\n"
                " --min-ttl     <value>    minimum TTL distance (128/64 - TTL) for which to send Fake Request\n"
                "                          in --set-ttl and --auto-ttl modes.\n"
                " --wrong-chksum           activate Fake Request Mode and send it with incorrect TCP checksum.\n"
                "                          May not work in a VM or with some routers, but is safer than set-ttl.\n"
                "                          Could be combined with --set-ttl\n"
                " --wrong-seq              activate Fake Request Mode and send it with TCP SEQ/ACK in the past.\n"
                " --discord-vc [value]     Fixes Discord Voice Chat, hopefully completely. If [value] is above 0,\n"
                "                          sends [value] fake packets instead of 1.\n"
                " --sni-frag-size <value>  If above 0, fragments the SNI into <value> sized chunks.\n"
                " --tls-segment-size <value> Fragments the other 2 parts of the TLS ClientHello into <value> sized chunks.\n"
                "                          Does NOT work with SNI fragmentation disabled.\n"
                "                          Can slow down your internet connection dramatically.\n"
                " --tls-absolute-frag <value> Fragments the entire TLS ClientHello into <value> sized pieces.\n" //For scale, to access youtube videos you send a roughly 2000 byte long ClientHello.
                "                          Can slow down your internet connection dramatically. And thrash your router.\n"
                " --tls-force-native       Forces the fragmented TLS ClientHello to be sent in the right order,\n"
                "                          may fix some websites.\n"
                " --tls-segmentation <value>  Splits the other parts of the TLS record into <value> equally sized\n"
                "                             segments. Won't do anything with SNI fragmentation disabled.\n"
                " --compound-frag          Uses vanilla HTTPS splitting and SNI fragmentation at the same time on\n"
                "                          TLS ClientHello packets.\n"
                " --native-frag            fragment (split) the packets by sending them in smaller packets, without\n"
                "                          shrinking the Window Size. Works faster (does not slow down the connection)\n"
                "                          and better.\n"
                " --reverse-frag           fragment (split) the packets just as --native-frag, but send them in the\n"
                "                          reversed order. Works with the websites which could not handle segmented\n"
                "                          HTTPS TLS ClientHello (because they receive the TCP flow \"combined\").\n"
                " --fake-from-hex <value>  Load fake packets for Fake Request Mode from HEX values (like 1234abcDEF).\n"
                "                          This option can be supplied multiple times, in this case each fake packet\n"
                "                          would be sent on every request in the command line argument order.\n"
                " --fake-with-sni <value>  Generate fake packets for Fake Request Mode with given SNI domain name.\n"
                "                          The packets mimic Mozilla Firefox 130 TLS ClientHello packet\n"
                "                          (with random generated fake SessionID, key shares and ECH grease).\n"
                "                          Can be supplied multiple times for multiple fake packets.\n"
                " --fake-gen <value>       Generate random-filled fake packets for Fake Request Mode, value of them\n"
                "                          (up to 30).\n"
                " --fake-resend <value>    Send each fake packet value number of times.\n"
                "                          Default: 1 (send each packet once).\n"
                " --max-payload [value]    packets with TCP payload data more than [value] won't be processed.\n"
                "                          Use this option to reduce CPU usage by skipping huge amount of data\n"
                "                          (like file transfers) in already established sessions.\n"
                "                          May skip some huge HTTP requests from being processed.\n"
                "                          Default (if set): --max-payload 1200.\n"
                "\n");
                puts("LEGACY modesets:\n"
                " -1          -p -r -s -f 2 -k 2 -n -e 2 (most compatible mode)\n"
                " -2          -p -r -s -f 2 -k 2 -n -e 40 (better speed for HTTPS yet still compatible)\n"
                " -3          -p -r -s -e 40 (better speed for HTTP and HTTPS)\n"
                " -4          -p -r -s (best speed)"
                "\n"
                "Modern modesets (more stable, more compatible, faster):\n"
                " -5          -f 2 -e 2 --auto-ttl --reverse-frag --max-payload\n"
                " -6          -f 2 -e 2 --wrong-seq --reverse-frag --max-payload\n"
                " -7          -f 2 -e 2 --wrong-chksum --reverse-frag --max-payload\n"
                " -8          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload\n"
                " -9          -f 2 -e 2 --wrong-seq --wrong-chksum --reverse-frag --max-payload -q (this is the default)\n\n"
                "Note: combination of --wrong-seq and --wrong-chksum generates two different fake packets.\n"
                );
                puts("NOTE: If you looked at the code and saw undocumented features, trust me, there is a reason they're undocumented\n(Those features were ass and useless.)\n");
                exit(ERROR_DEFAULT);
        }
    }

    if (!http_fragment_size)
        http_fragment_size = 2;
    if (!https_fragment_size)
        https_fragment_size = 2;
    if (!auto_ttl_1)
        auto_ttl_1 = 1;
    if (!auto_ttl_2)
        auto_ttl_2 = 4;
    if (do_auto_ttl) {
        if (!ttl_min_nhops)
            ttl_min_nhops = 3;
        if (!auto_ttl_max)
            auto_ttl_max = 10;
    }

    printf("Block passive: %d\n"                    /* 1 */
           "Block QUIC/HTTP3: %d\n"                 /* 2 */
           "Fragment HTTP: %u\n"                    /* 3 */
           "Fragment persistent HTTP: %u\n"         /* 4 */
           "Fragment HTTPS: %u\n"                   /* 5 */
           "SNI Fragment Size: %u\n"                /* 6 */
           "TLS Extension Fragment Size: %u\n"      /* 7 */
           "Fragment by SNI: %u\n"                  /* 8 */
           "TLS Native Fragmentation: %u\n"         /* 9 */
           "TLS Record Segments: %u\n"              /* 10 */
           "TLS Absolute Fragmentation: %u\n"       /* 11 */
           "TLS Random Fragmentation: %u\n"         /* 12 */
           "TLS Smart Fragmentation: %u (Extension fragment size: %u)\n" /* 13 */
           "Compound Fragmentation: %u\n"           /* 14 */
           //#ifdef UDPTEST
           //"UDP fragments: %u\n"                  /* 15 */
           //#endif
           "Native fragmentation (splitting): %d\n" /* 16 */
           "Fragments sending in reverse: %d\n"     /* 17 */
           "hoSt: %d\n"                             /* 18 */
           "Host no space: %d\n"                    /* 19 */
           "Additional space: %d\n"                 /* 20 */
           "Mix Host: %d\n"                         /* 21 */
           "HTTP AllPorts: %d\n"                    /* 22 */
           "HTTP Persistent Nowait: %d\n"           /* 23 */
           "Fix Discord VC: %u (Fake packets: %u)\n"/* 24 */
           "DNS redirect: %d\n"                     /* 25 */
           "DNSv6 redirect: %d\n"                   /* 26 */
           "Drop unsecure DNS: %d\n"                /* 27 */
           "Allow missing SNI: %d\n"                /* 28 */
           "Fake requests, TTL: %s (fixed: %hu, auto: %hu-%hu-%hu, min distance: %hu)\n"  /* 29 */
           "Fake requests, wrong checksum: %d\n"    /* 30 */
           "Fake requests, wrong SEQ/ACK: %d\n"     /* 31 */
           "Fake requests, custom payloads: %d\n"   /* 32 */
           "Fake requests, resend: %d\n"            /* 33 */
           "Max payload size: %hu\n",               /* 34 */
           do_passivedpi,                          /* 1 */ 
           do_block_quic,                          /* 2 */
           (do_fragment_http ? http_fragment_size : 0),           /* 3 */
           (do_fragment_http_persistent ? http_fragment_size : 0),/* 4 */
           (do_fragment_https ? https_fragment_size : 0),         /* 5 */
           sni_fragment_size,     /* 6 */
           ext_frag_size,         /* 7 */
           do_fragment_by_sni,    /* 8 */
           tls_force_native,      /* 9 */
           tls_segmentation,      /* 10 */
           tls_absolute_frag,     /* 11 */
           tls_rando_frag,        /* 12 */
           smart_frag, ext_frag_size, /* 13 */
           compound_frag,         /* 13 */
           //#ifdef UDPTEST
           //udp_fragments,       /* 14 */
           //#endif
           do_native_frag,        /* 15 */
           do_reverse_frag,       /* 16 */
           do_host,               /* 17 */
           do_host_removespace,   /* 18 */
           do_additional_space,   /* 19 */
           do_host_mixedcase,     /* 20 */
           do_http_allports,      /* 21 */
           do_fragment_http_persistent_nowait, /* 22 */
           activate_thrash, udp_fakes,         /* 23 */
           do_dnsv4_redirect,                  /* 24 */
           do_dnsv6_redirect,                  /* 25 */
           drop_unsecure_dns,                  /* 26 */
           do_allow_no_sni,                    /* 27 */
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),  /* 28 */
               ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0, do_auto_ttl ? auto_ttl_2 : 0,
               do_auto_ttl ? auto_ttl_max : 0, ttl_min_nhops,
           do_wrong_chksum, /* 29 */
           do_wrong_seq,    /* 30 */
           fakes_count,     /* 31 */
           fakes_resend,    /* 32 */
           max_payload_size /* 33 */
          );
    
    if (tls_rando_frag && sni_fragment_size) {
        puts("\nINFO: SNI Fragment size specified with TLS Random Fragmentation.\n"
            "SNI Fragment size overrides random SNI fragment sizes.");
    }
    if (tls_absolute_frag && sni_fragment_size) {
        puts("\nINFO: SNI Fragment size specified with TLS Absolute Fragmentation.\n"
            "SNI Fragment size overrides TLS fragment sizes while fragmenting the SNI.");
    }
    if (smart_frag && !ext_frag_size) ext_frag_size = 1;
    if (do_fragment_http && http_fragment_size > 2 && !do_native_frag) {
        puts("\nWARNING: HTTP fragmentation values > 2 are not fully compatible "
             "with other options. Please use values <= 2 or disable HTTP fragmentation "
             "completely.");
    }
    if (compound_frag && sni_fragment_size == 0) puts(
        "\nWARNING: Compound fragmentation is enabled but SNI fragmentation is not enabled.\n"
        "Compound fragmentation is not done."
    );
    if (tls_absolute_frag && (compound_frag || tls_segment_size || tls_segmentation)) {
        puts(
            "\nWARNING: You tried to use TLS Absolute Fragmentation with other related options.\n"
            "The actions related to those options are not being done."
        );
    }
    if (smart_frag && compound_frag) puts(
        "\nWARNING: Smart fragmentation is not compatible with\n"
        "Compound fragmentation. Compound fragmentation is not done."
    );
    if (smart_frag && tls_segmentation) puts(
        "\nWARNING: Smart fragmentation is not compatible with\n"
        "TLS Segmentation. TLS Segmentation is not done."
    );
    if (do_native_frag && !(do_fragment_http || do_fragment_https)) {
        puts("\nERROR: Native fragmentation is enabled but fragment sizes are not set.\n"
             "Fragmentation has no effect.");
        die();
    }
    pthread_t thrash_thread, conntrack_thread, synner_thread;
    if (max_payload_size) add_maxpayloadsize_str(max_payload_size);
    finalize_filter_strings();
    if (activate_thrash) {
        pthread_create(&thrash_thread, NULL, thrash, NULL);
    }
    if (conntrack_maxlen) {
        conntrack = calloc(conntrack_maxlen, sizeof(struct conntracksig));
        pthread_create(&conntrack_thread, NULL, do_conntrack, NULL);
    }
    if (synning) {
        pthread_create(&synner_thread, NULL, synner, NULL);
    }
    puts("\nOpening filter");
    filter_num = 0;
    if (do_passivedpi) {
        /* IPv4 only filter for inbound RST packets with ID [0x0; 0xF] */
        filters[filter_num] = init(
            filter_passive_string,
            WINDIVERT_FLAG_DROP);
        if (filters[filter_num] == NULL)
            die();
        filter_num++;
    }

    if (do_block_quic) {
        filters[filter_num] = init(
            FILTER_PASSIVE_BLOCK_QUIC,
            WINDIVERT_FLAG_DROP);
        if (filters[filter_num] == NULL)
            die();
        filter_num++;
    }

    /* 
     * IPv4 & IPv6 filter for inbound HTTP redirection packets and
     * active DPI circumvention
     */
    filters[filter_num] = init(filter_string, 0);
    //printf("My filter is %s\n", filter_string);
    w_filter = filters[filter_num];
    filter_num++;

    for (i = 0; i < filter_num; i++) {
        if (filters[i] == NULL)
            die();
    }
    printf("Filter activated, GoodbyeDPI is now running!\n");
    signal(SIGINT, sigint_handler);
    signal(SIGSEGV, sigsegv_handler);
    unsigned char* compound_fragHolder = (unsigned char*) malloc(https_fragment_size);

    while (1) {
        proceed = 0;
        if (WinDivertRecv(w_filter, realpacket, sizeof(realpacket), &packetLen, &addr)) {
            debug("Got %s packet, len=%d!\n", addr.Outbound ? "outbound" : "inbound",
                   packetLen);
            should_reinject = 1;
            should_recalc_checksum = 0;
            sni_ok = 0;
            ppIpHdr = (PWINDIVERT_IPHDR)NULL;
            ppIpV6Hdr = (PWINDIVERT_IPV6HDR)NULL;
            ppTcpHdr = (PWINDIVERT_TCPHDR)NULL;
            ppUdpHdr = (PWINDIVERT_UDPHDR)NULL;
            packet_v4 = packet_v6 = 0;
            packet_type = unknown;
            packet = realpacket;
            // Parse network packet and set it's type
            if (WinDivertHelperParsePacket(realpacket, packetLen, &ppIpHdr,
                &ppIpV6Hdr, NULL, NULL, NULL, &ppTcpHdr, &ppUdpHdr, (void**)&packet_data, &packet_dataLen,
                NULL, NULL))
            {
                if (ppIpHdr) {
                    packet_v4 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv4_tcp;
                        if (packet_data) {
                            packet_type = ipv4_tcp_data;
                        }
                    }
                    else if (ppUdpHdr && packet_data) {
                        packet_type = ipv4_udp_data;
                    }
                }
                else if (ppIpV6Hdr) {
                    packet_v6 = 1;
                    if (ppTcpHdr) {
                        packet_type = ipv6_tcp;
                        if (packet_data) {
                            packet_type = ipv6_tcp_data;
                        }
                    }
                    else if (ppUdpHdr && packet_data) {
                        packet_type = ipv6_udp_data;
                    }
                }
            }
            debug("packet_type: %d, packet_v4: %d, packet_v6: %d\n", packet_type, packet_v4, packet_v6);
            if (packet_type == ipv4_tcp_data || packet_type == ipv6_tcp_data) {
                //printf("Got parsed packet, len=%d!\n", packet_dataLen);
                /* Got a TCP packet WITH DATA */
                //If it's a TLS record, is a ClientHello and the record is larger than the packet itself, attempt reassembly of the record.
                if (addr.Outbound && ppTcpHdr->DstPort != htons(80)) {
                    hdrLen = (packet[0] & 0b00001111) * 4;
                    dataOffset = (packet[hdrLen + 12] >> 4) * 4;
                    unsigned int ip = *(unsigned int*)(packet + 16);
                    unsigned int seq = ntohl(*((unsigned int*)(packet + hdrLen + 4)));
                    freeWaiting = -1;
                    for (int i = 0; i < fatasslen; i++) {
                        if (fatass[i].ip == ip && freeWaiting == -1) {
                            if (fatass[i].seq == seq) {
                                freeWaiting = i;
                            }
                            else if (fatass[i].originseq = seq) {
                                freeWaiting = -2;
                                should_reinject = 0;
                            }
                        }
                        fatass[i].life++;
                        if (fatass[i].life > FATASSMAXLIFE) {
                            fatass[i].ip = 0;
                            fatass[i].seq = 0;
                        }
                    }
                    if (freeWaiting >= 0) {
                        memcpy(fatass[freeWaiting].packet + fatass[freeWaiting].recordlength + fatass[freeWaiting].iphdrlen + fatass[freeWaiting].dOffset, packet_data, packet_dataLen);
                        fatass[freeWaiting].recordlength += packet_dataLen;
                        fatass[freeWaiting].seq += packet_dataLen;
                        if (fatass[freeWaiting].recordlength == fatass[freeWaiting].expectedlength) {
                            printf("Packet completed..\n");
                            packet = fatass[freeWaiting].packet;
                            *((unsigned short*)(packet + 2)) = htons(fatass[freeWaiting].recordlength + fatass[freeWaiting].iphdrlen + fatass[freeWaiting].dOffset);
                            packetLen = fatass[freeWaiting].recordlength + fatass[freeWaiting].iphdrlen + fatass[freeWaiting].dOffset;
                            packet_dataLen = fatass[freeWaiting].recordlength;
                            packet_data = packet + fatass[freeWaiting].iphdrlen + fatass[freeWaiting].dOffset;
                            sni_ok = extract_sni(packet_data, packet_dataLen,
                                        &host_addr, &host_len);
                            if (!sni_ok) { //Well that was in vain. Oh well. Fragment the packet the old fashioned way. Should be easy enough.
                                memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                                progress = 0;
                                fragmentInfoLen = 0;
                                tcpBaseSeq = ntohl(*((unsigned int*)(packet + hdrLen + 4)));
                                while (progress != packet_dataLen) {
                                    current_fragment_size = 500;
                                    if (hdrLen + dataOffset + progress + current_fragment_size >= packetLen) { //Uh oh.
                                        current_fragment_size = (unsigned int) (packetLen - hdrLen - dataOffset - progress);
                                        break;
                                    }
                                    memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                                    totalLength = hdrLen + dataOffset + current_fragment_size;
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                    tcpSeq = tcpBaseSeq + progress;
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    newpacketid(fragmentHolder);
                                    WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                    );
                                    if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                    else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    progress += current_fragment_size;
                                }
                                do_super_reverse_frag(0, fragmentInfo, fragmentInfoLen, packet, tcpBaseSeq, 0);
                                should_reinject = 0;
                            }
                        }
                        fatass[freeWaiting].seq = 0;
                        fatass[freeWaiting].ip = 0;
                        if (
                             (do_blacklist && sni_ok &&
                              blackwhitelist_check_hostname(host_addr, host_len, 0, NULL)
                             ) ||
                             (do_blacklist && !sni_ok && do_allow_no_sni) ||
                             (sni_ok && !do_blacklist && (!do_whitelist || (do_whitelist && blackwhitelist_check_hostname(host_addr, host_len, 1, NULL))))
                           )
                        {
                            if (do_fake_packet) {
                                TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_https_request);
                            }
                            if (do_native_frag) {
                                // Signal for native fragmentation code handler
                                should_recalc_checksum = 1;
                            }
                        }
                    }
                    else if (freeWaiting == -1 && packet_dataLen > 41) {
                        if (istlshandshake(packet_data) && packet_data[5] == 1 && (ntohs(*((unsigned short*)(packet_data + 3))) + 5) > packet_dataLen) {
                            printf("Attempting reconstruction of record with the PDU size of %u\n", ntohs(*((unsigned short*)(packet_data + 3))) + 5);
                            for (int i = 0; i < fatasslen; i++) {
                                if (fatass[i].seq == 0 && fatass[i].ip == 0) {
                                    freeWaiting = i;
                                    break;
                                }
                            }
                            if (fatasslen == 512 && freeWaiting == -1) {
                                printf("SHIT SHIT SHIT SHIT SHIT SHIT!!!\n");
                                printf("P.S. If you see this and the program is still running, restart the program.\n");
                            }
                            if (freeWaiting == -1) {
                                freeWaiting = fatasslen++;
                            }
                            fatass[freeWaiting].ip = ip;
                            fatass[freeWaiting].originseq = seq;
                            fatass[freeWaiting].seq = seq + packet_dataLen;
                            fatass[freeWaiting].iphdrlen = hdrLen;
                            fatass[freeWaiting].dOffset = dataOffset;
                            fatass[freeWaiting].expectedlength = ntohs(*((unsigned short*)(packet_data + 3))) + 5;
                            fatass[freeWaiting].recordlength = packet_dataLen;
                            memcpy(fatass[freeWaiting].packet, packet, hdrLen + dataOffset);
                            memcpy(fatass[freeWaiting].packet + hdrLen + dataOffset, packet_data, packet_dataLen);
                            should_reinject = 0;
                        }
                    }
                }
                /* Handle INBOUND packet with data and find HTTP REDIRECT in there */
                if (!addr.Outbound && packet_dataLen > 16) {
                    /* If INBOUND packet with DATA (tcp.Ack) */

                    /* Drop packets from filter with HTTP 30x Redirect */
                    if (do_passivedpi && is_passivedpi_redirect(packet_data, packet_dataLen)) {
                        if (packet_v4) {
                            //printf("Dropping HTTP Redirect packet!\n");
                            should_reinject = 0;
                        }
                        else if (packet_v6 && WINDIVERT_IPV6HDR_GET_FLOWLABEL(ppIpV6Hdr) == 0x0) {
                                /* Contrary to IPv4 where we get only packets with IP ID 0x0-0xF,
                                 * for IPv6 we got all the incoming data packets since we can't
                                 * filter them in a driver.
                                 *
                                 * Handle only IPv6 Flow Label == 0x0 for now
                                 */
                                printf("Dropping HTTP Redirect packet!\n");
                                should_reinject = 0;
                        }
                    }
                }
                /* Handle OUTBOUND packet on port 443, search for something that resembles
                 * TLS handshake, send fake request.
                 */
                else if (addr.Outbound &&
                        ((do_fragment_https ? packet_dataLen == https_fragment_size : 0) ||
                         packet_dataLen > 16) &&
                         ppTcpHdr->DstPort != htons(80) &&
                         (do_fake_packet || do_native_frag)
                        )
                {
                    /**
                     * In case of Window Size fragmentation=2, we'll receive only 2 byte packet.
                     * But if the packet is more than 2 bytes, check ClientHello byte.
                    */
                    if ((packet_dataLen == 2 && memcmp(packet_data, "\x16\x03", 2) == 0) ||
                        (packet_dataLen >= 3 && ( memcmp(packet_data, "\x16\x03\x01", 3) == 0 || memcmp(packet_data, "\x16\x03\x03", 3) == 0 )))
                    {
                        if (do_blacklist || do_fragment_by_sni || (sni_fragment_size || tls_absolute_frag)) {
                            sni_ok = extract_sni(packet_data, packet_dataLen,
                                        &host_addr, &host_len);
                        }
                        if (
                             (do_blacklist && sni_ok &&
                              blackwhitelist_check_hostname(host_addr, host_len, 0, NULL)
                             ) ||
                             (do_blacklist && !sni_ok && do_allow_no_sni) ||
                             (sni_ok && !do_blacklist && (!do_whitelist || (do_whitelist && blackwhitelist_check_hostname(host_addr, host_len, 1, NULL))))
                           )
                        {
                            if (do_fake_packet) {
                                TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_https_request);
                            }
                            if (do_native_frag) {
                                // Signal for native fragmentation code handler
                                should_recalc_checksum = 1;
                            }
                        }
                    }
                }
                else if (addr.Outbound && 
                        packet_dataLen > 16 &&
                        (do_http_allports ? 1 : (ppTcpHdr->DstPort == htons(80))) &&
                        find_http_method_end(packet_data,
                                             (do_fragment_http ? http_fragment_size : 0u),
                                             &http_req_fragmented) &&
                        (do_host || do_host_removespace ||
                        do_host_mixedcase || do_fragment_http_persistent ||
                        do_fake_packet))
                {
                    /* Find Host header */
                    if (find_header_and_get_info(packet_data, packet_dataLen,
                        http_host_find, &hdr_name_addr, &hdr_value_addr, &hdr_value_len) &&
                        hdr_value_len > 0 && hdr_value_len <= HOST_MAXLEN &&
                        (do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len, 0, NULL) : 1))
                    {
                        if (do_whitelist && !do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len, 1, NULL) : 1) proceed = 1;
                        host_addr = hdr_value_addr;
                        host_len = hdr_value_len;
#ifdef DEBUG
                        char lhost[HOST_MAXLEN + 1] = {0};
                        memcpy(lhost, host_addr, host_len);
                        printf("Blocked HTTP website Host: %s\n", lhost);
                        printf("Host: ");
                        for (int i = 0; i < host_len; i++) {
                            charputter(host_addr[i]);
                        }
                        printf("\n");
                        analyze_ip_header(packet);
#endif
                        if (!proceed) {
                            if (do_native_frag) {
                                // Signal for native fragmentation code handler
                                should_recalc_checksum = 1;
                            }
                            if (do_fake_packet) {
                                TCP_HANDLE_OUTGOING_FAKE_PACKET(send_fake_http_request);
                            }
                            if (do_host_mixedcase) {
                                mix_case(host_addr, host_len);
                                should_recalc_checksum = 1;
                            }
                            if (do_host) {
                                /* Replace "Host: " with "hoSt: " */
                                memcpy(hdr_name_addr, http_host_replace, strlen(http_host_replace));
                                should_recalc_checksum = 1;
                                //printf("Replaced Host header!\n");
                            }
                            /* If removing space between host header and its value
                             * and adding additional space between Method and Request-URI */
                            if (do_additional_space && do_host_removespace) {
                                /* End of "Host:" without trailing space */
                                method_addr = find_http_method_end(packet_data,
                                                                (do_fragment_http ? http_fragment_size : 0),
                                                                NULL);
    
                                if (method_addr) {
                                    memmove(method_addr + 1, method_addr,
                                            (size_t)(host_addr - method_addr - 1));
                                    should_recalc_checksum = 1;
                                }
                            }
                            /* If just removing space between host header and its value */
                            else if (do_host_removespace) {
                                if (find_header_and_get_info(packet_data, packet_dataLen,
                                                            http_useragent_find, &hdr_name_addr,
                                                             &hdr_value_addr, &hdr_value_len))
                                {
                                    useragent_addr = hdr_value_addr;
                                    useragent_len = hdr_value_len;
    
                                    /* We move Host header value by one byte to the left and then
                                     * "insert" stolen space to the end of User-Agent value because
                                     * some web servers are not tolerant to additional space in the
                                     * end of Host header.
                                     *
                                     * Nothing is done if User-Agent header is missing.
                                     */
                                    if (useragent_addr && useragent_len > 0) {
                                        /* useragent_addr is in the beginning of User-Agent value */
    
                                        if (useragent_addr > host_addr) {
                                            /* Move one byte to the LEFT from "Host:"
                                            * to the end of User-Agent
                                            */
                                            memmove(host_addr - 1, host_addr,
                                                    (size_t)(useragent_addr + useragent_len - host_addr));
                                            host_addr -= 1;
                                            /* Put space in the end of User-Agent header */
                                            *(char*)((unsigned char*)useragent_addr + useragent_len - 1) = ' ';
                                            should_recalc_checksum = 1;
                                            //printf("Replaced Host header!\n");
                                        }
                                        else {
                                            /* User-Agent goes BEFORE Host header */
    
                                            /* Move one byte to the RIGHT from the end of User-Agent
                                            * to the "Host:"
                                            */
                                            memmove(useragent_addr + useragent_len + 1,
                                                    useragent_addr + useragent_len,
                                                    (size_t)(host_addr - 1 - (useragent_addr + useragent_len)));
                                            /* Put space in the end of User-Agent header */
                                            *(char*)((unsigned char*)useragent_addr + useragent_len) = ' ';
                                            should_recalc_checksum = 1;
                                            //printf("Replaced Host header!\n");
                                        }
                                    } /* if (host_len <= HOST_MAXLEN && useragent_addr) */
                                } /* if (find_header_and_get_info http_useragent) */
                            } /* else if (do_host_removespace) */
                        } //Proceed
                    } /* if (find_header_and_get_info http_host) */
                } /* Handle OUTBOUND packet with data */
                /*
                * should_recalc_checksum mean we have detected a packet to handle and
                * modified it in some way.
                * Handle native fragmentation here, incl. sending the packet.
                */
                hdrLen = (packet[0] & 0b00001111) * 4;
                dataOffset = (packet[hdrLen + 12] >> 4) * 4;

                if (should_reinject && should_recalc_checksum && do_native_frag && !proceed)
                {
                    current_fragment_size = 0;
                    if (do_fragment_http && ppTcpHdr->DstPort == htons(80)) {
                        current_fragment_size = http_fragment_size;
                    }
                    else if (do_fragment_https && ppTcpHdr->DstPort != htons(80)) {
                        if (do_fragment_by_sni && sni_ok) {
                            current_fragment_size = (void*)host_addr - (void*)packet_data;
                        } else {
                            current_fragment_size = https_fragment_size;
                        }
                    }
                    if ((sni_fragment_size || tls_absolute_frag || tls_rando_frag) && sni_ok && packet_v4) {
                        illegalSegmentLen = 0;
                        addoffset = 0;
                        beginSni = 0;
                        fragmentInfoLen = 0;
                        packetBACKLen = packetLen;
                        //analyze_tls_clienthello(packet);
                        #ifdef DEBUG
                        printf("BEGIN SNI FRAGMENTATION\n");
                        #endif
                        #ifdef SHOWSNI
                        printf("processing ");
                        xprint(host_addr, host_len, 0);
                        printf("\n");
                        #endif
                        //printf("PACKET LENGTH: %u\n", packetLen);
                        if (blackwhitelist_check_hostname(host_addr, host_len, 3, fakehost)) {
                            printf("MATCH!\n", fakehost);
                            struct clienthello clienthello;
                            parse_clienthello(packet, &clienthello);
                            for (unsigned short i = 0; i < clienthello.extensionCount; i++) {
                                if (clienthello.extensions[i].type == 0) {
                                    free(clienthello.extensions[i].data);
                                    clienthello.extensions[i].data = malloc(strlen(fakehost) + 5);
                                    unsigned char* sni = clienthello.extensions[i].data;
                                    clienthello.extensions[i].length = strlen(fakehost) + 5;
                                    *((unsigned short*)(sni)) = htons(strlen(fakehost) + 3);
                                    sni[2] = 0;
                                    *((unsigned short*)(sni + 3)) = htons(strlen(fakehost)); //Far too much work.
                                    memcpy(sni + 5, fakehost, strlen(fakehost));
                                }
                            }
                            memcpy(illegalSegment, packet, hdrLen + dataOffset);
                            illegalSegmentLen = rebuild_clienthello(&clienthello, illegalSegment + hdrLen + dataOffset) + hdrLen + dataOffset;
                            convert_endian(illegalSegment + 2, &illegalSegmentLen, 2);
                        }
                        convert_endian(&tcpBaseSeq, packet + hdrLen + 4, 4);
                        tcpBaseSeqTrue = tcpBaseSeq;
                        analyze_hlen = (packet[0] & 0b00001111) * 4;
                        analyze_dataoffset = ((packet + analyze_hlen)[12] >> 4) * 4;
                        convert_endian(&analyze_totallength, packet + 2, 2);
                        session_len = packet[analyze_hlen + analyze_dataoffset + 43];
                        convert_endian(&ciphersuitelen, packet + analyze_hlen + analyze_dataoffset + 44 + session_len, 2);
                        compresslen = packet[analyze_hlen + analyze_dataoffset + 46 + session_len + ciphersuitelen];
                        convert_endian(&extlen, packet + analyze_hlen + analyze_dataoffset + session_len + ciphersuitelen + compresslen + 47, 2);
                        for (int i = 0; i < MAX_PACKET_SIZE; i++) reassembleSegments[i] = 255;
                        overload = 0;
                        if (host_shiftback && host_len + host_shiftback > 0) {
                            host_addr -= host_shiftback;
                            host_len += host_shiftback;
                        }
                        if (record_frag && ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + 3))) > packet_dataLen - 5) {
                            //sprintf("Record overload...\n");
                            overload = ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + 3))) - (packet_dataLen - 5);
                        }
                        if (alter_max_record_len) {
                            *((unsigned short*)(packet + hdrLen + dataOffset + 3)) = htons(ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + 3))) + 6); //Increase the length of the TLS record.
                            *((unsigned int*)(packet + hdrLen + dataOffset + 5)) = htonl(ntohl(*((unsigned int*)(packet + hdrLen + dataOffset + 5)) & 0xFFFFFF00) + 6) | 0x00000001; //Increase the length of the ClientHello.
                            *((unsigned short*)(packet + hdrLen + dataOffset + session_len + ciphersuitelen + compresslen + 47)) = htons(ntohs(*((unsigned short*)(packet + hdrLen + dataOffset + session_len + ciphersuitelen + compresslen + 47))) + 6); //Increase the extensions length of the ClientHello.
                            memmove(packet + analyze_hlen + analyze_dataoffset + session_len + ciphersuitelen + compresslen + 55, packet + analyze_hlen + analyze_dataoffset + session_len + ciphersuitelen + compresslen + 49, packetLen - (analyze_hlen + analyze_dataoffset + session_len + ciphersuitelen + compresslen + 49)); //Move the extensions out of the way.
                            *((unsigned short*)(packet + hdrLen + dataOffset + session_len + ciphersuitelen + compresslen + 49)) = htons(28); //ExtType = 28
                            *((unsigned short*)(packet + hdrLen + dataOffset + session_len + ciphersuitelen + compresslen + 51)) = htons(2); //ExtLen = 2
                            *((unsigned short*)(packet + hdrLen + dataOffset + session_len + ciphersuitelen + compresslen + 53)) = htons(alter_max_record_len);
                            addoffset += 6; //Increase the conntrack offset.
                            host_addr += 6;
                            packetLen += 6;
                            extlen += 6;
                        }
                        memcpy(packetBACK, packet, packetLen); //Back 'er up!
                        if (record_frag && !smart_frag) {
                            memmove(packet + hdrLen + dataOffset, packet + hdrLen + dataOffset + 5, packetLen - 5 - hdrLen - dataOffset);
                            host_addr -= 5;
                            packetLen -= 5;
                            tcpBaseSeq += 5;
                        }
                        //analyze_tls_clienthello(packet);
                        if (tls_rando_frag) {
                            memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                            progress = 0;
                            fragging_sni = 0;
                            while (progress != packetLen - hdrLen - dataOffset) {
                                try_again: //goto within a loop! Very scary!
                                current_fragment_size = !fragging_sni ? genrand4((unsigned short) packetLen) : (sni_fragment_size || cleave_sni) ? (cleave_sni ? host_len / 2 : sni_fragment_size) : genrand2((unsigned short) packetLen);
                                if (!fragging_sni && current_fragment_size == 0) goto try_again;
                                if (super_reverse && !fragging_sni && !(packet + hdrLen + dataOffset + progress >= host_addr + host_len) && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr) { //Dangerously close to SNI, fragment right before it
                                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr - packet - dataOffset - hdrLen - progress);
                                    fragging_sni = 1;
                                    beginSni = fragmentInfoLen + (allow_sni_overlap ? 0 : 1);
                                    if (!allow_sni_overlap && current_fragment_size == 0) {
                                        beginSni--;
                                        goto try_again;
                                    }
                                }
                                if (fragging_sni && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr + host_len) { //Exitting SNI, fragment until the end of the SNI.
                                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr + host_len - packet - hdrLen - dataOffset - progress);
                                    fragging_sni = 0;
                                    endSni = fragmentInfoLen;
                                    if (!allow_sni_overlap && current_fragment_size == 0) goto try_again;
                                }
                                if (hdrLen + dataOffset + progress + current_fragment_size >= packetLen) { //Uh oh.
                                    current_fragment_size = (unsigned int) (packetLen - hdrLen - dataOffset - progress);
                                    if (current_fragment_size == 0) goto wrapup;
                                }
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                                totalLength = hdrLen + dataOffset + current_fragment_size;
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                tcpSeq = tcpBaseSeq + progress;
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                #ifdef DEBUG
                                reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                #endif
                                if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                progress += current_fragment_size;
                            }
                            goto wrapup;
                        }
                        if (tls_absolute_frag) { //It now uses the mechanism of TLS Random fragmentation, which is far better. (The old version of TLS absolute fragmentation is GONE. EXTINCT.)
                            memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                            progress = 0;
                            fragging_sni = 0;
                            while (progress != packetLen - hdrLen - dataOffset) {
                                try_again_absolute: //goto within a loop! Very scary!
                                current_fragment_size = !fragging_sni ? tls_absolute_frag : (sni_fragment_size || cleave_sni) ? (cleave_sni ? host_len / 2 : sni_fragment_size) : tls_absolute_frag;
                                if (!fragging_sni && current_fragment_size == 0) goto try_again_absolute;
                                if (sni_fragment_size && !fragging_sni && !(packet + hdrLen + dataOffset + progress >= host_addr + host_len) && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr) { //Dangerously close to SNI, fragment right before it
                                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr - packet - dataOffset - hdrLen - progress);
                                    fragging_sni = 1;
                                    beginSni = fragmentInfoLen + (allow_sni_overlap ? 0 : 1);
                                    if (!allow_sni_overlap && current_fragment_size == 0) {
                                        beginSni--;
                                        goto try_again_absolute;
                                    }
                                }
                                if (sni_fragment_size && fragging_sni && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr + host_len) { //Exitting SNI, fragment until the end of the SNI.
                                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr + host_len - packet - hdrLen - dataOffset - progress);
                                    fragging_sni = 0;
                                    endSni = fragmentInfoLen;
                                    if (!allow_sni_overlap && current_fragment_size == 0) goto try_again_absolute;
                                }
                                if (hdrLen + dataOffset + progress + current_fragment_size >= packetLen) { //Uh oh.
                                    current_fragment_size = (unsigned int) (packetLen - hdrLen - dataOffset - progress);
                                    if (current_fragment_size == 0) goto wrapup;
                                }
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                                totalLength = hdrLen + dataOffset + current_fragment_size;
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                tcpSeq = tcpBaseSeq + progress;
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                #ifdef DEBUG
                                reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                #endif
                                if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                progress += current_fragment_size;
                            }
                            goto wrapup;
                        }
                        /*if (tls_absolute_frag > 0) { 
                            memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                            for (int x = (do_reverse_frag && !tls_force_native && !super_reverse) ? ((packetLen - hdrLen - dataOffset) / tls_absolute_frag * tls_absolute_frag) : 0; (x < (packetLen - hdrLen - dataOffset) && (!do_reverse_frag || tls_force_native || super_reverse)) || ((do_reverse_frag && !tls_force_native && !super_reverse) && x >= 0); (do_reverse_frag && !tls_force_native && !super_reverse) ? (x -= tls_absolute_frag) : (x += tls_absolute_frag)) {
                                totalLength = (x + tls_absolute_frag > (packetLen - hdrLen - dataOffset) ? (packetLen - hdrLen - dataOffset) % tls_absolute_frag : tls_absolute_frag) + hdrLen + dataOffset;
                                tcpSeq = tcpBaseSeq + x;
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + (tcpSeq - tcpBaseSeq) + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                //analyze_ip_header(fragmentHolder);
                                //analyze_tcp_header(fragmentHolder, hdrLen);
                                //reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packet + hdrLen + dataOffset);
                                if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                            }
                            goto wrapup;
                        }
                        */
                        if (compound_frag && do_native_frag && !do_reverse_frag && !smart_frag) {
                            send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                                packet_dataLen,packet_v4, packet_v6,
                                                ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                                https_fragment_size, 0);
                        }
                        else if (compound_frag && do_reverse_frag && !smart_frag) {
                            memcpy(compound_fragHolder, packet + hdrLen + dataOffset, https_fragment_size); //Hold onto the first [https_fragment_size] bytes of the payload.
                        }
                        if (compound_frag && !smart_frag) {
                            tcpBaseSeq += https_fragment_size;
                            host_addr -= https_fragment_size;
                            memmove(packet + hdrLen + dataOffset, packet + hdrLen + dataOffset + https_fragment_size, packetLen - https_fragment_size - hdrLen - dataOffset);
                            packetLen -= https_fragment_size;
                        }
                        if (smart_frag) {
                            memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                            for (int i = do_reverse_frag && !tls_force_native && !super_reverse ? 5 : 0; (do_reverse_frag && !tls_force_native && !super_reverse && i >= 0) || (!(do_reverse_frag && !tls_force_native && !super_reverse) && i < 6); (do_reverse_frag && !tls_force_native && !super_reverse) ? i-- : i++) {
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + (2 * i), 2);
                                tcpSeq = tcpBaseSeq + (2 * i);
                                totalLength = hdrLen + dataOffset + 2;
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                #ifdef DEBUG
                                reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, packetBACK + hdrLen + dataOffset);
                                #endif
                                if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                            }
                            analyze_hlen = (packet[0] & 0b00001111) * 4;
                            analyze_dataoffset = ((packet + analyze_hlen)[12] >> 4) * 4;
                            convert_endian(&analyze_totallength, packet + 2, 2);
                            session_len = packet[analyze_hlen + analyze_dataoffset + 43];
                            convert_endian(&ciphersuitelen, packet + analyze_hlen + analyze_dataoffset + 44 + session_len, 2);
                            compresslen = packet[analyze_hlen + analyze_dataoffset + 46 + session_len + ciphersuitelen];
                            //Send the rest of the client random and Session ID, as those values are not identifiable as TLS ClientHello traffic. [And the client random was chipped by the other fragmenter.]
                            memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + 12, 32 + session_len);
                            tcpSeq = tcpBaseSeq + 12;
                            totalLength = hdrLen + dataOffset + 32 + session_len;
                            convert_endian(fragmentHolder + 2, &totalLength, 2);
                            convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                            newpacketid(fragmentHolder);
                            WinDivertHelperCalcChecksums(
                                fragmentHolder, totalLength, &addr, 0
                            );
                            #ifdef DEBUG
                            reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, packetBACK + hdrLen + dataOffset);
                            #endif
                            if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                            else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                            //Send the first byte of the cipher suites.
                            fragmentHolder[hdrLen + dataOffset] = packet[hdrLen + dataOffset + 44 + session_len];
                            tcpSeq = tcpBaseSeq + 44 + session_len;
                            totalLength = hdrLen + dataOffset + 1;
                            convert_endian(fragmentHolder + 2, &totalLength, 2);
                            convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                            newpacketid(fragmentHolder);
                            WinDivertHelperCalcChecksums(
                                fragmentHolder, totalLength, &addr, 0
                            );
                            #ifdef DEBUG
                            reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, packetBACK + hdrLen + dataOffset);
                            #endif
                            if (!super_reverse)
                            WinDivertSend(
                                w_filter, fragmentHolder,
                                totalLength,
                                NULL, &addr
                            );
                            else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                            //And now send the rest of it, and put the extensions length as a bonus.
                            for (int i = do_reverse_frag && !tls_force_native && !super_reverse ? ciphersuitelen + 4 : 0; (do_reverse_frag && !tls_force_native && !super_reverse && i >= 0) || (!(do_reverse_frag && !tls_force_native) || super_reverse && i <= ciphersuitelen + 4); (do_reverse_frag && !tls_force_native && !super_reverse) ? (i -= 2) : (i += 2)) {
                                if (i + 2 <= ciphersuitelen + 4) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + 45 + session_len + i, 2);
                                    totalLength = hdrLen + dataOffset + 2;
                                }
                                else {
                                    fragmentHolder[hdrLen + dataOffset] = packet[hdrLen + dataOffset + 45 + session_len + i];
                                    totalLength = hdrLen + dataOffset + 1;
                                }
                                tcpSeq = tcpBaseSeq + 45 + session_len + i;
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                #ifdef DEBUG
                                reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeq, packetBACK + hdrLen + dataOffset);
                                #endif
                                if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                            }
                            //Shift pointers and values
                            tcpBaseSeq += 49 + compresslen + session_len + ciphersuitelen;
                            host_addr -= 49 + compresslen + session_len + ciphersuitelen;
                            memmove(packet + hdrLen + dataOffset, packet + hdrLen + dataOffset + 49 + compresslen + session_len + ciphersuitelen, packetLen - 49 + compresslen + session_len + ciphersuitelen - hdrLen - dataOffset);
                            packetLen -= 49 + compresslen + session_len + ciphersuitelen;
                        }
                        memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                        if (!tls_segmentation && !tls_segment_size && !smart_frag) {
                            for (int i = (do_reverse_frag && !tls_force_native && !super_reverse) ? 2 : 0; (i < 3 && (!do_reverse_frag || tls_force_native || super_reverse)) || ((do_reverse_frag && !tls_force_native && !super_reverse) && i >= 0); (do_reverse_frag && !tls_force_native) ? i-- : i++) { //Three step plan!
                                addr.IPChecksum = 0;
                                addr.TCPChecksum = 0;
                                //Why is it backwards? Because why not! [I just thought backwards.]
                                if (i == 2) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + host_len, packetLen - (unsigned int)(host_addr - packet) - host_len);
                                    tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + host_len);
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    totalLength = hdrLen + dataOffset + (packetLen - (unsigned int)(host_addr - packet) - host_len);
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                }
                                if (i == 1 && host_len > sni_fragment_size) {
                                    for (int x = ((do_reverse_frag && !tls_force_native) ? host_len - sni_fragment_size : 0); ((!do_reverse_frag || tls_force_native) && x < host_len) || ((do_reverse_frag && !tls_force_native) && x > 0); x += ((do_reverse_frag && !tls_force_native) ? -sni_fragment_size : sni_fragment_size)) {
                                        memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + x, sni_fragment_size);
                                        tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + x);
                                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                        totalLength = hdrLen + dataOffset + sni_fragment_size;
                                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                                        newpacketid(fragmentHolder);
                                        WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                        );
                                        #ifdef DEBUG
                                        reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                        #endif
                                        if (!super_reverse)
                                        WinDivertSend(
                                            w_filter, fragmentHolder,
                                            totalLength,
                                            NULL, &addr
                                        );
                                        else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    }
                                }
                                if (host_len % sni_fragment_size > 0 && i == 1) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + ((do_reverse_frag && !tls_force_native) ? 0 : host_len - (host_len % sni_fragment_size)), host_len % sni_fragment_size);
                                    convert_endian(&tcpSeq, packet + hdrLen + 4, 4);
                                    tcpSeq = tcpBaseSeq + (unsigned int)(host_addr - packet) - hdrLen - dataOffset + ((do_reverse_frag && !tls_force_native) ? 0 : host_len - (host_len % sni_fragment_size));
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    totalLength = hdrLen + dataOffset + (host_len % sni_fragment_size);
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                }
                                if (i == 0) {
                                    tcpSeq = tcpBaseSeq;
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset, (unsigned int)(host_addr - packet) - hdrLen - dataOffset);
                                    totalLength = (unsigned int)(host_addr - packet);
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                }
                                if (i != 1 || (i == 1 && host_len % sni_fragment_size > 0)) {
                                    newpacketid(fragmentHolder);
                                    WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                    );
                                    #ifdef DEBUG
                                    reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                    #endif
                                    if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                    else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                }
                            }
                        }
                        else if (tls_segmentation && !tls_segment_size && !smart_frag) { //It's too much math!
                            //printf("SEGMENT 1 LENGTH: %u\nSNI LENGTH: %u\nSEGMENT 2 LENGTH: %u\nREAL SEQ: %u\n", (unsigned int)(host_addr - packet) - hdrLen - dataOffset, host_len, (packetLen - (unsigned int)(host_addr - packet) - host_len), htonl(*(unsigned int*)(packetBACK + hdrLen + 4)));
                            for (int i = (do_reverse_frag && !tls_force_native) ? 2 : 0; (i < 3 && (!do_reverse_frag || tls_force_native)) || ((do_reverse_frag && !tls_force_native) && i >= 0); (do_reverse_frag && !tls_force_native) ? i-- : i++) { //Dynamic plan!
                                addr.IPChecksum = 0;
                                addr.TCPChecksum = 0;
                                if (i == 2) {
                                    //printf("STAGE 3\n");
                                    for (int x = (do_reverse_frag && !tls_force_native && !super_reverse) ? tls_segmentation - 1 : 0; (x < tls_segmentation && (!do_reverse_frag || tls_force_native || super_reverse)) || ((do_reverse_frag && !tls_force_native && !super_reverse) && x >= 0); (do_reverse_frag && !tls_force_native && !super_reverse) ? x-- : x++) {
                                        totalLength = hdrLen + dataOffset + ((packetLen - (unsigned int)(host_addr - packet) - host_len) / tls_segmentation);
                                        tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + host_len) + ((totalLength - hdrLen - dataOffset) * x);
                                        totalLength += (x + 1 == tls_segmentation ? ((packetLen - (unsigned int)(host_addr - packet) - host_len) % tls_segmentation) : 0);
                                        //printf("SEGMENT %d, PAYLOAD LENGTH: %u, SEQ OFFSET: %u\n", x + 1, totalLength - hdrLen - dataOffset, tcpSeq - tcpBaseSeq);
                                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                        memcpy(fragmentHolder + hdrLen + dataOffset, packet + (tcpSeq - tcpBaseSeq) + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
                                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                                        newpacketid(fragmentHolder);
                                        WinDivertHelperCalcChecksums(
                                            fragmentHolder, totalLength, &addr, 0
                                        );
                                        #ifdef DEBUG
                                        reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                        #endif
                                        if (!super_reverse)
                                        WinDivertSend(
                                            w_filter, fragmentHolder,
                                            totalLength,
                                            NULL, &addr
                                        );
                                        else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    }
                                }
                                if (i == 1 && host_len > sni_fragment_size) { //OK
                                    //printf("STAGE 2: %u\n", host_len);
                                    for (int x = ((do_reverse_frag && !tls_force_native && !super_reverse) ? host_len - sni_fragment_size : 0); ((!do_reverse_frag || tls_force_native || super_reverse) && x < host_len) || ((do_reverse_frag && !tls_force_native && !super_reverse) && x >= 0); x += ((do_reverse_frag && !tls_force_native && !super_reverse) ? -sni_fragment_size : sni_fragment_size)) {
                                        //printf("OFFSET: %d\n", x);
                                        memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + x, sni_fragment_size);
                                        tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + x);
                                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                        totalLength = hdrLen + dataOffset + sni_fragment_size;
                                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                                        newpacketid(fragmentHolder);
                                        WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                        );
                                        #ifdef DEBUG
                                        reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                        #endif
                                        if (!super_reverse)
                                        WinDivertSend(
                                            w_filter, fragmentHolder,
                                            totalLength,
                                            NULL, &addr
                                        );
                                        else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    }
                                }
                                if (host_len % sni_fragment_size > 0 && i == 1) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + ((do_reverse_frag && !tls_force_native && !super_reverse) ? 0 : host_len - (host_len % sni_fragment_size)), host_len % sni_fragment_size);
                                    convert_endian(&tcpSeq, packet + hdrLen + 4, 4);
                                    tcpSeq = tcpBaseSeq + (unsigned int)(host_addr - packet) - hdrLen - dataOffset + ((do_reverse_frag && !tls_force_native && !super_reverse) ? 0 : host_len - (host_len % sni_fragment_size));
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    totalLength = hdrLen + dataOffset + (host_len % sni_fragment_size);
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                    newpacketid(fragmentHolder);
                                    WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                    );
                                    #ifdef DEBUG
                                    reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                    #endif
                                    if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                    else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                }
                                if (i == 0) {
                                    //printf("STAGE 1\n");
                                    for (int x = (do_reverse_frag && !tls_force_native && !super_reverse) ? tls_segmentation - 1 : 0; (x < tls_segmentation && (!do_reverse_frag || tls_force_native || super_reverse)) || ((do_reverse_frag && !tls_force_native && !super_reverse) && x >= 0); (do_reverse_frag && !tls_force_native && !super_reverse) ? x-- : x++) {
                                        totalLength = ((unsigned int)(host_addr - packet) - hdrLen - dataOffset) / tls_segmentation + hdrLen + dataOffset;
                                        tcpSeq = tcpBaseSeq + ((totalLength - hdrLen - dataOffset) * x);
                                        totalLength += (x + 1 == tls_segmentation ? (((unsigned int)(host_addr - packet) - hdrLen - dataOffset) % tls_segmentation) : 0);
                                        //printf("SEGMENT %d, PAYLOAD LENGTH: %u, SEQ OFFSET: %u\n", x + 1, totalLength - hdrLen - dataOffset, tcpSeq - tcpBaseSeq);
                                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                        memcpy(fragmentHolder + hdrLen + dataOffset, packet + (tcpSeq - tcpBaseSeq) + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
                                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                                        newpacketid(fragmentHolder);
                                        WinDivertHelperCalcChecksums(
                                            fragmentHolder, totalLength, &addr, 0
                                        );
                                        #ifdef DEBUG
                                        reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                        #endif
                                        if (!super_reverse)
                                        WinDivertSend(
                                            w_filter, fragmentHolder,
                                            totalLength,
                                            NULL, &addr
                                        );
                                        else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    }
                                }
                            }
                        }
                        else if (tls_segment_size && !smart_frag) {
                            for (int i = (do_reverse_frag && !tls_force_native && !super_reverse) ? 2 : 0; (i < 3 && (!do_reverse_frag || tls_force_native || super_reverse)) || ((do_reverse_frag && !tls_force_native && !super_reverse) && i >= 0); (do_reverse_frag && !tls_force_native && !super_reverse) ? i-- : i++) { //Dynamic plan!
                                addr.IPChecksum = 0;
                                addr.TCPChecksum = 0;
                                if (i == 2) {
                                    //printf("STAGE 3\n");
                                    for (int x = (do_reverse_frag && !tls_force_native && !super_reverse) ? ((packetLen - (unsigned int)(host_addr - packet) - host_len) / tls_segment_size * tls_segment_size) : 0; (x < (packetLen - (unsigned int)(host_addr - packet) - host_len) && (!do_reverse_frag || tls_force_native || super_reverse)) || ((do_reverse_frag && !tls_force_native && !super_reverse) && x >= 0); (do_reverse_frag && !tls_force_native && !super_reverse) ? (x -= tls_segment_size) : (x += tls_segment_size)) {
                                        totalLength = (x + tls_segment_size > (packetLen - (unsigned int)(host_addr - packet) - host_len) ? (packetLen - (unsigned int)(host_addr - packet) - host_len) % tls_segment_size : tls_segment_size) + hdrLen + dataOffset;
                                        tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + host_len) + x;
                                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                        memcpy(fragmentHolder + hdrLen + dataOffset, packet + (tcpSeq - tcpBaseSeq) + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
                                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                                        newpacketid(fragmentHolder);
                                        WinDivertHelperCalcChecksums(
                                            fragmentHolder, totalLength, &addr, 0
                                        );
                                        #ifdef DEBUG
                                        reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                        #endif
                                        if (!super_reverse)
                                        WinDivertSend(
                                            w_filter, fragmentHolder,
                                            totalLength,
                                            NULL, &addr
                                        );
                                        else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    }
                                }
                                if (i == 1 && host_len > sni_fragment_size) { //OK
                                    //printf("STAGE 2: %u\n", host_len);
                                    for (int x = ((do_reverse_frag && !tls_force_native && !super_reverse) ? host_len - sni_fragment_size : 0); ((!do_reverse_frag || tls_force_native || super_reverse) && x < host_len) || ((do_reverse_frag && !tls_force_native && !super_reverse) && x >= 0); x += ((do_reverse_frag && !tls_force_native && !super_reverse) ? -sni_fragment_size : sni_fragment_size)) {
                                        //printf("OFFSET: %d\n", x);
                                        memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + x, sni_fragment_size);
                                        tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + x);
                                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                        totalLength = hdrLen + dataOffset + sni_fragment_size;
                                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                                        newpacketid(fragmentHolder);
                                        WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                        );
                                        #ifdef DEBUG
                                        reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                        #endif
                                        if (!super_reverse)
                                        WinDivertSend(
                                            w_filter, fragmentHolder,
                                            totalLength,
                                            NULL, &addr
                                        );
                                        else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    }
                                }
                                if (host_len % sni_fragment_size > 0 && i == 1) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + ((do_reverse_frag && !tls_force_native && !super_reverse) ? 0 : host_len - (host_len % sni_fragment_size)), host_len % sni_fragment_size);
                                    convert_endian(&tcpSeq, packet + hdrLen + 4, 4);
                                    tcpSeq = tcpBaseSeq + (unsigned int)(host_addr - packet) - hdrLen - dataOffset + ((do_reverse_frag && !tls_force_native && !super_reverse) ? 0 : host_len - (host_len % sni_fragment_size));
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    totalLength = hdrLen + dataOffset + (host_len % sni_fragment_size);
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                    newpacketid(fragmentHolder);
                                    WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                    );
                                    #ifdef DEBUG
                                    reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                    #endif
                                    if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                    else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                }
                                if (i == 0) {
                                    //printf("STAGE 1\n");
                                    for (int x = (do_reverse_frag && !tls_force_native && !super_reverse) ? (((unsigned int)(host_addr - packet) - hdrLen - dataOffset) / tls_segment_size * tls_segment_size) : 0; (x < ((unsigned int)(host_addr - packet) - hdrLen - dataOffset) && (!do_reverse_frag || tls_force_native || super_reverse)) || ((do_reverse_frag && !tls_force_native && !super_reverse) && x >= 0); (do_reverse_frag && !tls_force_native && !super_reverse) ? (x -= tls_segment_size) : (x += tls_segment_size)) {
                                        totalLength = (x + tls_segment_size > ((unsigned int)(host_addr - packet) - hdrLen - dataOffset) ? ((unsigned int)(host_addr - packet) - hdrLen - dataOffset) % tls_segment_size : tls_segment_size) + hdrLen + dataOffset;
                                        tcpSeq = tcpBaseSeq + x;
                                        convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                        memcpy(fragmentHolder + hdrLen + dataOffset, packet + (tcpSeq - tcpBaseSeq) + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
                                        convert_endian(fragmentHolder + 2, &totalLength, 2);
                                        newpacketid(fragmentHolder);
                                        WinDivertHelperCalcChecksums(
                                            fragmentHolder, totalLength, &addr, 0
                                        );
                                        #ifdef DEBUG
                                        reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                        #endif
                                        if (!super_reverse)
                                        WinDivertSend(
                                            w_filter, fragmentHolder,
                                            totalLength,
                                            NULL, &addr
                                        );
                                        else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    }
                                }
                            }
                        }
                        else { //BEGIN EXTENSION FRAGMENTATION
                            progress = 0;
                            while (progress < packetLen - dataOffset - hdrLen) {
                                //Before doing anything, acquire the length of the extension we're working on, and what extension it is. [If the remaining payload is 4 or more bytes long.]
                                if (packetLen - dataOffset - hdrLen - progress >= 4) {
                                    convert_endian(&extensionType, packet + dataOffset + hdrLen + progress, 2);
                                    convert_endian(&extensionLen, packet + dataOffset + hdrLen + progress + 2, 2);
                                }
                                //Send the first byte of the extension information.
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, 1);
                                tcpSeq = tcpBaseSeq + progress;
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                totalLength = hdrLen + dataOffset + 1;
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                #ifdef DEBUG
                                reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                #endif
                                if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                progress += 1;
                                //Send the second and third byte.
                                if (packetLen - dataOffset - hdrLen - progress == 1) { //Ran out of payload data, Exit.
                                    fragmentHolder[hdrLen + dataOffset] = packet[hdrLen + dataOffset + progress];
                                    tcpSeq = tcpBaseSeq + progress;
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    totalLength = hdrLen + dataOffset + 1;
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                    newpacketid(fragmentHolder);
                                    WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                    );
                                    #ifdef DEBUG
                                    reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                    #endif
                                    if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                    else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    progress += 1;
                                    if (!super_reverse) continue;
                                    else goto wrapup;
                                }
                                else if (packetLen - dataOffset - hdrLen - progress == 0) {
                                    if (!super_reverse) continue;
                                    else goto wrapup;
                                }
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, 2);
                                tcpSeq = tcpBaseSeq + progress;
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                totalLength = hdrLen + dataOffset + 2;
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                #ifdef DEBUG
                                reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                #endif
                                if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                progress += 2;
                                //Send the last byte of extension information.
                                if (packetLen - dataOffset - hdrLen - progress == 0) {
                                    clientHelloSearch[freeWaiting].exttype = extensionType;
                                    clientHelloSearch[freeWaiting].extlen = packet[dataOffset + hdrLen + progress - 1] << 8;
                                    clientHelloSearch[freeWaiting].stage = 2;
                                    if (!super_reverse) continue;
                                    else goto wrapup;
                                }
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, 1);
                                tcpSeq = tcpBaseSeq + progress;
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                totalLength = hdrLen + dataOffset + 1;
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                                newpacketid(fragmentHolder);
                                WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                );
                                #ifdef DEBUG
                                reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                #endif
                                if (!super_reverse)
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                                else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                progress += 1;
                                if (packetLen - dataOffset - hdrLen - progress == 0) { 
                                    if (!super_reverse) continue;
                                    else goto wrapup;
                                }
                                //Set the extension's length to the size of the remaining payload if its larger than the remaining payload.
                                if (extensionLen > packetLen - dataOffset - hdrLen - progress) {
                                    extensionLen = packetLen - dataOffset - hdrLen - progress;
                                }
                                current_fragment_size = ext_frag_size;
                                //If the extension is the SNI, use SNI fragment size.
                                if (extensionType == 0) current_fragment_size = sni_fragment_size;
                                while (current_fragment_size <= extensionLen) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                                    totalLength = hdrLen + dataOffset + current_fragment_size;
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                    tcpSeq = tcpBaseSeq + progress;
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    newpacketid(fragmentHolder);
                                    WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                    );
                                    #ifdef DEBUG
                                    reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                    #endif
                                    if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                    else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    extensionLen -= current_fragment_size;
                                    progress += current_fragment_size;
                                }
                                if (extensionLen > 0) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, extensionLen);
                                    totalLength = hdrLen + dataOffset + extensionLen;
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                    tcpSeq = tcpBaseSeq + progress;
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    newpacketid(fragmentHolder);
                                    WinDivertHelperCalcChecksums(
                                        fragmentHolder, totalLength, &addr, 0
                                    );
                                    #ifdef DEBUG
                                    reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                                    #endif
                                    if (!super_reverse)
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                    else add_fragment(fragmentHolder, fragmentInfo, &fragmentInfoLen);
                                    progress += extensionLen;
                                }
                            }
                        }
                        if (compound_frag && do_reverse_frag && !tls_force_native && !super_reverse) {
                            //Repair the packet.
                            memcpy(fragmentHolder, packetBACK, hdrLen + dataOffset);
                            memcpy(fragmentHolder + hdrLen + dataOffset, compound_fragHolder, https_fragment_size);
                            totalLength = hdrLen + dataOffset + https_fragment_size;
                            convert_endian(fragmentHolder + 2, &totalLength, 2);
                            newpacketid(fragmentHolder);
                            WinDivertHelperCalcChecksums(
                                fragmentHolder, totalLength, &addr, 0
                            );
                            #ifdef DEBUG
                            reassemble_and_compare(fragmentHolder, reassembleSegments, tcpBaseSeqTrue, packetBACK + hdrLen + dataOffset);
                            #endif
                            WinDivertSend(
                                w_filter, fragmentHolder,
                                totalLength,
                                NULL, &addr
                            );
                        }
                        wrapup:
                        memcpy(fragmentHolder, packetBACK, hdrLen + dataOffset);
                        if (super_reverse && fragmentInfoLen > 1) {
                            unsigned char mode = 0;
                            if (record_frag) mode = 3;
                            else if (vortex_frag) mode = 1;
                            else if (rplrr) mode = 2;
                            else if (fnroor) mode = 4;
                            do_super_reverse_frag(mode, fragmentInfo, fragmentInfoLen, packetBACK, tcpBaseSeqTrue, 0);
                        }
                        #ifdef DEBUG
                        if (!smart_frag && compound_frag) packetLen += https_fragment_size;
                        if (smart_frag) packetLen += 49 + compresslen + session_len + ciphersuitelen;
                        convert_endian(&totalLength, packet + 2, 2);
                        printf("%u\n", packetLen - dataOffset - hdrLen);
                        printf("%u\n", totalLength - dataOffset - hdrLen);
                        if (totalLength != packetLen) printf("SIZE FAIL\n");
                        xprint(packetBACK + hdrLen + dataOffset, packetLen - dataOffset - hdrLen, 40);
                        printf("\n\n");
                        xprint(reassembleSegments, packetLen - dataOffset - hdrLen, 40);
                        printf("\n");
                        differentiate(packetBACK + hdrLen + dataOffset, packetLen - dataOffset - hdrLen, reassembleSegments, packetLen - dataOffset - hdrLen, 0);
                        #endif
                        continue;
                    }
                    if (current_fragment_size) {
                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen,packet_v4, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, do_reverse_frag);

                        send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                            packet_dataLen,packet_v4, packet_v6,
                                            ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                            current_fragment_size, !do_reverse_frag);
                        continue;
                    }
                }
            } /* Handle TCP packet with data */

            /* Else if we got TCP packet without data */
            else if (packet_type == ipv4_tcp || packet_type == ipv6_tcp) {
                /* If we got INBOUND SYN+ACK packet */
                if (!addr.Outbound &&
                    ppTcpHdr->Syn == 1 && ppTcpHdr->Ack == 1) {
                    //printf("Changing Window Size!\n");
                    /*
                     * Window Size is changed even if do_fragment_http_persistent
                     * is enabled as there could be non-HTTP data on port 80
                     */

                    if (do_fake_packet && (do_auto_ttl || ttl_min_nhops)) {
                        if (!((packet_v4 && tcp_handle_incoming(&ppIpHdr->SrcAddr, &ppIpHdr->DstAddr,
                                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
                                        0, ppIpHdr->TTL))
                            ||
                            (packet_v6 && tcp_handle_incoming((uint32_t*)&ppIpV6Hdr->SrcAddr,
                                        (uint32_t*)&ppIpV6Hdr->DstAddr,
                                        ppTcpHdr->SrcPort, ppTcpHdr->DstPort,
                                        1, ppIpV6Hdr->HopLimit))))
                        {
                            if (do_tcp_verb)
                                puts("[TCP WARN] Can't add TCP connection record.");
                        }
                    }
                }
            }

            /* Else if we got UDP packet with data */
            else if ((packet_type == ipv4_udp_data) ||
                     (packet_type == ipv6_udp_data))
            {
                if (!addr.Outbound && (do_dnsv4_redirect || do_dnsv6_redirect)) {
                    if ((packet_v4 && dns_handle_incoming(&ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen,
                                        &dns_conn_info, 0)) && do_dnsv4_redirect
                        ||
                        (packet_v6 && dns_handle_incoming(ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                                        packet_data, packet_dataLen,
                                        &dns_conn_info, 1)) && do_dnsv6_redirect)
                    {
                        /* Changing source IP and port to the values
                         * from DNS conntrack */
                        if (packet_v4)
                            ppIpHdr->SrcAddr = dns_conn_info.dstip[0];
                        else if (packet_v6)
                            ipv6_copy_addr(ppIpV6Hdr->SrcAddr, dns_conn_info.dstip);
                        ppUdpHdr->DstPort = dns_conn_info.srcport;
                        ppUdpHdr->SrcPort = dns_conn_info.dstport;
                        should_recalc_checksum = 1;
                    }
                    else {
                        if (dns_is_dns_packet(packet_data, packet_dataLen, 0))
                            should_reinject = 0;

                        if (do_dns_verb && !should_reinject) {
                            printf("[DNS] Error handling incoming packet: srcport = %hu, dstport = %hu\n",
                               ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
                        }
                    }
                    //printf("Incoming DNS response!\n");
                    //analyze_ip_header(packet);
                }
                else if (addr.Outbound) {
                    if (do_dnsv4_redirect || do_dnsv6_redirect) {
                        if ((packet_v4 && dns_handle_outgoing(&ppIpHdr->SrcAddr, ppUdpHdr->SrcPort,
                            &ppIpHdr->DstAddr, ppUdpHdr->DstPort,
                            packet_data, packet_dataLen, 0)) && do_dnsv4_redirect
                            ||
                            (packet_v6 && dns_handle_outgoing(ppIpV6Hdr->SrcAddr, ppUdpHdr->SrcPort,
                            ppIpV6Hdr->DstAddr, ppUdpHdr->DstPort,
                            packet_data, packet_dataLen, 1)) && do_dnsv6_redirect)
                        {
                            /* Changing destination IP and port to the values
                             * from configuration */
                            if (packet_v4) {
                                ppIpHdr->DstAddr = dnsv4_addr;
                                ppUdpHdr->DstPort = dnsv4_port;
                            }
                            else if (packet_v6) {
                                ipv6_copy_addr(ppIpV6Hdr->DstAddr, (uint32_t*)dnsv6_addr.s6_addr);
                                ppUdpHdr->DstPort = dnsv6_port;
                            }
                            should_recalc_checksum = 1;
                        }
                        else {
                            if (dns_is_dns_packet(packet_data, packet_dataLen, 1))
                                should_reinject = 0;

                            if (do_dns_verb && !should_reinject) {
                                printf("[DNS] Error handling outgoing packet: srcport = %hu, dstport = %hu\n",
                                   ntohs(ppUdpHdr->SrcPort), ntohs(ppUdpHdr->DstPort));
                            }
                        }
                    }
                    if (drop_unsecure_dns && dns_is_dns_packet(packet_data, packet_dataLen, 1)) should_reinject = 0;
                }
            }
            if (should_reinject) {
                if (should_recalc_checksum) {
                    newpacketid(packet);
                    WinDivertHelperCalcChecksums(packet, packetLen, &addr, (UINT64)0LL);
                }
                WinDivertSend(w_filter, packet, packetLen, NULL, &addr);
                for (int i = 0; i < connectionslen; i++) {
                    if (connections[i].taken && connections[i].ip == *((unsigned int*)(packet + 16)) && connections[i].seq == ntohl(*((unsigned int*)(packet + hdrLen + 4)))) {
                        connections[i].taken = 0;
                        break;
                    }
                }
            }
        }
        else {
            // error, ignore
            if (!exiting)
                printf("Error receiving packet! (%u)\n", GetLastError());
            break;
        }
    }
}
