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
#define MAX_PACKET_SIZE 2048
// My mingw installation does not load inet_pton definition for some reason
WINSOCK_API_LINKAGE INT WSAAPI inet_pton(INT Family, LPCSTR pStringBuf, PVOID pAddr);

#define GOODBYEDPI_VERSION "v0.3"

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
#define FILTER_STRING_TEMPLATE \
        "(tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
        "((inbound and (" \
         "(" \
          "(" \
           "(ipv6 or (ip.Id >= 0x0 and ip.Id <= 0xF) " IPID_TEMPLATE \
           ") and " \
           "tcp.SrcPort == 80 and tcp.Ack" \
          ") or " \
          "((tcp.SrcPort == 80 or tcp.SrcPort == 443) and tcp.Ack and tcp.Syn)" \
         ")" \
         " and (" DIVERT_NO_LOCALNETSv4_SRC " or " DIVERT_NO_LOCALNETSv6_SRC "))) or " \
        "(outbound and " \
         "(tcp.DstPort == 80 or tcp.DstPort == 443 or tcp.DstPort == 2096) and tcp.Ack and " \
         "(" DIVERT_NO_LOCALNETSv4_DST " or " DIVERT_NO_LOCALNETSv6_DST "))" \
        "))"
#define FILTER_PASSIVE_BLOCK_QUIC "outbound and !impostor and !loopback and udp " \
        "and udp.DstPort == 443 and udp.PayloadLength >= 1200 " \
        "and udp.Payload[0] >= 0xC0 and udp.Payload32[1b] == 0x01"
#define FILTER_PASSIVE_STRING_TEMPLATE "inbound and ip and tcp and " \
        "!impostor and !loopback and " \
        "(true " IPID_TEMPLATE ") and " \
        "(tcp.SrcPort == 443 or tcp.SrcPort == 80) and tcp.Rst and " \
        DIVERT_NO_LOCALNETSv4_SRC

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
    {"sni-force-native", no_argument,  0,  ';' },
    {"ip-id",       required_argument, 0,  'i' },
    {"set-ttl",     required_argument, 0,  '$' },
    {"min-ttl",     required_argument, 0,  '[' },
    {"auto-ttl",    optional_argument, 0,  '+' },
    {"wrong-chksum",no_argument,       0,  '%' },
    {"wrong-seq",   no_argument,       0,  ')' },
    {"native-frag", no_argument,       0,  '*' },
    {"reverse-frag",no_argument,       0,  '(' },
    {"max-payload", optional_argument, 0,  '|' },
    {"fake-from-hex",required_argument,0,  'u' },
    {"fake-with-sni",required_argument,0,  '}' },
    {"fake-gen",    required_argument, 0,  'j' },
    {"fake-resend", required_argument, 0,  'T' },
    {"debug-exit",  optional_argument, 0,  'x' },
    {"discord-vc",  optional_argument, 0,  '-' },
    {"help",        no_argument,       0,  'h' },
    {"compound-frag", no_argument,     0,  'o'},
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
static void add_filter_str_portless(int proto) {
    const char *udp = " or (udp and !loopback and outbound and !impostor and !fragment)";
    const char *tcp = " or (tcp and and !loopback and !impostor " MAXPAYLOADSIZE_TEMPLATE ")";

    char *current_filter = filter_string;
    size_t new_filter_size = strlen(current_filter) +
            (proto == IPPROTO_UDP ? strlen(udp) : strlen(tcp)) + 16;
    char *new_filter = malloc(new_filter_size);

    strcpy(new_filter, current_filter);
    if (proto == IPPROTO_UDP)
        sprintf(new_filter + strlen(new_filter), udp);
    else
        sprintf(new_filter + strlen(new_filter), tcp);

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
    if (errorcode == 2)
        printf("The driver files WinDivert32.sys or WinDivert64.sys were not found.\n");
    else if (errorcode == 654)
        printf("An incompatible version of the WinDivert driver is currently loaded.\n"
               "Please unload it with the following commands ran as administrator:\n\n"
               "sc stop windivert\n"
               "sc delete windivert\n"
               "sc stop windivert14"
               "sc delete windivert14\n");
    else if (errorcode == 1275)
        printf("This error occurs for various reasons, including:\n"
               "the WinDivert driver is blocked by security software; or\n"
               "you are using a virtualization environment that does not support drivers.\n");
    else if (errorcode == 1753)
        printf("This error occurs when the Base Filtering Engine service has been disabled.\n"
               "Enable Base Filtering Engine service.\n");
    else if (errorcode == 577)
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
unsigned int activate_thrash = 0;
HANDLE thrash_filter;
static void sigint_handler(int sig __attribute__((unused))) {
    exiting = 1;
    deinit_all();
    if (activate_thrash) {
	    WinDivertShutdown(thrash_filter, WINDIVERT_SHUTDOWN_BOTH);
	    WinDivertClose(thrash_filter);
    }
    exit(EXIT_SUCCESS);
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

unsigned char analyze_ver, analyze_hlen, analyze_typeofservice, analyze_ttl, analyze_protocol;
uint16_t analyze_totallength, analyze_ID, analyze_fragoff, analyze_hdrchksum, analyze_srcport, analyze_dstport, analyze_udplen, analyze_chksum;
unsigned char analyze_reserved, analyze_dontfragment, analyze_morefragments;
char charholder[2];
void charputter(char charr) {
    charholder[1] = (char) 0;
    charholder[0] = charr;
    printf("%s", charholder);
}
void xprint(char* pchar, unsigned int size) {
    for (int i = 0; i < size; i++) {
        charputter(pchar[i]);
    }
}
const char hex[16] = "0123456789ABCDEF";
char hexholder[3] = "00\0";
void hexprint(char* pchar, unsigned int size) {
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
void analyze_tcp_header(unsigned char* packet, unsigned char iphdrlen) {
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
unsigned int diffs = 0;
void differentiate(unsigned char* compared, unsigned int comparedsize, unsigned char* compare, unsigned int comparesize) {
    if (comparedsize != comparesize) printf("Data size has a %u byte difference %s.\n", comparedsize < comparesize ? comparesize - comparedsize : comparedsize - comparesize, comparedsize < comparesize ? "to the right" : "to the left");
    diffs = 0;
    for (int i = 0; i < comparedsize && i < comparesize; i++) {
        if (compared[i] != compare[i]) {
            printf("MISMATCH AT BYTE %u: ", i + 1);
            printf("%u %u\n", compared[i], compare[i]);
            diffs++;
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
                        char *packet, UINT packetLen, PVOID packet_data,
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
uint16_t calc_ip_header_checksum(unsigned char *packet, unsigned int hdrLen) {
    for (unsigned int i = 0; i < hdrLen; i += 2) {
        if (i != 10 && i != 11) {
            memcpy(&wordhold, packet + i, 2);
            testsum += wordhold;
        }
    }
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
    //Yeah.
}
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
    differentiate(reassemblePacket, totalLength, packet, packetLen);
    checksumtest(reassemblePacket, hdrLen * 4);
    #endif
    return true;
}
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
int main(int argc, char *argv[]) {
    hexbuff[2] = (char)0;
    fragmentHolder = calloc(MAX_PACKET_SIZE, sizeof(char));
    reassemblePacket = calloc(MAX_PACKET_SIZE, sizeof(char));
    unsigned char* reassembleSegments = calloc(MAX_PACKET_SIZE, sizeof(unsigned char));
    unsigned char* packetBACK = calloc(MAX_PACKET_SIZE, sizeof(unsigned char));
    char packetscan[2];
    packetscan[1] = (char) NULL;
    static enum packet_type_e {
        unknown,
        ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
        ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
    } packet_type;
    bool debug_exit = false;
    uint16_t domainLen = 0;
    int i, should_reinject, should_recalc_checksum = 0,
    sni_ok = 0,
    opt,
    packet_v4, packet_v6;
    HANDLE w_filter = NULL;
    WINDIVERT_ADDRESS addr;
    unsigned char packet[MAX_PACKET_SIZE];
    PVOID packet_data;
    UINT packetLen;
    UINT packet_dataLen;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_IPV6HDR ppIpV6Hdr;
    PWINDIVERT_TCPHDR ppTcpHdr;
    PWINDIVERT_UDPHDR ppUdpHdr;
    conntrack_info_t dns_conn_info;
    tcp_conntrack_info_t tcp_conn_info;
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
        do_native_frag = 0, do_reverse_frag = 0, compound_frag = 0, sni_force_native = 0, udp_fragments = 0, proceed = 0, hshift = 0, totalHdrLength = 0;
    unsigned int http_fragment_size = 0, https_fragment_size = 0, sni_fragment_size = 0, current_fragment_size = 0, udp_fakes = 0;
    unsigned short max_payload_size = 0;
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
    unsigned char *host_addr, *useragent_addr, *method_addr;
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

    void* thrash() { //Why do I need a void* function instead of a void? Oh well.
        thrash_filter = WinDivertOpen("outbound and udp and !impostor and !loopback and udp.DstPort > 49999 and udp.DstPort < 50100\0", WINDIVERT_LAYER_NETWORK, 1, 0);
        while (!exiting) {
            if (WinDivertRecv(thrash_filter, thrash_packet, 65536, &thrash_packetLen, &thrash_addr)) {
			    WinDivertHelperCalcChecksums(thrash_packet, thrash_packetLen, &thrash_addr, 0);
                memcpy(thrash_fake, thrash_packet, thrash_packetLen);
                //Encapsulate in trash
                xorinate(thrash_fake + 28, 20 % (thrash_packetLen - 28), "IAMTHRASH", 9);
			    WinDivertHelperCalcChecksums(thrash_fake, thrash_packetLen, &thrash_addr, 0);
                #ifdef DEBUG
                printf("Sending %u fakes!\n", udp_fakes / 2 + udp_fakes % 2);
                #endif
                for (int i = 0; i < (udp_fakes / 2 + udp_fakes % 2); i++) {
                    WinDivertSend(thrash_filter, thrash_fake, thrash_packetLen, NULL, &thrash_addr);
                }
                WinDivertSend(thrash_filter, thrash_packet, thrash_packetLen, NULL, &thrash_addr);
                #ifdef DEBUG
                printf("Sending %u fakes!\n", udp_fakes / 2);
                #endif
                for (int i = 0; i < (udp_fakes / 2); i++) {
                    WinDivertSend(thrash_filter, thrash_fake, thrash_packetLen, NULL, &thrash_addr);
                }
            }
        }
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
            case 'q':
                do_block_quic = 1;
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
            case 'm':
                do_host_mixedcase = 1;
                break;
            case '-': // --discord-vc
                const char *tcp = " or (tcp and !impostor and !loopback " MAXPAYLOADSIZE_TEMPLATE " and " \
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
                //printf("Shit: %u\n", atousi(optarg, "UDP Fake packet assignment error!"));
                if (optarg && atousi(optarg, "UDP Fake packet assignment error!") > 0)
                    udp_fakes = atousi(optarg, "UDP Fake packet assignment error!");
                else
                    udp_fakes = 1;
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
            case 'w':
                do_http_allports = 1;
                break;
#ifdef UDPTEST
            case 'y':
                add_filter_str_portless(IPPROTO_UDP);
                udp_fragments = atousi(optarg, "Fragment amount should be <= 4.");
                if (udp_fragments < 1) udp_fragments = 1;
                if (udp_fragments > 4) udp_fragments = 4;
                break;
#endif
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
            case 'i': // --ip-id
                /* i is used as a temporary variable here */
                i = atousi(optarg, "IP ID parameter error!\n");
                add_ip_id_str(i);
                i = 0;
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
            case ';': //sni-force-native
                sni_force_native = 1;
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
            case '?':
                drop_unsecure_dns = 1;
                break;
            case ']': // --allow-no-sni
                do_allow_no_sni = 1;
                break;
            case '>': // --frag-by-sni
                do_fragment_by_sni = 1;
                break;
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
            case ')': // --wrong-seq
                do_fake_packet = 1;
                do_wrong_seq = 1;
                break;
            case '*': // --native-frag
                do_native_frag = 1;
                do_fragment_http_persistent = 1;
                do_fragment_http_persistent_nowait = 1;
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
                " --whitelist   <txtfile>  do not perform circumvention tricks only to host names and subdomains from\n"
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
                " --sni-force-native       Forces the fragmented TLS ClientHello to be sent in the right order,\n"
                "                          may fix impatient websites.\n"
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
           "Fragment by SNI: %u\n"                  /* 7 */
           "SNI Native Fragmentation: %u\n"         /* 8 */
           #ifdef UDPTEST
           "UDP fragments: %u\n"                    /* 9 */
           #endif
           "Native fragmentation (splitting): %d\n" /* 10 */
           "Fragments sending in reverse: %d\n"     /* 11 */
           "hoSt: %d\n"                             /* 12 */
           "Host no space: %d\n"                    /* 13 */
           "Additional space: %d\n"                 /* 14 */
           "Mix Host: %d\n"                         /* 15 */
           "HTTP AllPorts: %d\n"                    /* 16 */
           "HTTP Persistent Nowait: %d\n"           /* 17 */
           "Fix Discord VC: %u (Fake packets: %u)\n"/* 18 */
           "DNS redirect: %d\n"                     /* 19 */
           "DNSv6 redirect: %d\n"                   /* 20 */
           "Drop unsecure DNS: %d\n"                /* 21 */
           "Allow missing SNI: %d\n"                /* 22 */
           "Fake requests, TTL: %s (fixed: %hu, auto: %hu-%hu-%hu, min distance: %hu)\n"  /* 23 */
           "Fake requests, wrong checksum: %d\n"    /* 24 */
           "Fake requests, wrong SEQ/ACK: %d\n"     /* 25 */
           "Fake requests, custom payloads: %d\n"   /* 26 */
           "Fake requests, resend: %d\n"            /* 27 */
           "Max payload size: %hu\n",               /* 28 */
           do_passivedpi,                          /* 1 */ 
           do_block_quic,                          /* 2 */
           (do_fragment_http ? http_fragment_size : 0),           /* 3 */
           (do_fragment_http_persistent ? http_fragment_size : 0),/* 4 */
           (do_fragment_https ? https_fragment_size : 0),         /* 5 */
           sni_fragment_size,     /* 6 */
           do_fragment_by_sni,    /* 7 */
           sni_force_native,      /* 8 */
           #ifdef UDPTEST
           udp_fragments,         /* 9 */
           #endif
           do_native_frag,        /* 10 */
           do_reverse_frag,       /* 11 */
           do_host,               /* 12 */
           do_host_removespace,   /* 13 */
           do_additional_space,   /* 14 */
           do_host_mixedcase,     /* 15 */
           do_http_allports,      /* 16 */
           do_fragment_http_persistent_nowait, /* 17 */
           activate_thrash, udp_fakes,         /* 18 */
           do_dnsv4_redirect,                  /* 19 */
           do_dnsv6_redirect,                  /* 20 */
           drop_unsecure_dns,                  /* 21 */
           do_allow_no_sni,                    /* 22 */
           do_auto_ttl ? "auto" : (do_fake_packet ? "fixed" : "disabled"),  /* 23 */
               ttl_of_fake_packet, do_auto_ttl ? auto_ttl_1 : 0, do_auto_ttl ? auto_ttl_2 : 0,
               do_auto_ttl ? auto_ttl_max : 0, ttl_min_nhops,
           do_wrong_chksum, /* 24 */
           do_wrong_seq,    /* 25 */
           fakes_count,     /* 26 */
           fakes_resend,    /* 27 */
           max_payload_size/* 28 */
          );

    if (do_fragment_http && http_fragment_size > 2 && !do_native_frag) {
        puts("\nWARNING: HTTP fragmentation values > 2 are not fully compatible "
             "with other options. Please use values <= 2 or disable HTTP fragmentation "
             "completely.");
    }
    if (compound_frag && sni_fragment_size == 0) puts(
        "\nWARNING: Compound fragmentation is enabled but SNI fragmentation is not enabled.\n"
        "Compound fragmentation is not done."
    );
    if (do_native_frag && !(do_fragment_http || do_fragment_https)) {
        puts("\nERROR: Native fragmentation is enabled but fragment sizes are not set.\n"
             "Fragmentation has no effect.");
        die();
    }

    if (max_payload_size) add_maxpayloadsize_str(max_payload_size);
    finalize_filter_strings();
    pthread_t thrash_thread;
    if (activate_thrash) {
        pthread_create(&thrash_thread, NULL, thrash, NULL);
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
    //printf("My filter is %s", filter_string);
    w_filter = filters[filter_num];
    filter_num++;

    for (i = 0; i < filter_num; i++) {
        if (filters[i] == NULL)
            die();
    }
    printf("Filter activated, GoodbyeDPI is now running!\n");
    signal(SIGINT, sigint_handler);
    unsigned char* compound_fragHolder = (unsigned char*) malloc(https_fragment_size);

    while (1) {
        proceed = 0;
        if (WinDivertRecv(w_filter, packet, sizeof(packet), &packetLen, &addr)) {
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
            // Parse network packet and set it's type
            if (WinDivertHelperParsePacket(packet, packetLen, &ppIpHdr,
                &ppIpV6Hdr, NULL, NULL, NULL, &ppTcpHdr, &ppUdpHdr, &packet_data, &packet_dataLen,
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
                        if (do_blacklist || do_fragment_by_sni || sni_fragment_size) {
                            sni_ok = extract_sni(packet_data, packet_dataLen,
                                        &host_addr, &host_len);
                        }
                        if (
                             (do_blacklist && sni_ok &&
                              blackwhitelist_check_hostname(host_addr, host_len, 0)
                             ) ||
                             (do_blacklist && !sni_ok && do_allow_no_sni) ||
                             (!do_blacklist && (!do_whitelist || (do_whitelist && blackwhitelist_check_hostname(host_addr, host_len, 1))))
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
                        (do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len, 0) : 1))
                    {
                        if (do_whitelist && !do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len, 1) : 1) proceed = 1;
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
                if (sni_ok && sni_fragment_size) {
                    should_recalc_checksum = 1; //Signal to native fragmentation handler
                }
                /*
                * should_recalc_checksum mean we have detected a packet to handle and
                * modified it in some way.
                * Handle native fragmentation here, incl. sending the packet.
                */
                if (should_reinject && should_recalc_checksum && do_native_frag && !proceed)
                {
                    current_fragment_size = 0;
                    if (do_fragment_http && ppTcpHdr->DstPort == htons(80)) {
                        current_fragment_size = http_fragment_size;
                    }
                    else if (do_fragment_https && ppTcpHdr->DstPort != htons(80)) {
                        if (do_fragment_by_sni && sni_ok) {
                            current_fragment_size = (void*)host_addr - packet_data;
                        } else {
                            current_fragment_size = https_fragment_size;
                        }
                    }
                    if (sni_fragment_size && sni_ok && packet_v4) {
                        hdrLen = (packet[0] & 0b00001111) * 4;
                        dataOffset = (packet[hdrLen + 12] >> 4) * 4;
                        convert_endian(&tcpBaseSeq, packet + hdrLen + 4, 4);
                        tcpBaseSeqTrue = tcpBaseSeq;
                        if (compound_frag && do_native_frag && !do_reverse_frag) {
                            memcpy(packetBACK, packet, packetLen); //Back 'er up!
                            send_native_fragment(w_filter, addr, packet, packetLen, packet_data,
                                                packet_dataLen,packet_v4, packet_v6,
                                                ppIpHdr, ppIpV6Hdr, ppTcpHdr,
                                                https_fragment_size, 0);
                        }
                        else if (compound_frag && do_reverse_frag) {
                            memcpy(packetBACK, packet, packetLen); //Back 'er up!
                            memcpy(compound_fragHolder, packet + hdrLen + dataOffset, https_fragment_size); //Hold onto the first [https_fragment_size] bytes of the payload.
                        }
                        if (compound_frag) {
                            tcpBaseSeq += https_fragment_size;
                            host_addr -= https_fragment_size;
                            memmove(packet + hdrLen + dataOffset, packet + hdrLen + dataOffset + https_fragment_size, packetLen - https_fragment_size - hdrLen - dataOffset);
                            packetLen -= https_fragment_size;
                        }
                        memcpy(fragmentHolder, packet, hdrLen + dataOffset);
                        for (int i = (do_reverse_frag && !sni_force_native) ? 2 : 0; (i < 3 && (!do_reverse_frag || sni_force_native)) || ((do_reverse_frag && !sni_force_native) && i >= 0); (do_reverse_frag && !sni_force_native) ? i-- : i++) { //Three step plan!
                            addr.IPChecksum = 0;
                            addr.TCPChecksum = 0;
                            //Why is it backwards? Because why not! [I just thought backwards.]
                            if (i == 2) { //OK
                                memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + host_len, packetLen - (unsigned int)(host_addr - packet) - host_len);
                                tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + host_len);
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                totalLength = hdrLen + dataOffset + (packetLen - (unsigned int)(host_addr - packet) - host_len);
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                            }
                            if (i == 1 && host_len > sni_fragment_size) { //Meet the spaghetti monster, and the actual SNI fragmenation part. OK
                                for (int x = ((do_reverse_frag && !sni_force_native) ? host_len - sni_fragment_size : 0); ((!do_reverse_frag || sni_force_native) && x < host_len) || ((do_reverse_frag && !sni_force_native) && x > 0); x += ((do_reverse_frag && !sni_force_native) ? -sni_fragment_size : sni_fragment_size)) {
                                    memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + x, sni_fragment_size);
                                    tcpSeq = tcpBaseSeq + ((unsigned int)(host_addr - packet) - hdrLen - dataOffset + x);
                                    convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                    totalLength = hdrLen + dataOffset + sni_fragment_size;
                                    convert_endian(fragmentHolder + 2, &totalLength, 2);
                                    WinDivertHelperCalcChecksums(
                                    fragmentHolder, totalLength, &addr, 0
                                    );
                                    WinDivertSend(
                                        w_filter, fragmentHolder,
                                        totalLength,
                                        NULL, &addr
                                    );
                                }
                            }
                            if (host_len % sni_fragment_size > 0 && i == 1) { //VERIFIED
                                memcpy(fragmentHolder + hdrLen + dataOffset, host_addr + ((do_reverse_frag && !sni_force_native) ? 0 : host_len - (host_len % sni_fragment_size)), host_len % sni_fragment_size);
                                convert_endian(&tcpSeq, packet + hdrLen + 4, 4);
                                tcpSeq = tcpBaseSeq + (unsigned int)(host_addr - packet) - hdrLen - dataOffset + ((do_reverse_frag && !sni_force_native) ? 0 : host_len - (host_len % sni_fragment_size));
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                totalLength = hdrLen + dataOffset + (host_len % sni_fragment_size);
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                            }
                            if (i == 0) { //OK
                                tcpSeq = tcpBaseSeq;
                                convert_endian(fragmentHolder + hdrLen + 4, &tcpSeq, 4);
                                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset, (unsigned int)(host_addr - packet) - hdrLen - dataOffset);
                                totalLength = (unsigned int)(host_addr - packet);
                                convert_endian(fragmentHolder + 2, &totalLength, 2);
                            }
                            if (i != 1 || (i == 1 && host_len % sni_fragment_size > 0)) {
                                WinDivertHelperCalcChecksums(
                                fragmentHolder, totalLength, &addr, 0
                                );
                                WinDivertSend(
                                    w_filter, fragmentHolder,
                                    totalLength,
                                    NULL, &addr
                                );
                            }
                        }
                        if (compound_frag && do_reverse_frag) { //OK!
                            //Repair the packet.
                            memcpy(fragmentHolder, packetBACK, hdrLen + dataOffset);
                            memcpy(fragmentHolder + hdrLen + dataOffset, compound_fragHolder, https_fragment_size);
                            totalLength = hdrLen + dataOffset + https_fragment_size;
                            convert_endian(fragmentHolder + 2, &totalLength, 2);
                            WinDivertHelperCalcChecksums(
                                fragmentHolder, totalLength, &addr, 0
                            );
                            WinDivertSend(
                                w_filter, fragmentHolder,
                                totalLength,
                                NULL, &addr
                            );
                        }
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
                        //printf("Outgoing DNS request!\n");
                        //analyze_ip_header(packet);
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
                        //printf("Outgoing DNS request!\n");
                        //analyze_ip_header(packet);
                    }
                    if (drop_unsecure_dns && dns_is_dns_packet(packet_data, packet_dataLen, 1)) should_reinject = 0;
                    if (udp_fragments && should_reinject) {
                        #ifdef UDPDEBUG
                        printf("%s", "Got a UDP packet! Fragmenting it.\n");
                        #endif
                        if (send_native_fragments_udp(w_filter, packet, packetLen, packet_dataLen + 8, udp_fragments, addr)) {
                            should_reinject = 0;
                        }
                        #ifdef UDPDEBUG
                        else {
                            printf("I can't fragment this packet! Bummer.\n");
                        }
                        #endif
                    }
                }
            }
            if (should_reinject) {
                //printf("Re-injecting!\n");
                if (should_recalc_checksum) {
                    WinDivertHelperCalcChecksums(packet, packetLen, &addr, (UINT64)0LL);
                }
                WinDivertSend(w_filter, packet, packetLen, NULL, &addr);
            }
        }
        else {
            // error, ignore
            if (!exiting)
                printf("Error receiving packet!\n");
            break;
        }
    }
}
