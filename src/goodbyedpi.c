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
#include <time.h>
#define MAX_PACKET_SIZE 4096 //A bit more memory...
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

#define PTRTOUS(ptr) *((unsigned short*)((ptr)))
#define PTRTOUSCE(ptr) (unsigned short)(((*((unsigned short*)((ptr))) >> 8) & 0x00FF) + ((*((unsigned short*)((ptr))) << 8) & 0xFF00))
#define SETPTRTOUS(ptr, us) *((unsigned short*)((ptr))) = (us)
#define SETPTRTOUSCE(ptr, us) *((unsigned short*)((ptr))) = (((us) >> 8) & 0x00FF) + (((us) << 8) & 0xFF00)

#define PTRTOUI(ptr) *((unsigned int*)((ptr)))
#define PTRTOUICE(ptr) (unsigned int)(((*((unsigned int*)((ptr))) << 24) & 0xFF000000) + ((*((unsigned int*)((ptr))) << 8) & 0x00FF0000) + ((*((unsigned int*)((ptr))) >> 8) & 0x0000FF00) + ((*((unsigned int*)((ptr))) >> 24) & 0x000000FF))
#define SETPTRTOUI(ptr, ui) *((unsigned int*)((ptr))) = ui
#define SETPTRTOUICE(ptr, ui) *((unsigned int*)((ptr))) = (((ui) << 24) & 0xFF000000) + (((ui) << 8) & 0x00FF0000) + (((ui) >> 8) & 0x0000FF00) + (((ui) >> 24) & 0x000000FF)

#define PTRTOIP(ptr) ((unsigned char*)(ptr))[0], ((unsigned char*)(ptr))[1], ((unsigned char*)(ptr))[2], ((unsigned char*)(ptr))[3]

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
    {"ext-frag-size",required_argument,0,  '=' },
    {"vortex-frag", no_argument,       0,  '0' },
    {"vortex-frag-by-sni",no_argument, 0,  'V' },
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
    {"fakemap",     required_argument, 0,  'B' },
    {"illegal-segments",no_argument,   0,  ':' },
    {"wrong-flags", no_argument,       0,  'L' },
    {"fake-build",  required_argument, 0,  'F' }, //010100, 11226;0
    {"fake-randgen",required_argument, 0,  'Y' },
    {"fake-override",required_argument,0,  'X' },
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
unsigned short genrand16(unsigned short seed) {
    unsigned short shift;
    unsigned short num = seed; 
    for (unsigned int i = 0; i <= epoch; i++) {
        shift = (num & 0xFF) + (num >> 8 & 0xFF);
        if ((num & 1) == 0) num = (num >> (shift % 16 + 1)) + (num << (16 - (shift % 16 + 1)));
        else num = (num << (shift % 16 + 1)) + (num >> (16 - (shift % 16 + 1)));
        num += (num >> 4);
        num += (num * (num & 0xA) + ((num >> 6) & 0xB));
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
                   "sc stop windivert14\n"
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
    exit(0xC0000005u);
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
void charputter(char charr) {
    char charholder[2];
    charholder[1] = (char) 0;
    charholder[0] = charr;
    printf("%s", charholder);
}
void xprint(char* pchar, unsigned int size, unsigned int wrap) {
    for (unsigned int i = 0; i < size; i++) {
        if (wrap && i % wrap == 0) charputter('\n');
        if (pchar[i] > 31 && pchar[i] < 127) charputter(pchar[i]);
        else charputter('.');
    }
}
const char hex[16] = "0123456789ABCDEF";
void hexprint(unsigned char* pchar, unsigned int size) {
    char hexholder[3] = "00\0";
    for (unsigned int i = 0; i < size; i++) {
        hexholder[0] = hex[pchar[i] / 16];
        hexholder[1] = hex[pchar[i] % 16];
        printf("%s ", hexholder);
    }
    charputter('\n');
}
void analyze_ip_header(unsigned char* packet) {
    unsigned char hdrLen = packet[0] & 0xF;
    printf("Version: %d\nHeader length: %d (%d bytes)\nType of Service: %d\nTotal length: %d\nID: %d\nReserved bit: %d\nDon't Fragment: %d\nMore Fragments: %d\nFragment offset: %d\nTTL: %d\nProtocol: %d\nHeader checksum: %d\nSource IP: %d.%d.%d.%d\nDestination IP: %d.%d.%d.%d\n\n", 
        packet[0] >> 4, hdrLen, hdrLen * 4, packet[1], PTRTOUSCE(packet + 2), PTRTOUSCE(packet + 4), (packet[6] & 0b10000000) > 0, (packet[6] & 0b01000000) > 0, (packet[6] & 0b00100000) > 0, 
        PTRTOUSCE(packet + 6) & 0x1FFF, packet[8], packet[9], PTRTOUSCE(packet + 10), PTRTOIP(packet + 12), PTRTOIP(packet + 16));
}
void analyze_udp_header(unsigned char* packet) {
    unsigned char hdrLen = (packet[0] & 0xF) * 4;
    printf("Source port: %d\nDestination port: %d\nUDP Payload length: %d\nChecksum: %d\n\n", PTRTOUSCE(packet + hdrLen), PTRTOUSCE(packet + hdrLen + 2), PTRTOUSCE(packet + hdrLen + 4), PTRTOUSCE(packet + hdrLen + 6));
}
char empty[4] = "...\0";
void analyze_tcp_header(unsigned char* packet) {
    unsigned char hdrLen = (packet[0] & 0xF) * 4;
    printf("Flags: %s.%s.%s.%s.%s.%s.%s.%s\nSource port: %d\nDestination port: %d\nSequence number: %d\nAcknowledgement number: %d\nData offset: %d\nReserved: %d\nWindow: %d\nChecksum: %d\nUrgent pointer: %d\n\n", ((packet + hdrLen)[13] & 0x80) > 0 ? "CWR" : empty, ((packet + hdrLen)[13] & 0x40) > 0 ? "ECE" : empty, ((packet + hdrLen)[13] & 0x20) > 0 ? "URG" : empty, ((packet + hdrLen)[13] & 0x10) > 0 ? "ACK" : empty, ((packet + hdrLen)[13] & 0x8) > 0 ? "PSH" : empty, ((packet + hdrLen)[13] & 0x4) > 0 ? "RST" : empty, ((packet + hdrLen)[13] & 0x2) > 0 ? "SYN" : empty, ((packet + hdrLen)[13] & 0x1) > 0 ? "FIN" : empty,
        PTRTOUSCE(packet + hdrLen), PTRTOUSCE(packet + hdrLen + 2), PTRTOUSCE(packet + hdrLen + 4), PTRTOUSCE(packet + hdrLen + 8), (packet + hdrLen)[12] >> 4, 
        (packet + hdrLen)[12] & 0xF, PTRTOUSCE(packet + hdrLen + 14), PTRTOUSCE(packet + hdrLen + 16), PTRTOUSCE(packet + hdrLen + 18));
}
void analyze_tls_clienthello(unsigned char* packet) {
    unsigned short ciphersuitelen = 0, extlen = 0, analyze_extlen = 0, analyze_exttype = 0;
    unsigned char session_len = 0, compresslen = 0,
                  hdrLen = (packet[0] & 0b00001111) * 4,
                  dataOffset = ((packet + hdrLen)[12] >> 4) * 4;
    printf("Version: %d.%d\n", packet[hdrLen + dataOffset + 9] - 2, packet[hdrLen + dataOffset + 10] - 1);
    unsigned short totallength = PTRTOUSCE(packet + 2);
    unsigned short progress = 0;
    session_len = packet[hdrLen + dataOffset + 43];
    ciphersuitelen = PTRTOUSCE(packet + hdrLen + dataOffset + 44 + session_len);
    compresslen = packet[hdrLen + dataOffset + 46 + session_len + ciphersuitelen];
    extlen = PTRTOUSCE(packet + hdrLen + dataOffset + session_len + ciphersuitelen + compresslen + 47);
    progress = session_len + ciphersuitelen + compresslen + 49;
    //xprint(packet, totallength, 40);
    printf("Session Length: %u\nCipher Suite Length: %u\nCompression Method Length: %u\nExtensions Length: %u\n", session_len, ciphersuitelen, compresslen, extlen);
    printf("Extensions:\n");
    printf("%u, %d\n", progress, totallength - hdrLen - dataOffset);
    while (progress < totallength - hdrLen - dataOffset) {
        if (totallength - dataOffset - hdrLen - progress >= 4) {
            analyze_exttype = PTRTOUSCE(packet + dataOffset + hdrLen + progress);
            analyze_extlen = PTRTOUSCE(packet + dataOffset + hdrLen + progress + 2);
            printf("Type: %u, Length: %u%s\n", analyze_exttype, analyze_extlen, analyze_exttype == 65037 ? " [ECH DETECTED]" : (analyze_exttype == 1 ? "[MAX_FRAGMENT_LENGTH SPECIFIED]" : ""));
            if (analyze_exttype == 64768) {
                xprint(packet + dataOffset + hdrLen + progress + 4, analyze_extlen, 0);
                printf("\n");
            }
            if (analyze_exttype == 0) {
                xprint(packet + dataOffset + hdrLen + progress + 9, analyze_extlen - 5, 0);
                printf("\n");
            }
            progress += 4 + analyze_extlen;
        }
    }
    printf("\n");
}
void differentiate(unsigned char* compared, unsigned int comparedsize, unsigned char* compare, unsigned int comparesize, char showmatching) {
    if (comparedsize != comparesize) printf("Data size has a %u byte difference %s.\n", comparedsize < comparesize ? comparesize - comparedsize : comparedsize - comparesize, comparedsize < comparesize ? "to the right" : "to the left");
    unsigned int diffs = 0;
    for (unsigned int i = 0; i < comparedsize && i < comparesize; i++) {
        if (compared[i] != compare[i]) {
            printf("MISMATCH AT BYTE %u: ", i + 1);
            printf("%u %u\n", compared[i], compare[i]);
            diffs++;
        }
        else if (showmatching) {
            printf("BYTE %u: %u %u\n", i, compared[i], compare[i]);
        }
    }
    printf("\n\n Data has %u differences.\n", diffs);
}

const char chrome_useragent[16] = "Chrome/135.0.0.0";
unsigned char *reassemblePacket;
void bytestep(void *in, unsigned int size) {
    for (unsigned int i = 0; i < size; i++) {
        printf("%u\n", ((unsigned char*)in)[i]);
    }
}
void reassemble_segments(unsigned char* packet, unsigned char* reassembleOut, unsigned int baseSeq) {
    //Skip over to the whole reassembly part, assume packet is valid
    unsigned char hdrLen = (packet[0] & 0x0F) * 4,
                  dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    //We acquired enough information to start reassembling the data.
    memcpy(reassembleOut + (PTRTOUSCE(packet + hdrLen + 4) - baseSeq), packet + hdrLen + dataOffset, PTRTOUSCE(packet + 2) - hdrLen - dataOffset);
}
void reassemble_and_compare(unsigned char* packet, unsigned char* reassembleOut, unsigned int baseSeq, unsigned char* knowngood) {
    unsigned char flags = 0, /*1s bit on = Corrupted, 2s bit on = Overlapping */ 
    hdrLen = (packet[0] & 0x0F) * 4, dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    unsigned int tcpSeq = PTRTOUICE(packet + hdrLen + 4);
    unsigned short totalLength = PTRTOUSCE(packet + 2);
    #ifdef DEBUG
    printf("TRACE, OFFSET: %u, LEN: %u\n", tcpSeq - baseSeq, totalLength - hdrLen - dataOffset);
    #endif
    //We acquired enough information to start reassembling the data, but we gotta check it.
    for (unsigned short i = 0; i < totalLength - hdrLen - dataOffset; i++) {
        //printf("STEP: %u, %u, %u, %u\n", i, tcpSeq - baseSeq, tcpSeq, baseSeq);
        if (knowngood[i + (tcpSeq - baseSeq)] != packet[hdrLen + dataOffset + i]) flags = flags | 1;
        if (reassembleOut[i + (tcpSeq - baseSeq)] != 255) flags = flags | 2;
    }
    if (flags ^ 1) memcpy(reassembleOut + (tcpSeq - baseSeq), packet + hdrLen + dataOffset, totalLength - hdrLen - dataOffset);
    else printf("This segment is corrupted! Not writing.\n");
    if (flags & 2) printf("Overlap Detected\n");
}
unsigned short tls_reassembly_progress = 0;
unsigned char reassembleTls[65536];
unsigned char istlshandshake(unsigned char* packet_data) {
    if (packet_data[0] == 0x16 && packet_data[1] == 3 && packet_data[2] < 4 && packet_data[2] >= 1 && PTRTOUSCE(packet_data + 3) <= 16384) return TRUE;
    else return FALSE;
}
void reassemble_tls(unsigned char* packet) {
    unsigned char hdrLen = (packet[0] & 0x0F) * 4, 
                  dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    unsigned short totalLength = PTRTOUSCE(packet + 2);
    //This must be as strict as the destination.
    if (packet[hdrLen + dataOffset] != 0x16) {
        printf("REASSEMBLY ERROR: Not a handshake message. (%u)\n", packet[hdrLen + dataOffset]);
        return;
    }
    if (packet[hdrLen + dataOffset + 1] != 3 || packet[hdrLen + dataOffset + 2] > 4 || packet[hdrLen + dataOffset + 2] < 1) {
        printf("REASSEMBLY ERROR: Not a TLS 1.0 - 1.3 record. (%u)\n", packet[hdrLen + dataOffset]);
        return;
    }
    unsigned short tls_recordLen = PTRTOUSCE(packet + hdrLen + dataOffset + 3);
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
    unsigned short tls_recordLen = PTRTOUSCE(record + 3);
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
    unsigned char sessionidlen;
    unsigned char compressionmethodslen;
    unsigned char random[32];
    unsigned short ciphersuiteslen;
    unsigned short extensionCount;
    unsigned short version;
    unsigned char* sessionid;
    unsigned short* ciphersuites;
    unsigned char* compressionmethods;
    struct extension* extensions;
};
int parse_clienthello(unsigned char* packet, struct clienthello* clienthello) {
    unsigned short progress = 5,
                   totalLength = PTRTOUSCE(packet + 2),
                   step = 0;
    unsigned char hdrLen = (packet[0] & 0x0F) * 4,
                  dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    if (PTRTOUSCE(packet + hdrLen + dataOffset + 3) + 5 > totalLength - hdrLen - dataOffset) {
        printf("ERROR: Incomplete packet.\n");
        return 0;
    }
    clienthello->length = ntohl(PTRTOUI(packet + hdrLen + dataOffset + progress) & 0xFFFFFF00);
    progress += 4;
    clienthello->version = PTRTOUSCE(packet + hdrLen + dataOffset + progress);
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
    clienthello->ciphersuiteslen = ntohs(PTRTOUS(packet + hdrLen + dataOffset + progress));
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
        progress += ntohs(PTRTOUS(packet + hdrLen + dataOffset + progress)) + 2;
        clienthello->extensionCount++;
    }
    clienthello->extensions = calloc(clienthello->extensionCount, sizeof(struct extension));
    progress = progressbackup;
    while (progress < totalLength - hdrLen - dataOffset) { //NOW we can get to work.
        clienthello->extensions[step].type = ntohs(PTRTOUS(packet + hdrLen + dataOffset + progress));
        progress += 2;
        clienthello->extensions[step].length = ntohs(PTRTOUS(packet + hdrLen + dataOffset + progress)); 
        progress += 2;
        if (clienthello->extensions[step].type != 21) {
            clienthello->extensions[step].data = malloc(clienthello->extensions[step].length);
            memcpy(clienthello->extensions[step].data, packet + hdrLen + dataOffset + progress, clienthello->extensions[step].length);
        }
        else clienthello->extensions[step].data = NULL;
        progress += clienthello->extensions[step++].length;
    }
    return 1;
}
unsigned short rebuild_clienthello(struct clienthello* clienthello, unsigned char* destPacketPayload) { //Builds a handshake record that contains a ClientHello out of that struct.
    SETPTRTOUI(destPacketPayload, 0x00010316);
    unsigned short progress = 9;
    SETPTRTOUSCE(destPacketPayload + progress, clienthello->version);
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
    SETPTRTOUSCE(destPacketPayload + progress, clienthello->ciphersuiteslen);
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
        SETPTRTOUSCE(destPacketPayload + progress, clienthello->extensions[i].type);
        progress += 2;
        SETPTRTOUSCE(destPacketPayload + progress, clienthello->extensions[i].length);
        progress += 2;
        if (clienthello->extensions[i].type != 21)
            memcpy(destPacketPayload + progress, clienthello->extensions[i].data, clienthello->extensions[i].length);
        else 
            for (unsigned short x = 0; x < clienthello->extensions[i].length; x++) destPacketPayload[progress + x] = 0;
        progress += clienthello->extensions[i].length;
        extensionsLen += 4 + clienthello->extensions[i].length;
    }
    unsigned short length = progress - 5;
    SETPTRTOUSCE(destPacketPayload + 3, length);
    SETPTRTOUSCE(destPacketPayload + 5, (length - 4) | 0x01000000);
    progress = progressbackup;
    SETPTRTOUSCE(destPacketPayload + progress, extensionsLen);
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
//Reduced to a macro. What a glowdown.
#ifndef SIGNATURE
    #define NEWPACKETID(packet) SETPTRTOUSCE(packet + 4, genrand16(PTRTOUSCE(packet + 4)))
#else
    #define NEWPACKETID(packet) SETPTRTOUSCE(packet + 4, 12345)
#endif
struct connection {
    unsigned int ip;
    unsigned int seq;
    unsigned short mss;
    unsigned short life;
    unsigned char taken;
};
struct fragmentInfoChunk {
    unsigned int seq;
    uint16_t payloadLen;
};
struct fragmentInfo {
    unsigned short length;
    unsigned short beginSni;
    unsigned short endSni;
    struct fragmentInfoChunk fragments[MAX_PACKET_SIZE - 40];
};
struct conntracksig {
    WINDIVERT_ADDRESS addr;
    int offset;
    unsigned int ip;
    unsigned int upperseq; //SEQ upper bound
    unsigned int lowerseq; //SEQ lower bound
    unsigned int originseq;
    unsigned int nextseq;
    unsigned int wrapoffset; //Offset between the SEQ of the last unwrapped packet and 0xFFFFFFFF
    unsigned short clientport;
    unsigned short nextpacketid;
    unsigned short mss;
    unsigned char flags; //0b100 = busy; 0b10 = outbound fin sent; 1 = inbound fin sent;
    unsigned char retransmits;
    char associatedsni[256];
};
struct fatasssig {
    unsigned int ip;
    unsigned int seq;
    unsigned int originseq;
    unsigned short recordlength;
    unsigned short expectedlength;
    unsigned short life;
    unsigned char iphdrlen;
    unsigned char dOffset;
    unsigned char packet[4216];
};
struct superReverseParams {
    unsigned short vortex_step_left;
    unsigned short vortex_step_right;
    unsigned short https_fragment_size;
    unsigned short tls_recseg_size; //Damn it.
    unsigned char flags;
};
struct fakebuild {
    unsigned char mode; //Functions identically to fakemode, except 0 is 1 and so on, since real 0 makes no sense.
    unsigned char type; //0 = Packet filled with zeroes; 1 = Fake with fakemap SNI
    unsigned char fragmentation; //0 = No fragmentation; 1 = Absolute Fragmentation; 2 = Random Fragmentation
    unsigned char disorder; //0 = Native; 1 = Reverse; 2 = RPLRR
    unsigned char ttl; //0 = Unchanged TTL; >0 = Set TTL
    unsigned char chksum; //0 = OK Checksums; 1 = Bad TCP Checksum;
};
unsigned char overriden = 0;
struct fakebuild *fakebuilds[4],
                  fboverrides;
struct fatasssig* fatass = NULL;
struct conntracksig* conntrack;
struct connection* connections;
unsigned int fakebuildlen[4] = {0,0,0,0};
unsigned short fatasslen = 0,
               connectionslen = 0;
void add_fragment(unsigned char* packet, struct fragmentInfo* fragmentInfo) {
    //Skip over to the whole- yeah, this is just copied code from reassemble_segments
    unsigned char hdrLen = (packet[0] & 0x0F) * 4,
                  dataOffset = (packet[hdrLen + 12] >> 4) * 4;
    fragmentInfo->fragments[fragmentInfo->length].seq = PTRTOUICE(packet + hdrLen + 4);
    fragmentInfo->fragments[fragmentInfo->length].payloadLen = PTRTOUSCE(packet + 2) - hdrLen - dataOffset;
    fragmentInfo->length++;
}
struct fragmentationParams {
    unsigned char mode; //0 = No fragmentation other than to the SNI! (IF THERE EVEN IS ONE!); 1 = Absolute fragmentation; 2 = Random Fragmentation; 3 = Smart fragmentation;
    unsigned char write_fragments; //To support super reverse fragmentation.
    unsigned char allow_sni_overlap;
    unsigned char cleave_sni;
    unsigned short sni_fragment_size;
    unsigned short tls_absolute_frag_size;
    unsigned short ext_frag_size;
    unsigned short compound_frag; // >0 = Compound fragmentation enabled.
};
char host_addrBACK[HOST_MAXLEN];
unsigned short host_lenBACK;
void do_fragmentation(HANDLE filter, WINDIVERT_ADDRESS* pAddr, struct fragmentInfo* fragmentInfo, unsigned int tcpBaseSeq, unsigned char* packet, unsigned short packetLen,
    unsigned char* host_addr, unsigned short host_len, struct fragmentationParams* params, unsigned short* pprogress) {
    //printf("initializing fragmenter\n");
    unsigned short progress = 0, current_fragment_size = 0, totalLength = 0, target_fragment_size = (params->tls_absolute_frag_size > 0 && params->mode == 1) ? params->tls_absolute_frag_size : 0,
                   sni_fragment_size = params->sni_fragment_size, ext_frag_size = params->ext_frag_size, ciphersuitelen = 0, compound_frag = params->compound_frag, extensionLen = 0, extensionType = 0;
    unsigned char super_reverse = (params->write_fragments && fragmentInfo != NULL), fragmentHolder[65535], hdrLen = (packet[0] & 0x0F) * 4, dataOffset = (packet[hdrLen + 12] >> 4) * 4,
                  sni_ok = (host_len != 0 && host_addr != NULL), fragging_sni = 0, allow_sni_overlap = params->allow_sni_overlap, cleave_sni = params->cleave_sni,
                  session_len = 0, compresslen = 0;
    //printf("initialized variables\n");
    if (params->tls_absolute_frag_size == 0 && params->mode == 0) {
        unsigned short mss = 1200;
        for (unsigned short i = 0; i < connectionslen; i++)
            if (connections[i].taken && connections[i].ip == PTRTOUI(packet + 16))
                if (connections[i].seq == PTRTOUICE(packet + hdrLen + 4)) {
                    if (connections[i].mss != 0) mss = connections[i].mss;
                    else printf("BAD MSS ASSOCIATED WITH CONNECTION %u\n", i);
                    connections[i].taken = 0;
                    break;
                }
        if (mss == 1200) printf("ERROR: CONNECTION TRACKING FAIL\n");
        target_fragment_size = mss;
    }
    else if (params->tls_absolute_frag_size == 0 && params->mode == 1) target_fragment_size = 500; //Failsafe.
    if (tcpBaseSeq == 0) tcpBaseSeq = PTRTOUICE(packet + hdrLen + 4);
    if (pprogress != NULL) progress = *pprogress;
    //printf("initialization complete, building fragments\n");
    memcpy(fragmentHolder, packet, hdrLen + dataOffset);
    //printf("headers ready\n");
    if (compound_frag) {
        memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, compound_frag);
        totalLength = hdrLen + dataOffset + compound_frag;
        SETPTRTOUSCE(fragmentHolder + 2, totalLength);
        SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
        NEWPACKETID(fragmentHolder);
        WinDivertHelperCalcChecksums(
            fragmentHolder, totalLength, pAddr, 0
        );
        if (!super_reverse)
            WinDivertSend(
                filter, fragmentHolder,
                totalLength,
                NULL, pAddr
            );
        else
            add_fragment(fragmentHolder, fragmentInfo);
        progress += compound_frag;
    }
    //printf("processed compound fragmentation\n");
    if (sni_ok) {
        session_len = packet[hdrLen + dataOffset + 43], compresslen = packet[hdrLen + dataOffset + 46 + session_len + ciphersuitelen];
        ciphersuitelen = PTRTOUSCE(packet + hdrLen + dataOffset + 44 + session_len);
    }
    if ((!sni_ok || progress > 12) && params->mode == 3) params->mode = 0;
    //printf("processed SNI\n");
    switch (params->mode) {
        case 3: //This is gonna zuck.
            while (progress < 12) { //Improved interoperability.
                current_fragment_size = 2;
                if (progress + current_fragment_size >= 12) { //Uh oh.
                    current_fragment_size = 12 - progress;
                    if (current_fragment_size == 0) break;
                }
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                totalLength = hdrLen + dataOffset + 2;
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                else add_fragment(fragmentHolder, fragmentInfo);
            }
            //Send the rest of the client random and Session ID, as those values are not identifiable as a TLS ClientHello. [And the client random was chipped by the other fragmenter.]
            //And then the first byte of the cipher suites.
            for (unsigned char i = 0; i < 2; i++) {
                if (!i) current_fragment_size = 32 + session_len;
                else current_fragment_size = 1;
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                totalLength = hdrLen + dataOffset + current_fragment_size;
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                    WinDivertSend(
                        filter, fragmentHolder,
                        totalLength,
                        NULL, pAddr
                    );
                else add_fragment(fragmentHolder, fragmentInfo);
                progress += current_fragment_size;
            }
            //And now send the rest of it, and put the extensions length as a bonus.
            unsigned short term = progress + ciphersuitelen + 4;
            while (progress < term) {
                current_fragment_size = 2;
                if (progress + current_fragment_size >= term) { //Uh oh.
                    current_fragment_size = term - progress;
                    if (current_fragment_size == 0) break;
                }
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                else add_fragment(fragmentHolder, fragmentInfo);
                progress += current_fragment_size;
            }
            while (progress < packetLen - dataOffset - hdrLen) {
                //Before doing anything, acquire the length of the extension we're working on, and what extension it is. [If the remaining payload is 4 or more bytes long.]
                if (packetLen - dataOffset - hdrLen - progress >= 4) {
                    extensionType = PTRTOUSCE(packet + dataOffset + hdrLen + progress);
                    extensionLen = PTRTOUSCE(packet + dataOffset + hdrLen + progress + 2);
                }
                //Send the first byte of the extension information.
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, 1);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                totalLength = hdrLen + dataOffset + 1;
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                else add_fragment(fragmentHolder, fragmentInfo);
                progress++;
                //Send the second and third byte.
                if (packetLen - dataOffset - hdrLen - progress == 1) { //Ran out of payload data, Exit.
                    fragmentHolder[hdrLen + dataOffset] = packet[hdrLen + dataOffset + progress];
                    SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                    totalLength = hdrLen + dataOffset + 1;
                    SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                    NEWPACKETID(fragmentHolder);
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, pAddr, 0
                    );
                    if (!super_reverse)
                    WinDivertSend(
                        filter, fragmentHolder,
                        totalLength,
                        NULL, pAddr
                    );
                    else add_fragment(fragmentHolder, fragmentInfo);
                    progress++;
                    if (!super_reverse) continue;
                    else break;
                }
                else if (packetLen - dataOffset - hdrLen - progress == 0) {
                    if (!super_reverse) continue;
                    else break;
                }
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, 2);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                totalLength = hdrLen + dataOffset + 2;
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                else add_fragment(fragmentHolder, fragmentInfo);
                progress += 2;
                //Send the last byte of extension information.
                if (packetLen - dataOffset - hdrLen - progress == 0) {
                    if (!super_reverse) continue;
                    else break;
                }
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, 1);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                totalLength = hdrLen + dataOffset + 1;
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                else add_fragment(fragmentHolder, fragmentInfo);
                progress++;
                if (packetLen - dataOffset - hdrLen - progress == 0) { 
                    if (!super_reverse) continue;
                    else break;
                }
                //Set the extension's length to the size of the remaining payload if its larger than the remaining payload.
                if (extensionLen > packetLen - dataOffset - hdrLen - progress)
                    extensionLen = packetLen - dataOffset - hdrLen - progress;
                //If the extension is the SNI, use SNI fragment size.
                current_fragment_size = extensionType != 0 ? ext_frag_size : sni_fragment_size;
                while (extensionLen != 0) {
                    if (current_fragment_size > extensionLen) current_fragment_size = extensionLen;
                    memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                    totalLength = hdrLen + dataOffset + current_fragment_size;
                    SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                    SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                    NEWPACKETID(fragmentHolder);
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, pAddr, 0
                    );
                    if (!super_reverse)
                    WinDivertSend(
                        filter, fragmentHolder,
                        totalLength,
                        NULL, pAddr
                    );
                    else add_fragment(fragmentHolder, fragmentInfo);
                    extensionLen -= current_fragment_size;
                    progress += current_fragment_size;
                }
            }
            break;
        case 2: //This could've been a ternary extension in absolute fragmentation... But that was getting really long.
            while (progress != packetLen - hdrLen - dataOffset) {
                current_fragment_size = !fragging_sni ? genrand4(packetLen) : (sni_fragment_size || cleave_sni) ? (cleave_sni ? host_len / 2 : sni_fragment_size) : genrand2(packetLen);
                if (!fragging_sni && current_fragment_size == 0) continue;
                if (sni_ok && !fragging_sni && !(packet + hdrLen + dataOffset + progress >= host_addr + host_len) && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr) { //Dangerously close to SNI, fragment right before it
                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr - packet - dataOffset - hdrLen - progress);
                    fragging_sni = 1;
                    if (super_reverse) {
                        fragmentInfo->beginSni = fragmentInfo->length + !allow_sni_overlap; //What?
                        if (current_fragment_size == 0) {
                            fragmentInfo->beginSni--;
                            continue;
                        }
                    }
                }
                if (sni_ok && fragging_sni && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr + host_len) { //Exitting SNI, fragment until the end of the SNI.
                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr + host_len - packet - hdrLen - dataOffset - progress);
                    fragging_sni = 0;
                    if (super_reverse) fragmentInfo->endSni = fragmentInfo->length;
                    if (current_fragment_size == 0) continue;
                }
                if (hdrLen + dataOffset + progress + current_fragment_size >= packetLen) { //Uh oh.
                    current_fragment_size = packetLen - hdrLen - dataOffset - progress;
                    if (current_fragment_size == 0) break;
                }
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                totalLength = hdrLen + dataOffset + current_fragment_size;
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                else add_fragment(fragmentHolder, fragmentInfo);
                progress += current_fragment_size;
            }
            break;
        default: //And the default is... ABSOLUTE FRAGMENTATION!
            while (progress != packetLen - hdrLen - dataOffset) {
                //printf("AF progress: %u\n", progress);
                current_fragment_size = !fragging_sni ? target_fragment_size : cleave_sni ? host_len / 2 : sni_fragment_size;
                //printf("TFS: %u\n", target_fragment_size);
                //printf("CFS: %u\n", current_fragment_size);
                if (sni_ok && !fragging_sni && !(packet + hdrLen + dataOffset + progress >= host_addr + host_len) && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr) { //Dangerously close to SNI, fragment right before it
                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr - packet - dataOffset - hdrLen - progress);
                    fragging_sni = 1;
                    if (super_reverse) {
                        fragmentInfo->beginSni = fragmentInfo->length + !allow_sni_overlap; //What?
                        if (current_fragment_size == 0) {
                            fragmentInfo->beginSni--;
                            continue;
                        }
                    }
                }
                if (sni_ok && fragging_sni && packet + hdrLen + dataOffset + progress + current_fragment_size >= host_addr + host_len) { //Exitting SNI, fragment until the end of the SNI.
                    if (!allow_sni_overlap) current_fragment_size = (unsigned int) (host_addr + host_len - packet - hdrLen - dataOffset - progress);
                    fragging_sni = 0;
                    fragmentInfo->endSni = fragmentInfo->length;
                    if (current_fragment_size == 0) continue;
                }
                if (hdrLen + dataOffset + progress + current_fragment_size >= packetLen) { //Uh oh.
                    current_fragment_size = packetLen - hdrLen - dataOffset - progress;
                    if (current_fragment_size == 0) break;
                }
                memcpy(fragmentHolder + hdrLen + dataOffset, packet + hdrLen + dataOffset + progress, current_fragment_size);
                totalLength = hdrLen + dataOffset + current_fragment_size;
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpBaseSeq + progress);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                if (!super_reverse)
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                else add_fragment(fragmentHolder, fragmentInfo);
                progress += current_fragment_size;
            }
            //printf("FINISHING WITH %u BYTES PROCESSED\n", progress);
            break;
    }
    //printf("fragmentation over.\n");
    if (pprogress != NULL) *pprogress = progress;
    //printf("returning\n");
}
#define SAFE_SEND(filter, pAddr, packet, packetLen, mss)\
    struct fragmentationParams sparams = {1};\
    sparams.tls_absolute_frag_size = mss;\
    do_fragmentation(filter, pAddr, NULL, 0, packet, packetLen, NULL, 0, &sparams, NULL);

void xorinate(char* victim, unsigned int victimLen, char* key, unsigned int keyLen) 
{
    for (unsigned int vicPtr = 0; vicPtr < victimLen; vicPtr++) { //Very clever!
        victim[vicPtr] = victim[vicPtr] ^ key[vicPtr % keyLen];
    }
}
//Meet the thrash machine!
unsigned int udp_fakes = 0;
void* thrash(void* something) {
    unsigned char packet[65536],
                  fake[65536];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;
    thrash_filter = WinDivertOpen("outbound and udp and !impostor and !loopback and udp.DstPort > 49999 and udp.DstPort < 50100\0", WINDIVERT_LAYER_NETWORK, 1, 0);
    if (thrash_filter != INVALID_HANDLE_VALUE)
    while (!exiting) {
        if (WinDivertRecv(thrash_filter, packet, 65536, &packetLen, &addr)) {
		    WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
            memcpy(fake, packet, packetLen);
            //Encapsulate in trash
            xorinate(fake + 28, 20 % (packetLen - 28), "TOOTROLLED", 10);
		    WinDivertHelperCalcChecksums(fake, packetLen, &addr, 0);
            for (unsigned int i = 0; i < (udp_fakes / 2 + udp_fakes % 2); i++) {
                WinDivertSend(thrash_filter, fake, packetLen, NULL, &addr);
            }
            WinDivertSend(thrash_filter, packet, packetLen, NULL, &addr);
            for (unsigned int i = 0; i < (udp_fakes / 2); i++) {
                WinDivertSend(thrash_filter, fake, packetLen, NULL, &addr);
            }
        }
    }
    else printf("thrash init error %u\n", GetLastError());
}
//'tis hardcoded.
#ifndef DOLOCALNETS
char synner_filter_str_default[] = "!impostor && !loopback && tcp.Syn && ((outbound && tcp.DstPort == 443) || (inbound && tcp.Ack && tcp.SrcPort == 443))\0",
     synner_filter_str_discord_vc[] = "!impostor && !loopback && tcp.Syn && ((outbound && (tcp.DstPort == 443 || (tcp.DstPort > 1999 && tcp.DstPort < 2100))) || (inbound && tcp.Ack && (tcp.SrcPort == 443 || (tcp.SrcPort > 1999 && tcp.SrcPort < 2100))))\0",
#else
char synner_filter_str_default[] = "!impostor && tcp.Syn && ((outbound && tcp.DstPort == 443) || (inbound && tcp.Ack && tcp.SrcPort == 443))\0",
     synner_filter_str_discord_vc[] = "!impostor && tcp.Syn && ((outbound && (tcp.DstPort == 443 || (tcp.DstPort > 1999 && tcp.DstPort < 2100))) || (inbound && tcp.Ack && (tcp.SrcPort == 443 || (tcp.SrcPort > 1999 && tcp.SrcPort < 2100))))\0",
#endif
    *synner_filter_str = synner_filter_str_default, disable_sack = 0; 
void* synner(void* something) { //For accessing SYN packets without the clutter of main()
    WINDIVERT_ADDRESS addr;
    unsigned char packet[256], //SYN packets cannot possibly be any larger than this.
                  hdrLen = 0, dataOffset = 0;
    unsigned short findmss = 0, mss = 1200, pmss = 0;
    int freeWaiting;
    unsigned int packetLen;
    synner_filter = WinDivertOpen(synner_filter_str, WINDIVERT_LAYER_NETWORK, 2, 0);
    if (synner_filter != INVALID_HANDLE_VALUE)
    while (!exiting) {
        if (WinDivertRecv(synner_filter, packet, 256, &packetLen, &addr)) {
            hdrLen = (packet[0] & 0xF) * 4;
            dataOffset = (packet[hdrLen + 12] >> 4) * 4;
            freeWaiting = -1;
            if (!addr.Outbound) {
                for (int i = 0; i < connectionslen; i++) {
                    if (!connections[i].taken && freeWaiting == -1) {
                        freeWaiting = i;
                    }
                    else if (connections[i].taken) {
                        connections[i].life += 1;
                        if (connections[i].life > 256) connections[i].taken = 0;
                    }
                }
                if (freeWaiting == -1 && connectionslen == 512) {
                    printf("FATAL SYNNING ERROR\n");
                    break;
                }
                else if (freeWaiting == -1) {
                    freeWaiting = connectionslen++;
                }
                if (freeWaiting != -1) {
                    connections[freeWaiting].ip = *((unsigned int*)(packet + 12));
                    connections[freeWaiting].seq = PTRTOUICE(packet + hdrLen + 8);
                }
            }
            findmss = 0;
            //Locate the MSS option.
            for (unsigned short i = 0; i < dataOffset; i += packet[hdrLen + i] > 1 ? packet[hdrLen + i + 1] : 1) { //Actually cramming logic in there. Amazing.
                if (packet[hdrLen + i] == 2) {
                    findmss = i + 2;
                    break;
                }
            }
            if (findmss != 0) {
                pmss = PTRTOUSCE(packet + hdrLen + findmss);
                if (mss > 0) {
                    if (pmss > mss && addr.Outbound) { //Now not stupid!
                        SETPTRTOUSCE(packet + hdrLen + findmss, mss);
                    }
                }
                if (!addr.Outbound) {
                    connections[freeWaiting].mss = pmss;
                    printf("Associating connection %d with SEQ %u with IP %u.%u.%u.%u to MSS %u\n", freeWaiting, connections[freeWaiting].seq, PTRTOIP(&(connections[freeWaiting].ip)), pmss);
                }
            }
            if (disable_sack && addr.Outbound) { //Remove SACK_PERM.
                for (unsigned char i = hdrLen; i < dataOffset; i += packet[hdrLen + i] > 1 ? packet[hdrLen + i + 1] : 1) { //Actually cramming logic in there. Amazing.
                    if (packet[hdrLen + i] == 4) {
                        packet[hdrLen + i] = 1; //Replace Option-Kind with NOP.
                        packet[hdrLen + i + 1] = 1; //Replace Option-Length with NOP.
                    }
                }
            }
            WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
            WinDivertSend(synner_filter, packet, packetLen, NULL, &addr);
            if (!addr.Outbound) connections[freeWaiting].taken = 1;
        }
        else if (!exiting) {
            printf("synning error: %u\n", GetLastError());
            break;
        }
    }
    else printf("synner init error %u\n", GetLastError());
}
//'tis hardcoded.
#ifndef DOLOCALNETS
char conntrack_filter_str_default[] = "!tcp.Syn && !impostor and !loopback and ((inbound and tcp.SrcPort == 443 and tcp.Ack) or (outbound and tcp.DstPort == 443))\0",
     conntrack_filter_str_discord_vc[] = "!tcp.Syn && !impostor and !loopback and ((inbound and tcp.SrcPort == 443) or (outbound and tcp.DstPort == 443) or (outbound and tcp.DstPort > 1999 and tcp.DstPort < 2100))\0",
#else
char conntrack_filter_str_default[] = "!tcp.Syn && !impostor and (((inbound or loopback) and tcp.SrcPort == 443 and tcp.Ack) or (outbound and tcp.DstPort == 443))\0",
     conntrack_filter_str_discord_vc[] = "!tcp.Syn && !impostor and (((inbound or loopback) and tcp.SrcPort == 443) or (outbound and tcp.DstPort == 443) or (outbound and tcp.DstPort > 1999 and tcp.DstPort < 2100))\0",
#endif
     *conntrack_filter_str = conntrack_filter_str_default;
unsigned int conntrack_maxlen = 0, conntrack_curlen = 0; 
void* do_conntrack(void* something) {
    WINDIVERT_ADDRESS addr;
    unsigned int seq, nseq, ip, packetLen;
    unsigned short clientport = 0;
    unsigned char packet[65536], should_reinject = 0, hdrLen = 0, dataOffset = 0, final_ack = 0, outbound = 0;
    conntrack_filter = WinDivertOpen(conntrack_filter_str, WINDIVERT_LAYER_NETWORK, 2, 0);
    struct fragmentationParams ctparams = {.mode = 0, .compound_frag = 2};
    if (conntrack_filter != INVALID_HANDLE_VALUE)
    while (!exiting) {
        if (WinDivertRecv(conntrack_filter, packet, 65536, &packetLen, &addr)) {
            final_ack = 0;
            should_reinject = 1;
            hdrLen = (packet[0] & 0xF) * 4;
            dataOffset = (packet[hdrLen + 12] >> 4) * 4;
            packetLen = PTRTOUSCE(packet + 2);
            outbound = addr.Outbound && PTRTOUSCE(packet + hdrLen) != 443;
            ip = PTRTOUI((outbound ? packet + 16 : packet + 12));
            seq = PTRTOUICE((outbound ? packet + hdrLen + 4 : packet + hdrLen + 8));
            clientport = PTRTOUSCE((outbound ? packet + hdrLen : packet + hdrLen + 2));
            for (unsigned int i = 0; i < conntrack_curlen; i++) {
                if ((conntrack[i].flags & 4) == 0 && conntrack[i].ip == ip && ((outbound ? seq : seq - conntrack[i].offset) >= conntrack[i].lowerseq && (outbound ? seq : seq - conntrack[i].offset) <= conntrack[i].upperseq)) {
                    if (*(packet + hdrLen + 13) & 0b00000001) {
                        if (outbound) {
                            printf("OUTBOUND FIN\n");
                            conntrack[i].flags = conntrack[i].flags | 2;
                        }
                        else {
                            printf("INBOUND FIN\n");
                            conntrack[i].flags = conntrack[i].flags | 1;
                        }
                    }
                    if ((conntrack[i].flags & 3) == 3 && (*(packet + hdrLen + 13) & 0b00010000) > 0) {
                        printf("FINALIZING\n");
                        final_ack = 1;
                        SETPTRTOUICE(packet + hdrLen + 8, seq - conntrack[i].offset);
                    }
                    if (outbound) {
                        //*((unsigned short*)(packet + 4)) = htons(conntrack[i].nextpacketid++);
                        NEWPACKETID(packet);
                        if (seq == conntrack[i].upperseq) {
                            SETPTRTOUICE(packet + hdrLen + 4, conntrack[i].nextseq);
                            if (0xFFFFFFFFu - conntrack[i].nextseq + 1 <= (packetLen - hdrLen - dataOffset)) {
                                printf("NOTE: ATTEMPTING WRAPAROUND FOR %s\n", conntrack[i].associatedsni);
                                conntrack[i].nextseq = 0;
                                conntrack[i].wrapoffset = 0xFFFFFFFFu - seq;
                            }
                            else conntrack[i].nextseq += (packetLen - hdrLen - dataOffset);
                            if ((0xFFFFFFFFu - conntrack[i].upperseq + 1) <= (packetLen - hdrLen - dataOffset)) {
                                printf("%s WRAPPING AROUND\n", conntrack[i].associatedsni);
                                conntrack[i].lowerseq = 0;
                                conntrack[i].upperseq = 0;
                            }
                            else conntrack[i].upperseq += (packetLen - hdrLen - dataOffset);
                            conntrack[i].retransmits = 0;
                        }
                        else if (seq + (packetLen - hdrLen - dataOffset) > conntrack[i].upperseq) {
                            nseq = conntrack[i].offset < (0xFFFFFFFF - seq + 1) ? seq + conntrack[i].offset : 0;
                            SETPTRTOUICE(packet + hdrLen + 4, nseq);
                            conntrack[i].upperseq = seq + (packetLen - hdrLen - dataOffset);
                        }
                        else {
                            nseq = conntrack[i].offset < (0xFFFFFFFF - seq + 1) ? seq + conntrack[i].offset : 0;
                            SETPTRTOUICE(packet + hdrLen + 4, nseq);
                            /*
                            switch (conntrack[i].retransmits++) {
                                case 0:
                                    do_fragmentation(conntrack_filter, &addr, NULL, 0, packet, packetLen, NULL, 0, &ctparams, NULL);
                                    should_reinject = 0;
                                    break;
                                default:
                                    SETPTRTOUSCE(packet + 4, 12345);
                                    SETPTRTOUICE(packet + hdrLen + 4, seq - 200);
                                    SETPTRTOUICE(packet + hdrLen + 8, PTRTOUICE(packet + hdrLen + 8) + 200);
                            }
                            */
                        }
                    }
                    else {
                        SETPTRTOUICE(packet + hdrLen + 8, seq < conntrack[i].offset ? 0xFFFFFFFF - (conntrack[i].wrapoffset - seq) : seq - conntrack[i].offset);
                    }
                    if (final_ack || ((*(packet + hdrLen + 13) & 0b00000100) > 0)) {
                        conntrack[i].flags = 0; conntrack[i].ip = 0; conntrack[i].lowerseq = 0; 
                        conntrack[i].upperseq = 0; conntrack[i].offset = 0; conntrack[i].originseq = 0; 
                        conntrack[i].nextpacketid = 0; conntrack[i].retransmits = 0;
                    }
                    break;
                }
                else if (conntrack[i].ip == ip) {
                    if (clientport == conntrack[i].clientport && (packet[hdrLen + 13] & 0b00000100) > 0) {
                        printf("CONNTRACK ERROR (%s, %s, %s: %u)\n",conntrack[i].associatedsni, addr.Outbound ? "OUTBOUND" : "INBOUND", addr.Outbound ? "SEQ" : "ACK", seq);
                        conntrack[i].flags = 0; conntrack[i].ip = 0; conntrack[i].lowerseq = 0; 
                        conntrack[i].upperseq = 0; conntrack[i].offset = 0; conntrack[i].originseq = 0; 
                        conntrack[i].nextpacketid = 0; conntrack[i].retransmits = 0;
                    }
                    else {
                        if (outbound && seq > conntrack[i].upperseq && seq - conntrack[i].upperseq < 600) printf("proximity alert, this likely means a missed packet and conntrack is failing. (%s)\n", (addr.Outbound && PTRTOUSCE(packet + hdrLen) != 443) ? "Outbound" : "Inbound");
                        if (seq < conntrack[i].lowerseq && seq >= conntrack[i].originseq) should_reinject = 0;
                    }
                }
            }
            WinDivertHelperCalcChecksums(packet, packetLen, &addr, 0);
            if (should_reinject) {
                WinDivertSend(conntrack_filter, packet, packetLen, NULL, &addr);
            }
        }
        else {
            printf("conntrack receive error %u\n", GetLastError());
            break;
        }
    }
    else printf("conntrack init error %u\n", GetLastError());
}

void do_super_reverse_frag(HANDLE filter, WINDIVERT_ADDRESS *pAddr, struct superReverseParams* params, struct fragmentInfo* fragmentInfo, unsigned char* host_addr, unsigned int host_len, unsigned char* srcPacket, unsigned int srcPacketLen, unsigned int tcpBaseSeq, unsigned short baseid, unsigned char* fakepacket, unsigned short fakepacketlen) {
    unsigned int tcpSeq = 0, fakePacketLen = 0, progress = 0;
    unsigned char hdrLen = (srcPacket[0] & 0b00001111) * 4,
                  dataOffset = (srcPacket[hdrLen + 12] >> 4) * 4,
                  fragmentHolder[MAX_PACKET_SIZE], recordbufferpacket[65535], *recordbuffer, fakePacket[65535], fakehost[256],
                  tls_force_native = 0, rplrr_by_sni = 0,
                  vortex_frag = 0, vortex_frag_by_sni = 0, rplrr = 0,
                  record_frag = 0, mode = 0;
    unsigned short totalLength, vortex_left, vortex_right, vortex_step, vortex_direction, vortex_relevant, mss = 1200, fragmentInfoLen = fragmentInfo->length,
                   vortex_step_left = 0, vortex_step_right = 0, https_fragment_size = 0,
                   beginSni = fragmentInfo->beginSni, endSni = fragmentInfo->endSni;
    struct fragmentInfoChunk* fragments = fragmentInfo->fragments;
    if (params != NULL) {
        tls_force_native = (params->flags & 0b100000) > 0; rplrr_by_sni = (params->flags & 0b10000) > 0;
        vortex_frag = (params->flags & 0b1000) > 0; vortex_frag_by_sni = (params->flags & 0b100) > 0; rplrr = (params->flags & 0b10) > 0;
        record_frag = params->flags & 1; mode = (record_frag ? 3 : vortex_frag ? 1 : rplrr ? 2 : 0); //BITWISE MADNESS
        vortex_step_left = params->vortex_step_left; vortex_step_right = params->vortex_step_right; https_fragment_size = params->https_fragment_size;
    }
    for (unsigned short i = 0; i < connectionslen; i++) {
        if (connections[i].taken && connections[i].ip == *((unsigned int*)(srcPacket + 16))) {
            if (connections[i].seq == PTRTOUICE(srcPacket + hdrLen + 4)) {
                if (connections[i].mss != 0) mss = connections[i].mss;
                else printf("BAD MSS ASSOCIATED WITH CONNECTION %u\n", i);
                connections[i].taken = 0;
                break;
            }
            else {
                //printf("Un-Match %u.%u.%u.%u %up%ue\n", PTRTOIP(&connections[i].ip), PTRTOUICE(fakePacket + hdrLen + 4), connections[i].seq);
            }
        }
    }
    if (mss == 1200) printf("ERROR: CONNECTION TRACKING FAIL\n");
    //printf("starting...\n");
    //printf("Begin Super Reverse\n");
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
                tcpSeq = fragments[vortex_relevant].seq;
                totalLength = hdrLen + dataOffset + fragments[vortex_relevant].payloadLen;
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpSeq);
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
                if (vortex_direction == 0) vortex_left++;
                else vortex_right--;
                vortex_step++;
            }
            if (vortex_frag_by_sni) {
                for (short i = beginSni - 1; i >= 0; i--) {
                    tcpSeq = fragments[i].seq;
                    totalLength = hdrLen + dataOffset + fragments[i].payloadLen;
                    SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpSeq);
                    SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                    memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                    NEWPACKETID(fragmentHolder);
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, pAddr, 0
                    );
                    WinDivertSend(
                        filter, fragmentHolder,
                        totalLength,
                        NULL, pAddr
                    );
                }
            }
            break;
        case 2: // --rplrr
            //printf("Begin RPLRR\n");
            vortex_left = rplrr_by_sni ? beginSni : 0;
            vortex_step = 0;
            if (rplrr_by_sni) fragmentInfoLen -= beginSni;
            while (fragmentInfoLen > 0) {
                unsigned short i = genrand16(PTRTOUSCE(srcPacket + 4)) % fragmentInfoLen;
                tcpSeq = fragments[i + vortex_left].seq;
                totalLength = hdrLen + dataOffset + fragments[i + vortex_left].payloadLen;
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpSeq);
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                NEWPACKETID(fragmentHolder);
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
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
                    //printf("PRE:  %u, %u\n", fragments[i + vortex_left].seq, fragments[i + vortex_left].payloadLen);
                    unsigned int pull = vortex_step % 2 == 0 ? vortex_left : fragmentInfoLen - 1 + vortex_left;
                    fragments[i + vortex_left].seq = fragments[pull].seq;
                    fragments[i + vortex_left].payloadLen = fragments[pull].payloadLen;
                    //printf("POST: %u, %u\n", fragments[i + vortex_left].seq, fragments[i + vortex_left].payloadLen);
                }
                if (vortex_step % 2 == 0) vortex_left++;
                skipCondLeft:
                fragmentInfoLen--;
                skipAll:
                vortex_step++;
                //printf("Popped %u, Offset: %u\n", i + vortex_left, vortex_left);
            }
            if (rplrr_by_sni) {
                for (short i = beginSni - 1; i >= 0; i--) {
                    tcpSeq = fragments[i].seq;
                    totalLength = hdrLen + dataOffset + fragments[i].payloadLen;
                    SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpSeq);
                    SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                    memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                    NEWPACKETID(fragmentHolder);
                    WinDivertHelperCalcChecksums(
                        fragmentHolder, totalLength, pAddr, 0
                    );
                    WinDivertSend(
                        filter, fragmentHolder,
                        totalLength,
                        NULL, pAddr
                    );
                }
            }
            break;
        case 3: // --record-frag
            //printf("begin record frag\n");
            struct fragmentationParams rparams = {
                .mode = 1,
                .write_fragments = !tls_force_native,
                .compound_frag = (https_fragment_size > 0 ? https_fragment_size : 2),
                .tls_absolute_frag_size = params->tls_recseg_size,
            };
            struct superReverseParams srparams = {0};
            if (params != NULL) srparams = *params;
            srparams.flags = srparams.flags & 0b11111110;
            //Before this thing causes everything to go to shit, check if theres already a conntrack entry for this connection.
            for (unsigned int i = 0; i < conntrack_curlen; i++) {
                if (conntrack[i].originseq == tcpBaseSeq) {
                    #ifdef TLSDEBUG
                    printf("DUPLICATE\n");
                    #endif
                    return;
                }
            }
            //Find a free conntrack space.
            int freeWaiting = -1;
            for (unsigned int i = 0; i < conntrack_curlen; i++) {
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
            //printf("Expecting SEQ %u\n", tcpBaseSeq + (srcPacketLen - hdrLen - dataOffset) + (fragmentInfoLen - 1) * 5);
            //printf("setting conntrack values at %d\n", freeWaiting);
            conntrack[freeWaiting].flags = 4;
            conntrack[freeWaiting].ip = PTRTOUI(srcPacket + 16);
            conntrack[freeWaiting].lowerseq = tcpBaseSeq + (srcPacketLen - hdrLen - dataOffset);
            conntrack[freeWaiting].upperseq = tcpBaseSeq + (srcPacketLen - hdrLen - dataOffset);
            conntrack[freeWaiting].offset = (fragmentInfoLen - 1) * 5;
            conntrack[freeWaiting].originseq = tcpBaseSeq;
            conntrack[freeWaiting].mss = mss;
            for (unsigned int i = 0; i < host_lenBACK; i++) {
                conntrack[freeWaiting].associatedsni[i] = host_addrBACK[i];
            }
            conntrack[freeWaiting].clientport = PTRTOUSCE(srcPacket + hdrLen);
            conntrack[freeWaiting].associatedsni[host_lenBACK] = 0;
            conntrack[freeWaiting].nextpacketid = PTRTOUSCE(srcPacket + 4);
            conntrack[freeWaiting].flags = conntrack[freeWaiting].flags & 0b11111011;
            tls_reassembly_progress = 0;
            progress = 0;
            unsigned short begin_sni;
            unsigned short end_sni;
            recordbuffer = recordbufferpacket + hdrLen + dataOffset;
            memcpy(recordbufferpacket, srcPacket, hdrLen + dataOffset);
            //printf("building records\n");
            for (unsigned short i = 0; i < fragmentInfoLen; i++) {
                memcpy(recordbuffer + progress + 5, srcPacket + hdrLen + dataOffset + (fragments[i].seq - tcpBaseSeq), fragments[i].payloadLen);
                SETPTRTOUI(recordbuffer + progress, 0x00010316); //Clever, not clever.
                SETPTRTOUSCE(recordbuffer + progress + 3, fragments[i].payloadLen);
                reassemble_tls_bald(recordbuffer + progress);
                if (i == beginSni) begin_sni = progress;
                if (i == endSni) end_sni = progress;
                progress += 5 + fragments[i].payloadLen;
            }
            //unsigned short midpoint = begin_sni + ((end_sni - begin_sni) / 2);
            unsigned int tls_len = progress;
            conntrack[freeWaiting].nextseq = tcpBaseSeq + tls_len;
            progress = 0;
            //for (unsigned int i = 0; i < fragmentInfoLen; i++) {
            //    reassemble_tls_bald(recordbuffer + progress); //BALD! BALD! MY EYEEEEEEEEEES!!!!!
            //    progress += fragments[i].payloadLen + 5;
            //}
            memcpy(fragmentHolder, srcPacket, hdrLen + dataOffset);
            fragmentInfo->length = 0;
            //printf("fakemap check\n");
            if (blackwhitelist_check_hostname(host_addrBACK, host_lenBACK, 3, fakehost)) {
                printf("MATCH! (%s)\n", fakehost);
                struct clienthello clienthello;
                char foundpadding = 0;
                parse_clienthello(srcPacket, &clienthello);
                for (unsigned short i = 0; i < clienthello.extensionCount; i++) {
                    if (clienthello.extensions[i].type == 0) {
                        free(clienthello.extensions[i].data);
                        clienthello.extensions[i].data = malloc(strlen(fakehost) + 5);
                        unsigned char* sni = clienthello.extensions[i].data;
                        clienthello.extensions[i].length = strlen(fakehost) + 5;
                        SETPTRTOUSCE(sni, strlen(fakehost) + 3);
                        sni[2] = 0;
                        SETPTRTOUSCE(sni + 3, strlen(fakehost)); //Far too much work.
                        memcpy(sni + 5, fakehost, strlen(fakehost));
                    }
                    if (clienthello.extensions[i].type == 21) {
                        foundpadding = 1;
                        clienthello.extensions[i].length = tls_len - (srcPacketLen - hdrLen - dataOffset - clienthello.extensions[i].length);
                    }
                }
                if (!foundpadding) {
                    clienthello.extensions = realloc(clienthello.extensions, (clienthello.extensionCount + 1) * sizeof(struct extension));
                    clienthello.extensions[clienthello.extensionCount].type = 21;
                    clienthello.extensions[clienthello.extensionCount].data = NULL;
                    clienthello.extensions[clienthello.extensionCount++].length = tls_len - (srcPacketLen - hdrLen - dataOffset + 4);
                }
                memcpy(fakePacket, srcPacket, hdrLen + dataOffset);
                fakePacketLen = rebuild_clienthello(&clienthello, fakePacket + hdrLen + dataOffset) + hdrLen + dataOffset;
                delete_clienthello(&clienthello);
                SETPTRTOUSCE(fakePacket + 2, fakePacketLen);
            }
            //printf("building fragments\n");
            do_fragmentation(filter, pAddr, fragmentInfo, tcpBaseSeq, recordbufferpacket, tls_len + hdrLen + dataOffset, NULL, 0, &rparams, NULL);
            //printf("built fragments\n");
            conntrack[freeWaiting].nextpacketid = PTRTOUSCE(srcPacket + 4) + fragmentInfo->length;
            //printf("Sending %u fragments.\n", fragmentInfo->length);
            if (!tls_force_native) {
                //printf("attempting to start super reverse in record fragmentation\n");
                do_super_reverse_frag(filter, pAddr, &srparams, fragmentInfo, NULL, 0, recordbufferpacket, tls_len + hdrLen + dataOffset, tcpBaseSeq, 0, fakePacket, fakePacketLen);
            }
            //printf("over\n");
            break;
        default:
            memcpy(fragmentHolder, srcPacket, hdrLen + dataOffset);
            for (short i = fragmentInfoLen - 1; i >= 0; i--) {
                tcpSeq = fragments[i].seq;
                totalLength = hdrLen + dataOffset + fragments[i].payloadLen;
                SETPTRTOUICE(fragmentHolder + hdrLen + 4, tcpSeq);
                SETPTRTOUSCE(fragmentHolder + 2, totalLength);
                memcpy(fragmentHolder + hdrLen + dataOffset, srcPacket + hdrLen + dataOffset + (tcpSeq - tcpBaseSeq), totalLength - hdrLen - dataOffset);
                if (!baseid) NEWPACKETID(fragmentHolder);
                else {
                    SETPTRTOUSCE(srcPacket + 4, baseid);
                    baseid++;
                }
                WinDivertHelperCalcChecksums(
                    fragmentHolder, totalLength, pAddr, 0
                );
                WinDivertSend(
                    filter, fragmentHolder,
                    totalLength,
                    NULL, pAddr
                );
            }
            //differentiate(reassembleSegments, ntohs(PTRTOUS(srcPacket + 2)) - dataOffset - hdrLen, srcPacket + hdrLen + dataOffset, ntohs(PTRTOUS(srcPacket + 2)) - hdrLen - dataOffset, 0);
            //if (!istlshandshake(reassembleSegments)) printf("What?\n");
            break;
    }
    //printf("Finish reverse\n");
}
int main(int argc, char *argv[]) {
    //hexbuff[2] = (char)0;
    reassemblePacket = calloc(MAX_PACKET_SIZE, sizeof(char));
    fatass = calloc(512, sizeof(struct fatasssig));
    unsigned char *fakePacket = calloc(MAX_PACKET_SIZE * 2, sizeof(unsigned char)),
                  fakehost[HOST_MAXLEN],
                  *reassembleSegments = calloc(4216, sizeof(unsigned char));
    struct fragmentInfo fragmentInfo;
    connections = calloc(512, sizeof(struct connection));
    static enum packet_type_e {
        unknown,
        ipv4_tcp, ipv4_tcp_data, ipv4_udp_data,
        ipv6_tcp, ipv6_tcp_data, ipv6_udp_data
    } packet_type;
    //uint16_t domainLen = 0;
    int should_reinject, should_recalc_checksum = 0,
    sni_ok = 0,
    opt,
    packet_v4, packet_v6;
    HANDLE w_filter = NULL;
    WINDIVERT_ADDRESS addr;
    unsigned char realpacket[MAX_PACKET_SIZE],
                  *packet = NULL,
                  recordbufferpacket[65535], //The giant enemy records.
                  *recordbuffer,
                  *packet_data;
    UINT packet_dataLen, packetLen;
    PWINDIVERT_IPHDR ppIpHdr;
    PWINDIVERT_IPV6HDR ppIpV6Hdr;
    PWINDIVERT_TCPHDR ppTcpHdr;
    PWINDIVERT_UDPHDR ppUdpHdr;
    conntrack_info_t dns_conn_info;
    tcp_conntrack_info_t tcp_conn_info;
    unsigned int findmss = 0, fakebuilderrors = 0;
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
        tls_rando_frag = 0,
        fakemap = 0, bad_flags = 0,
        do_native_frag = 0, do_reverse_frag = 0, record_frag = 0, super_reverse = 0, rplrr = 0, rplrr_by_sni, mss = 0, smart_frag = 0, compound_frag = 0, tls_force_native = 0,
        vortex_frag = 0, vortex_frag_by_sni = 0, vortex_step_left = 1, vortex_step_right = 1; //"Big boy words" my- it's gone...
    unsigned int http_fragment_size = 0, https_fragment_size = 0, sni_fragment_size = 0, ext_frag_size = 0, tls_absolute_frag = 0, tls_recseg_size = 0,
                 current_fragment_size = 0, host_len, useragent_len, tcpBaseSeq = 0;
    unsigned short max_payload_size = 0, cleave_sni = 0, fakePacketLen = 0, progress = 0;
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
    unsigned char *host_addr, *useragent_addr, *method_addr, hdrLen, dataOffset;
    int http_req_fragmented;
    char *hdr_name_addr = NULL, *hdr_value_addr = NULL;
    unsigned int hdr_value_len;
    unsigned short randseed = time(NULL) % 0x10000;
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
    struct fakebuild fakebuild;
    unsigned char step = 0, ttlholdstep = 0;
    char ttlhold[4] = "0\0";
    unsigned int max = strlen(optarg);

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
            case 'L': // --wrong-flags
                bad_flags = 1;
                break;
            case 'N': // --cleave-sni
                cleave_sni = 1;
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
            case 'Y':
                unsigned int target = atousi(optarg, "Failed to process fake instruction random generation count!");
                for (unsigned int i = 0; i < target; i++) {
                    fakebuild.mode = genrand16(randseed) % 4;
                    fakebuild.type = genrand16(randseed) % 2;
                    fakebuild.fragmentation = genrand16(randseed) % 3;
                    fakebuild.disorder = genrand16(randseed) % 3;
                    fakebuild.ttl = genrand16(randseed) % 256;
                    fakebuild.chksum = genrand16(randseed) % 2;
                    printf("MODE: %u TYPE %u FRAGMODE %u DISORDERING %u TTL %u CHECKSUM %u\n", fakebuild.mode, fakebuild.type, fakebuild.fragmentation, fakebuild.disorder, fakebuild.ttl, fakebuild.chksum);
                    void* tempptr = realloc(fakebuilds[fakebuild.mode], ++fakebuildlen[fakebuild.mode] * sizeof(struct fakebuild)); //Sucks, but that's too bad.
                    if (tempptr == NULL) {
                        printf("SHIT.\n");
                        die();
                    }
                    else fakebuilds[fakebuild.mode] = tempptr;
                    fakebuilds[fakebuild.mode][fakebuildlen[fakebuild.mode] - 1] = fakebuild;
                }
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
                synner_filter_str = synner_filter_str_discord_vc;
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
            case 'F':
                step = 0;
                progress = 0;
                max = strlen(optarg);
                ttlholdstep = 0;
                while (progress < max && step < 6) {
                    unsigned char curchar = optarg[progress++];
                    if (step != 4 && curchar >= '0' && curchar <= '9')
                        ((unsigned char*)&fakebuild)[step++] = curchar - '0';
                    else if (step == 4) {
                        if (curchar == '0' && ttlholdstep == 0)
                            ((unsigned char*)&fakebuild)[step++] = 0;
                        if (curchar >= '0' && curchar <= '9' && ttlholdstep < 3)
                            ttlhold[ttlholdstep++] = curchar;
                        else if (curchar == ':') {
                            ttlhold[ttlholdstep] = 0;
                            ((unsigned char*)&fakebuild)[step++] = atousi(ttlhold, "Failed to parse TTL!");
                        }
                        else {
                            printf("Error processing %s!\n", optarg);
                            break;
                        }
                    }
                    else {
                        printf("Error processing %s!\n", optarg);
                        break;
                    }
                }
                if (step == 6) {
                    void* tempptr = realloc(fakebuilds[fakebuild.mode], ++fakebuildlen[fakebuild.mode] * sizeof(struct fakebuild)); //Sucks, but that's too bad.
                    if (tempptr == NULL) {
                        printf("SHIT.\n");
                        die();
                    }
                    else fakebuilds[fakebuild.mode] = tempptr;
                    printf("Setting fbs[%u][%u] = %u.%u.%u.%u.%u.%u\n", fakebuild.mode, fakebuildlen[fakebuild.mode] - 1, fakebuild.mode, fakebuild.type, fakebuild.fragmentation, fakebuild.disorder, fakebuild.ttl, fakebuild.chksum);
                    fakebuilds[fakebuild.mode][fakebuildlen[fakebuild.mode] - 1] = fakebuild;
                    for (unsigned int i = 0; i < fakebuildlen[fakebuild.mode]; i++) {
                        printf("%u.%u.%u.%u.%u.%u\n", fakebuild.mode, fakebuilds[fakebuild.mode][i].type, fakebuilds[fakebuild.mode][i].fragmentation, fakebuilds[fakebuild.mode][i].disorder, fakebuilds[fakebuild.mode][i].ttl, fakebuilds[fakebuild.mode][i].chksum);
                    }
                }
                else fakebuilderrors++;
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
            case 'X':
                step = 0;
                progress = 0;
                ttlholdstep = 0;
                max = strlen(optarg);
                while (progress < max && step < 6) {
                    unsigned char curchar = optarg[progress++];
                    if (curchar == '_') {
                        step++;
                    }
                    else if (step != 4 && curchar >= '0' && curchar <= '9') {
                        ((unsigned char*)&fboverrides)[step] = curchar - '0';
                        overriden = overriden | 1 << (5 - step++);
                    }
                    else if (step == 4) {
                        if (curchar == '0' && ttlholdstep == 0) {
                            ((unsigned char*)&fboverrides)[step] = 0;
                            overriden = overriden | 1 << (5 - step++);
                        }
                        if (curchar >= '0' && curchar <= '9' && ttlholdstep < 3)
                            ttlhold[ttlholdstep++] = curchar;
                        else if (curchar == ':') {
                            ttlhold[ttlholdstep] = 0;
                            ((unsigned char*)&fboverrides)[step] = atousi(ttlhold, "Failed to parse TTL!");
                            overriden = overriden | 1 << (5 - step++);
                        }
                        else {
                            printf("Error processing TTL in %s!\n", optarg);
                            break;
                        }
                    }
                    else {
                        printf("Error processing %s!\n", optarg);
                        break;
                    }
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
                fakemap = 1;
                if (!blackwhitelist_load_list(optarg, 3)) {
                    printf("Can't load fake SNI map from file!\n");
                    exit(ERROR_BLACKLIST_LOAD);
                }
                break;
            case 'w':
                do_http_allports = 1;
                break;
            case 'V': // --vortex-frag-by-sni
                vortex_frag_by_sni = 1;
                break;
            case 'z': // --port
                /* i is used as a temporary variable here */
                int i = atoi(optarg);
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
    for (unsigned int x = 0; x < 4; x++)
        for (unsigned int y = 0; y < fakebuildlen[x]; y++)
            printf("MODE: %u, TYPE: %u, FRAGMODE: %u, DISORDERING: %u, TTL: %u, CHECKSUM: %u\n", x, fakebuilds[x][y].type, fakebuilds[x][y].fragmentation, fakebuilds[x][y].disorder, fakebuilds[x][y].ttl, fakebuilds[x][y].chksum);
    printf("OVERRIDES PATTERN: %u\nMODE: %u, TYPE: %u, FRAGMODE: %u, DISORDERING: %u, TTL: %u, CHECKSUM: %u\n", overriden, fboverrides.mode, fboverrides.type, fboverrides.fragmentation, fboverrides.disorder, fboverrides.ttl, fboverrides.chksum);
    //Process FB overrides
    if (overriden > 0) {
        if (overriden & 0b100000)
            for (unsigned char x = 0; x < 4; x++) {
                if (x != fboverrides.mode) {
                    for (unsigned int y = 0; y < fakebuildlen[x]; y++) fakebuilds[x][y].mode = fboverrides.mode;
                    fakebuildlen[fboverrides.mode] += fakebuildlen[x];
                    void* tempptr = realloc(fakebuilds[fboverrides.mode], fakebuildlen[fboverrides.mode] * sizeof(struct fakebuild));
                    if (tempptr == NULL) {
                        printf("SHIT!!!!!\n");
                        die();
                    }
                    else fakebuilds[fboverrides.mode] = tempptr;
                    memcpy(fakebuilds[fboverrides.mode] + (fakebuildlen[fboverrides.mode] - fakebuildlen[x]), fakebuilds[x], fakebuildlen[x] * sizeof(struct fakebuild));
                    fakebuildlen[x] = 0;
                    free(fakebuilds[x]);
                }
            }
        for (unsigned char x = 0; x < 4; x++)
            for (unsigned int y = 0; y < fakebuildlen[x]; y++) {
                if (overriden & 0b10000) fakebuilds[x][y].type = fboverrides.type;
                if (overriden & 0b1000) fakebuilds[x][y].fragmentation = fboverrides.fragmentation;
                if (overriden & 0b100) fakebuilds[x][y].disorder = fboverrides.disorder;
                if (overriden & 0b10) fakebuilds[x][y].ttl = fboverrides.ttl;
                if (overriden & 1) fakebuilds[x][y].chksum = fboverrides.chksum;
            }
        for (unsigned int x = 0; x < 4; x++)
            for (unsigned int y = 0; y < fakebuildlen[x]; y++)
                printf("MODE: %u, TYPE: %u, FRAGMODE: %u, DISORDERING: %u, TTL: %u, CHECKSUM: %u\n", x, fakebuilds[x][y].type, fakebuilds[x][y].fragmentation, fakebuilds[x][y].disorder, fakebuilds[x][y].ttl, fakebuilds[x][y].chksum);
    }
    //Process Super Reverse parameters
    struct superReverseParams srparams;
    srparams.flags = tls_force_native * 0b100000;
    srparams.flags = srparams.flags | (rplrr_by_sni* 0b10000);
    srparams.flags = srparams.flags | (vortex_frag * 0b1000);
    srparams.flags = srparams.flags | (vortex_frag_by_sni * 0b100);
    srparams.flags = srparams.flags | (rplrr * 0b10);
    srparams.flags = srparams.flags | record_frag;
    srparams.vortex_step_left = vortex_step_left;
    srparams.vortex_step_right = vortex_step_right;
    srparams.https_fragment_size = https_fragment_size;
    srparams.tls_recseg_size = tls_recseg_size;
    if (fakebuilderrors > 0)
        printf("%u errors occured while parsing fake packet construction instructions!\n", fakebuilderrors);
    if (tls_rando_frag && sni_fragment_size)
        puts("\nINFO: SNI Fragment size specified with TLS Random Fragmentation.\n"
            "SNI Fragment size overrides random SNI fragment sizes.");
    if (tls_absolute_frag && sni_fragment_size)
        puts("\nINFO: SNI Fragment size specified with TLS Absolute Fragmentation.\n"
            "SNI Fragment size overrides TLS fragment sizes while fragmenting the SNI.");
    if (smart_frag && !ext_frag_size) ext_frag_size = 1;
    if (do_fragment_http && http_fragment_size > 2 && !do_native_frag)
        puts("\nWARNING: HTTP fragmentation values > 2 are not fully compatible "
             "with other options. Please use values <= 2 or disable HTTP fragmentation "
             "completely.");
    if (compound_frag && sni_fragment_size == 0) puts(
        "\nWARNING: Compound fragmentation is enabled but SNI fragmentation is not enabled.\n"
        "Compound fragmentation is not done."
    );
    if (do_native_frag && !(do_fragment_http || do_fragment_https)) {
        puts("\nERROR: Native fragmentation is enabled but fragment sizes are not set.\n"
             "Fragmentation has no effect.");
        die();
    }
    pthread_t thrash_thread, conntrack_thread, synner_thread;
    struct fragmentationParams params = {tls_absolute_frag > 0 ? 1 : (tls_rando_frag ? 2 : (smart_frag ? 3 : 0))},
                               nparams = {.mode = 0, .write_fragments = do_reverse_frag};
    switch (params.mode) {
        case 1: 
            params.tls_absolute_frag_size = tls_absolute_frag;
        case 3:
            params.ext_frag_size = ext_frag_size;
        default:
            params.sni_fragment_size = sni_fragment_size;
            params.write_fragments = super_reverse;
            params.allow_sni_overlap = allow_sni_overlap;
            params.cleave_sni = cleave_sni;
            params.compound_frag = compound_frag ? https_fragment_size : 0;
    }
    if (max_payload_size) add_maxpayloadsize_str(max_payload_size);
    finalize_filter_strings();
    if (activate_thrash) {
        pthread_create(&thrash_thread, NULL, thrash, NULL);
    }
    if (conntrack_maxlen) {
        conntrack = calloc(conntrack_maxlen, sizeof(struct conntracksig));
        pthread_create(&conntrack_thread, NULL, do_conntrack, NULL);
    }
    //pthread_create(&synner_thread, NULL, &synner, NULL); //synner is actually a lot more important now.
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

    for (unsigned int i = 0; i < filter_num; i++) {
        if (filters[i] == NULL)
            die();
    }
    printf("Filter activated, GoodbyeDPI is now running!\n");
    signal(SIGINT, sigint_handler);
    signal(SIGSEGV, sigsegv_handler);

    while (1) {
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
                hdrLen = (packet[0] & 0b00001111) * 4;
                dataOffset = (packet[hdrLen + 12] >> 4) * 4;
                //printf("Got parsed packet, len=%d!\n", packet_dataLen);
                /* Got a TCP packet WITH DATA */
                //If it's a TLS record, is a ClientHello and the record is larger than the packet itself, attempt reassembly of the record.
                if (addr.Outbound && ppTcpHdr->DstPort != htons(80)) {
                    unsigned int ip = PTRTOUI(packet + 16), seq = PTRTOUICE(packet + hdrLen + 4);
                    int freeWaiting = -1;
                    for (unsigned int i = 0; i < fatasslen; i++) {
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
                            unsigned short mss = 1200;
                            tcpBaseSeq = PTRTOUICE(packet + hdrLen + 4);
                            for (unsigned short i = 0; i < connectionslen; i++) {
                                if (connections[i].seq == PTRTOUICE(packet + hdrLen + 4)) {
                                    if (connections[i].mss != 0) mss = connections[i].mss;
                                    else printf("BAD MSS ASSOCIATED WITH CONNECTION %u\n", i);
                                    connections[i].taken = 0;
                                    break;
                                }
                                else {
                                    //printf("Un-Match %u.%u.%u.%u %up%ue\n", PTRTOIP(&connections[i].ip), PTRTOUICE(fakePacket + hdrLen + 4), connections[i].seq);
                                }
                            }
                            if (mss == 1200) printf("ERROR: CONNECTION TRACKING FAIL\n");
                            else if (mss == 0) printf("UH OH!\n");
                            SAFE_SEND(w_filter, &addr, packet, packetLen, mss);
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
                        else {
                            unsigned short mss = 1200;
                            tcpBaseSeq = PTRTOUICE(packet + hdrLen + 4);
                            for (unsigned int i = 0; i < connectionslen; i++) {
                                if (connections[i].seq == PTRTOUICE(packet + hdrLen + 4)) {
                                    if (connections[i].mss != 0) mss = connections[i].mss;
                                    else printf("BAD MSS ASSOCIATED WITH CONNECTION %u\n", i);
                                    connections[i].taken = 0;
                                    break;
                                }
                                else {
                                    //printf("Un-Match %u.%u.%u.%u %up%ue\n", PTRTOIP(&connections[i].ip), PTRTOUICE(fakePacket + hdrLen + 4), connections[i].seq);
                                }
                            }
                            if (mss == 1200) printf("ERROR: CONNECTION TRACKING FAIL\n");
                            else if (mss == 0) printf("UH OH!\n");
                            printf("DAMN. (");
                            xprint(host_addr, host_len, 0);
                            printf(")\n");
                            SAFE_SEND(w_filter, &addr, packet, packetLen, mss);
                            should_reinject = 0;
                            printf("OK.\n");
                        }
                    }
                    else if (freeWaiting == -1 && packet_dataLen > 41) {
                        if (istlshandshake(packet_data) && packet_data[5] == 1 && (PTRTOUSCE(packet_data + 3) + 5) > packet_dataLen) {
                            printf("Attempting reconstruction of record with the PDU size of %u\n", PTRTOUSCE(packet_data + 3) + 5);
                            for (unsigned int i = 0; i < fatasslen; i++) {
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
                            fatass[freeWaiting].expectedlength = PTRTOUSCE(packet_data + 3) + 5;
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
                        if (do_whitelist && !do_blacklist ? blackwhitelist_check_hostname(hdr_value_addr, hdr_value_len, 1, NULL) : 1) goto proceed;
                        host_addr = hdr_value_addr;
                        host_len = hdr_value_len;
                        #ifdef DEBUG
                            char lhost[HOST_MAXLEN + 1] = {0};
                            memcpy(lhost, host_addr, host_len);
                            printf("Blocked HTTP website Host: %s\n", lhost);
                        #endif
                
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
                    } /* if (find_header_and_get_info http_host) */
                } /* Handle OUTBOUND packet with data */
                /*
                * should_recalc_checksum mean we have detected a packet to handle and
                * modified it in some way.
                * Handle native fragmentation here, incl. sending the packet.
                */
                hdrLen = (packet[0] & 0b00001111) * 4;
                dataOffset = (packet[hdrLen + 12] >> 4) * 4;

                if (should_reinject && should_recalc_checksum && do_native_frag)
                {
                    current_fragment_size = 0;
                    fragmentInfo.length = 0;
                    if ((sni_fragment_size || tls_absolute_frag || tls_rando_frag) && sni_ok && packet_v4) {
                        tcpBaseSeq = PTRTOUICE(packet + hdrLen + 4);
                        progress = 0;
                        fakePacketLen = 0;
                        memcpy(host_addrBACK, host_addr, host_len);
                        host_lenBACK = host_len;
                        #ifdef SHOWSNI
                        printf("processing ");
                        xprint(host_addr, host_len, 0);
                        printf("\n");
                        #endif
                        if (!record_frag && blackwhitelist_check_hostname(host_addr, host_len, 3, fakehost)) {
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
                            memcpy(fakePacket, packet, hdrLen + dataOffset);
                            fakePacketLen = rebuild_clienthello(&clienthello, fakePacket + hdrLen + dataOffset) + hdrLen + dataOffset;
                            delete_clienthello(&clienthello);
                            SETPTRTOUSCE(fakePacket + 2, fakePacketLen);
                        }
                        for (unsigned int i = 0; i < MAX_PACKET_SIZE; i++) reassembleSegments[i] = 255;
                        if (host_shiftback != 0 && host_len + host_shiftback > 0) {
                            host_addr -= host_shiftback;
                            host_len += host_shiftback;
                        }
                        if (record_frag) progress = 5;
                        do_fragmentation(w_filter, &addr, &fragmentInfo, tcpBaseSeq, packet, packetLen, host_addr,
                                         host_len, &params, &progress);
                        if (super_reverse) {
                            printf("attempting to start super reverse\n");
                            do_super_reverse_frag(w_filter, &addr, &srparams, &fragmentInfo, host_addr, host_len, packet, packetLen, tcpBaseSeq, 0, NULL, 0);
                        }
                        printf("finished processing\n");
                        continue;
                    }
                    nparams.compound_frag = 0;
                    if (do_fragment_http && ppTcpHdr->DstPort == htons(80)) {
                        nparams.compound_frag = http_fragment_size;
                    }
                    else if (do_fragment_https && ppTcpHdr->DstPort != htons(80)) {
                        if (do_fragment_by_sni && sni_ok) {
                            nparams.compound_frag = (void*)host_addr - (void*)packet_data;
                        } else {
                            nparams.compound_frag = https_fragment_size;
                        }
                    }
                    if (nparams.compound_frag) {
                        printf("attempting to process native fragmentation\n");
                        //TODO: replace this junk with better junk
                        do_fragmentation(w_filter, &addr, &fragmentInfo, 0, packet, packetLen, NULL, 0, &nparams, NULL);
                        if (do_reverse_frag) do_super_reverse_frag(w_filter, &addr, NULL, &fragmentInfo, host_addr, host_len, packet, packetLen, tcpBaseSeq, 0, NULL, 0);
                        continue;
                    }
                }
                proceed:
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
                    NEWPACKETID(packet);
                    WinDivertHelperCalcChecksums(packet, packetLen, &addr, (UINT64)0LL);
                }
                WinDivertSend(w_filter, packet, packetLen, NULL, &addr);
                for (unsigned short i = 0; i < connectionslen; i++) {
                    if (connections[i].taken && connections[i].ip == *((unsigned int*)(packet + 16)) && connections[i].seq == PTRTOUICE(packet + hdrLen + 4)) {
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