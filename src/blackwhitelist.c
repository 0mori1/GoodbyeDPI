/*
 * Blacklist for GoodbyeDPI HTTP DPI circumvention tricks
 *
 * This is a simple domain hash table.
 * Domain records are added from a text file, where every
 * domain is separated with a new line.
 */
#include <windows.h>
#include <stdio.h>
#include "goodbyedpi.h"
#include "utils/uthash.h"
#include "utils/getline.h"

typedef struct blackwhitelist_record {
    const char *host;
    const char *dchunk;
    const char *fakehost;
    UT_hash_handle hh;   /* makes this structure hashable */
    unsigned char childcount;
    struct blackwhitelist_record* children;
} blackwhitelist_record_t;

static blackwhitelist_record_t *blacklist = NULL;
static blackwhitelist_record_t *whitelist = NULL;
static blackwhitelist_record_t *dropper = NULL;
static blackwhitelist_record_t *fakemap = NULL;
static int check_get_hostname(const char *host, char list, char* fakehost) {
    if (!blacklist && !whitelist && !dropper && !fakemap) return FALSE;
    blackwhitelist_record_t *tmp_record = NULL;
    HASH_FIND_STR(list == 0 ? blacklist : (list == 1 ? whitelist : (list == 2 ? dropper : fakemap)), host, tmp_record);
    if (tmp_record) {
        debug("%s - check_get_hostname found host\n", list == 0 ? "BLACKLIST" : list == 1 ? "WHITELIST" : "DROPPER");
        if (list == 3) {
            memcpy(fakehost, tmp_record->fakehost, strlen(tmp_record->fakehost) + 1);
        }
        return TRUE;
    }
    debug("BLACKLIST - check_get_hostname host not found\n");
    return FALSE;
}

static int add_hostname(const char *host, const char *fakehost, char list) {
    if (!host)
        return FALSE;

    blackwhitelist_record_t *tmp_record = malloc(sizeof(blackwhitelist_record_t));
    char *host_c = NULL;
    if (!check_get_hostname(host, 0, NULL)) {
        host_c = strdup(host);
        tmp_record->host = host_c;
        if (list == 3 && fakehost != NULL) {
            tmp_record->fakehost = strdup(fakehost);
        }
        if (list == 0) HASH_ADD_KEYPTR(hh, blacklist, tmp_record->host, strlen(tmp_record->host), tmp_record);
        else if (list == 1) HASH_ADD_KEYPTR(hh, whitelist, tmp_record->host, strlen(tmp_record->host), tmp_record);
        else if (list == 2) HASH_ADD_KEYPTR(hh, dropper, tmp_record->host, strlen(tmp_record->host), tmp_record);
        else HASH_ADD_KEYPTR(hh, fakemap, tmp_record->host, strlen(tmp_record->host), tmp_record);
        debug("Added host %s\n", host_c);
        return TRUE;
    }
    debug("Not added host %s\n", host);
    free(tmp_record);
    if (host_c)
        free(host_c);
    return FALSE;
}

int blackwhitelist_load_list(const char *filename, char list) {
    char *line = malloc(HOST_MAXLEN + 1);
    size_t linelen = HOST_MAXLEN + 1;
    int cnt = 0;
    ssize_t read;

    FILE *fp = fopen(filename, "r");
    if (!fp) return FALSE;
    if (list != 3) {
        while ((read = getline(&line, &linelen, fp)) != -1) {
        /* works with both \n and \r\n */
        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) > HOST_MAXLEN) {
            printf("WARNING: host %s exceeds maximum host length and has not been added\n",
                line);
            continue;
        }
        if (strlen(line) < 2) {
            printf("WARNING: host %s is less than 2 characters, skipping\n", line);
            continue;
        }
        if (add_hostname(line, NULL, list))
            cnt++;
        }
    }
    else {
        unsigned int spacepos = 0;
        while ((read = getline(&line, &linelen, fp)) != -1) {
        /* works with both \n and \r\n */
        line[strcspn(line, "\r\n")] = '\0';
        spacepos = strcspn(line, " ");
        if (spacepos == strlen(line)) {
            printf("WARNING: Error parsing line! Skipping.\n");
            continue;
        }
        line[spacepos] = '\0';
        if (strlen(line) > HOST_MAXLEN) {
            printf("WARNING: host %s exceeds maximum host length and has not been added\n",
                line);
            continue;
        }
        if (strlen(line) < 2) {
            printf("WARNING: host %s is less than 2 characters, skipping\n", line);
            continue;
        }
        if (strlen(line + spacepos + 1) > HOST_MAXLEN) {
            printf("WARNING: fake host %s exceeds maximum host length and has not been added\n",
                line + spacepos + 1);
            continue;
        }
        if (strlen(line + spacepos + 1) < 2) {
            printf("WARNING: fake host %s is less than 2 characters, skipping\n", line + spacepos + 1);
            continue;
        }
        if (add_hostname(line, line + spacepos + 1, list))
            cnt++;
        }
    }
    free(line);
    if ((!blacklist && list == 0) || (!whitelist && list == 1) || (!dropper && list == 2) || (!fakemap && list == 3)) return FALSE;
    printf("Loaded %d hosts from file %s\n", cnt, filename);
    fclose(fp);
    return TRUE;
}

int blackwhitelist_check_hostname(const char *host_addr, size_t host_len, char list, char* fakehost) {
    char current_host[HOST_MAXLEN + 1];
    char *tokenized_host = NULL;

    if (host_len > HOST_MAXLEN) return FALSE;
    if (host_addr && host_len) {
        memcpy(current_host, host_addr, host_len);
        current_host[host_len] = '\0';
    }
    if (list != 1) {
        if (check_get_hostname(current_host, list, fakehost))
            return TRUE;

        tokenized_host = strchr(current_host, '.');
        while (tokenized_host != NULL && tokenized_host < (current_host + HOST_MAXLEN)) {
            if (check_get_hostname(tokenized_host + 1, list, fakehost))
                return TRUE;
            tokenized_host = strchr(tokenized_host + 1, '.');
        }
        debug("____blackwhitelist_check_hostname FALSE: host %s\n", current_host);
        return FALSE;
    }
    else {
        if (check_get_hostname(current_host, 1, fakehost))
            return FALSE;

        tokenized_host = strchr(current_host, '.');
        while (tokenized_host != NULL && tokenized_host < (current_host + HOST_MAXLEN)) {
            if (check_get_hostname(tokenized_host + 1, 1, fakehost))
                return FALSE;
            tokenized_host = strchr(tokenized_host + 1, '.');
        }
        debug("____blackwhitelist_check_hostname FALSE: host %s\n", current_host);
        return TRUE;
    }
}
