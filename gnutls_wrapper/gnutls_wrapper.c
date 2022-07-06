//
// Created by HRoszell on 1/26/2022.
//

#include <gnutls/abstract.h>
#include <gnutls/x509.h>

#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include "../utils.h"
#include "../logging.h"
#include "../lib/base64.h"
#include "../global.h"

#include "gnutls/gnutls.h"
#include "gnutls_wrapper.h"

/******************************************************************************/
/***************************** LOCAL DEFINES  *********************************/
/******************************************************************************/

#define MIN_GNUTLS_VERSION "3.6.3"
#define MAX_CRQ_BUFFER_SIZE 1024 * 10
#define MAX_X509_CERT_SIZE 1024 * 10
#define MAX_FILE_BUF_SIZE 1024 * 50
#define PEM_BUF_SIZE 1024 * 2
#define SHA1LEN 20

/******************************************************************************/
/************************ LOCAL GLOBAL STRUCTURES *****************************/
/******************************************************************************/

/**                                                                           */
/* This structure temporarily matches a PEMInventoryItem to an X509 cert      */
/* by its location in the PEMInventoryItem List.  That is the cert at         */
/* location 0 in PEMInventoryItem is matched to the X509 cert in this list.   */
/*                                                                            */
typedef struct PEMx509List {
    int item_count;
    gnutls_x509_crt_t* certs;
} PEMx509List;

/**                                                                           */
/* This structure allows for dynamic allocation of a list of private keys     */
/* located in a store.                                                        */
/*                                                                            */
typedef struct PrivKeyList
{
    int key_count;
    gnutls_x509_privkey_t *keys;
} PrivKeyList;

/******************************************************************************/
/************************** LOCAL GLOBAL VARIABLES ****************************/
/******************************************************************************/

/* This keypair is for temporary storage in memory.                           */
/* Once the certificate is received from the platform, this gets stored to    */
/* The file system                                                            */
gnutls_privkey_t newPrivKey;

/******************************************************************************/
/************************ LOCAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

static bool PrivKeyList_add(PrivKeyList* list, gnutls_x509_privkey_t key);
static int get_inventory(const char* path,
                         const char* password,
                         PemInventoryList** pPemList,
                         PEMx509List** pPemArray,
                         const bool returnX509array,
                         PrivKeyList** pKeyArray,
                         const bool returnKeyArray);
static bool is_cert_key_match(gnutls_x509_crt_t cert, gnutls_x509_privkey_t key);

int save_datum_to_file(gnutls_datum_t data, const char* file) {
    FILE *fd;
    int ret;

    fd = fopen(file, "a");
    if (fd == NULL) {
        log_error("%s::%s(%d) : Failed to open %s - %s", LOG_INF, file, strerror(errno));
        return -1;
    }

    fseek(fd, 0, SEEK_END);

    ret = (int)fwrite(data.data, (size_t)data.size, 1, fd);
    if (ret != 1) {
        log_error("%s::%s(%d) : Failed to write to %s - %s", LOG_INF, file, strerror(ret));
        return ret;
    }

    ret = fclose(fd);
    if (ret != 0) {
        log_error("%s::%s(%d) : Failed to close %s - %s", LOG_INF, file, strerror(ret));
        return ret;
    }
    log_trace("%s::%s(%d) : Saved datum to %s", LOG_INF, file);

    return 0;
}

int read_datum_from_file(gnutls_datum_t * datum, const char* file) {
    FILE *fd;
    int ret;

    fd = fopen(file, "r");
    if (fd == NULL) {
        log_error("%s::%s(%d) : Failed to open %s - %s", LOG_INF, file, strerror(errno));
        return -1;
    }

    datum->data = calloc(sizeof(char) * MAX_FILE_BUF_SIZE, sizeof(char ));
    if (!datum->data) {
        log_error("%s::%s(%d) : Failed to allocate memory to read from %s", LOG_INF, file);
        return -1;
    }

    datum->size = fread(datum->data, sizeof(char), MAX_FILE_BUF_SIZE, fd);
    if (ret < 1) {
        log_error("%s::%s(%d) : Failed to read from %s - %s", LOG_INF, file, strerror(ret));
        return ret;
    }

    datum->data = realloc(datum->data, datum->size * sizeof(char));

    ret = fclose(fd);
    if (ret != 0) {
        log_error("%s::%s(%d) : Failed to close %s - %s", LOG_INF, file, strerror(ret));
        return ret;
    }
    log_trace("%s::%s(%d) : Read datum (%d bytes) from %s to %p", LOG_INF, datum->size, file, datum->data);

    return (int)datum->size;
}

/******************************************************************************/
/* NOTE: PemInventoryItem and list are created here, but freed in the Agent.  */
/* The ssl wrapper MUST know about this structure to communicate with the     */
/* agent layer.                                                               */
/******************************************************************************/
/**                                                                           */
/* Allocate memory for a new PemInventoryItem                                 */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : a pointer to the memory allocated for the new item     */
/*         - failure : NULL                                                   */
/*                                                                            */
static PemInventoryItem* PemInventoryItem_new()
{
    PemInventoryItem* pem = (PemInventoryItem*)malloc(sizeof(PemInventoryItem));
    if(pem)
    {
        pem->cert = NULL;
        pem->thumbprint_string = NULL;
        pem->has_private_key = false;
    }
    else
    {
        log_error("%s::%s(%d) : Out of memory",
                  LOG_INF);
    }
    return pem;
} /* PemInventoryItem_new */

/**                                                                           */
/* Allocate memory for a new PemInventoryList                                 */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success : a pointer to the memory allocated for the new list     */
/*         - failure : NULL                                                   */
/*                                                                            */
static PemInventoryList* PemInventoryList_new()
{
    PemInventoryList* list = (PemInventoryList*)malloc(sizeof(PemInventoryList));
    if(list)
    {
        list->item_count = 0;
        list->items = NULL;
    }
    return list;
} /* PemInventoryList_new */

/**                                                                           */
/* Allocate memory for a new PEMx509List                                      */
/*                                                                            */
/* NOTE: This item is linked to the PEMInventoryItemList.  For each entry in  */
/* the PEMInventoryItemList, the index is the same into this dynamic list     */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success = a pointer to the newly allocated memory area           */
/*	       - failure = NULL                                                   */
/*                                                                            */
static PEMx509List* PEMx509List_new(void)
{
    PEMx509List* x509list = (PEMx509List*)calloc(1,sizeof(*x509list));
    if (x509list)
    {
        x509list->item_count = 0;
        x509list->certs = NULL;
    }
    return x509list;
} /* PEMx509List_new */

/**                                                                           */
/* Allocate memory for a new PrivKeyList                                      */
/*                                                                            */
/* @param  - none                                                             */
/* @return - success = a pointer to the newly allocated memory area           */
/*	       - failure = NULL                                                   */
/*                                                                            */
static PrivKeyList* PrivKeyList_new(void)
{
    PrivKeyList* list = (PrivKeyList*)calloc(1,sizeof(*list));
    if (list)
    {
        list->key_count = 0;
        list->keys = NULL;
    }
    else
    {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
    }
    return list;
} /* PrivKeyList_new */

/**                                                                           */
/* Free the PrivKeyList from memory                                           */
/*                                                                            */
/* @param  - [Input] : list = the list to free                                */
/* @return - none                                                             */
/*                                                                            */
static void PrivKeyList_free(PrivKeyList* pList)
{
    if (0 < pList->key_count)
    {
        for(int i = 0; pList->key_count > i; i++)
        {
            log_trace("%s::%s(%d) : Freeing PrivKey #%d from PrivKeyList",
                      LOG_INF, i);
            if ( pList->keys[i] ) {
                gnutls_x509_privkey_deinit(pList->keys[i]);
            }
        }
        pList->key_count = 0;
    }

    log_trace("%s::%s(%d) : Freeing the PrivKeyList", LOG_INF);
    if (pList->keys) free(pList->keys);
    if (pList) free(pList);
    pList = NULL;

    return;
} /* PrivKeyList_free */

/**                                                                           */
/* Free the PEMx509List from memory                                           */
/*                                                                            */
/* @param  - [Input] : list = the list to free                                */
/* @return - none                                                             */
/*                                                                            */
static void PEMx509List_free(PEMx509List* pList)
{
    if (0 < pList->item_count)
    {
        for(int i = 0; pList->item_count > i; i++)
        {
            log_trace("%s::%s(%d) Freeing cert #%d from PEMx509List",
                      LOG_INF, i);
            gnutls_x509_crt_deinit(pList->certs[i]);
        }
        pList->item_count = 0;
    }

    log_trace("%s::%s(%d) : Freeing the PEMx509List", LOG_INF);
    if (pList ->certs) free(pList->certs);
    if (pList) free(pList);
    pList = NULL;

} /* PEMx509List_free */

/**                                                                           */
/* Add a key to a PrivKeyList                                                 */
/*                                                                            */
/* @param  - [Output] : list = the list to add the key into                   */
/* @param  - [Input]  : cert = the key to add to the list                     */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PrivKeyList_add(PrivKeyList* list, gnutls_x509_privkey_t key)
{
    bool bResult = false;
    if(list && key)
    {
        list->keys = realloc(list->keys, (1 + list->key_count) * sizeof(key));
        if (list->keys)
        {
            log_trace("%s::%s(%d) : Added gnutls_x509_privkey_t #%d to PrivKeyList",
                      LOG_INF, list->key_count);
            list->keys[list->key_count] = key;
            list->key_count++;
            bResult = true;
        }
        else
        {
            log_error("%s::%s(%d) : Out of memory",	LOG_INF);
        }
    }
    else
    {
        log_error("%s::%s(%d) : Either the list or key was NULL", LOG_INF);
    }
    return bResult;
} /* PrivKeyList_add */

/**                                                                           */
/* Look through the subject to decode the subject's value                     */
/* e.g., if subject is CN=12345,O=Keyfactor then this function is passed      */
/* the portion after the equals sign.  The first time it is called, it will   */
/* receive 12345,O=Keyfactor.  It will return 12345                           */
/* The next time it is called it will be passed Keyfactor & return Keyfactor. */
/*                                                                            */
/* If an ascii escaped string is encountered it parses the value accordingly. */
/* e.g., if domain\\user is sent, the subject is converted to domain\user     */
/*                                                                            */
/* If an ascii escaped hex value is encontered it parses the value accordingly*/
/* e.g., if \\3F  then the value ? is returned.                               */
/*                                                                            */
/* @param  - [Input] : subject = a portion of the full subject after a key    */
/*                               i.e., it starts with a value for the key     */
/* @param  - [Ouput] : buf = string containing the value                      */
/* @return - success : how far into the subject string we found a subject     */
/*					   separator                                              */
/*         - failure : -1                                                     */
/*                                                                            */
static int read_subject_value(const char* subject, char* buf)
{
    int subjLen = (int)strlen(subject);
    int subInd = 0;
    int bufInd = 0;
    char c = ' ';
    char escaped[1] = {' '};
    unsigned int hexHi, hexLo;

    bool done = false;
    bool hasError = false;

    while(!done && !hasError && subInd < subjLen)
    {
        c = subject[subInd];
        switch(c)
        {
            case '\\':
                if(sscanf(&subject[subInd], "\\%1[\" #+,;<=>\\]", escaped) == 1)
                {
                    if(buf)
                    {
                        buf[bufInd++] = escaped[0];
                    }
                    subInd += 2;
                }
                else if(sscanf(&subject[subInd], "\\%1x%1x", &hexHi, &hexLo) == 2)
                {
                    if(buf)
                    {
                        buf[bufInd++] = (char)((hexHi << 4) | hexLo);
                    }
                    subInd += 3;
                }
                else
                {
                    hasError = true;
                }
                break;
            case ',':
                done = true;
                break;
            default:
                if(buf)
                {
                    buf[bufInd++] = c;
                }
                ++subInd;
                break;
        }
    }

    if(buf)
    {
        buf[bufInd] = '\0';
    }

    return hasError ? -1 : subInd;
} /* read_subject_value */

/**                                                                           */
/* Return a pointer to the first non-space element in the string.  The string */
/* MAY be modified by this function by adding a NULL ('\0') terminator        */
/* inside the string.  This null terminator may be before the null terminator */
/* of the original string.                                                    */
/*                                                                            */
/* for example, both of these may happen:                                     */
/*   string = " I have spaces before and after me      "\0                    */
/* Here is what happens this function does:                                   */
/*                                                                            */
/* sring = " I have spaces before and after me      "\0                       */
/*           ^                                ^ is replaced with \0           */
/*           |                                                                */
/*            - beg (returned value)                                          */
/*                                                                            */
/* NOTE: This doesn't ADD any dynamically allocated memory                    */
/*       so you MUST NOT DEALLOCATE the returned value.  The returned         */
/*       value is at a minimum, a subset pointing inside the original data    */
/*       structure.  At a maximum it is the same pointer.                     */
/*                                                                            */
/* @param  - [Input/Output] : string = the string to parse                    */
/* @param  - [Input] : the length of the string                               */
/* @return - none                                                             */
/*                                                                            */
static char* strip_blanks(char* string, const unsigned long strSz)
{
    char* beg = string;  /* Copy the pointer so we can advance */
    char* end = string + strlen(string) - 1; /* Point to the string's end */

    /* Remove any leading spaces */
    while (isspace((unsigned char)*beg))
    {
        beg++;
    }

    /* beg now points to the first non whitespace character */
    /* now find the last non-whitespace character */
    while (isspace((unsigned char)*end) && (end != (beg-1)) )
    {
        end--;
    }

    /* Null terminate one after the last non-whitespace character */
    end[1] = '\0';

    return beg;
} /* strip_blanks */

int populate_subject(gnutls_x509_crq_t * crq, char* key, char* value) {
    // todo check if crq is init
    const char *oid = NULL;

    if ( 0 == (strcasecmp(key,"C")) )
    {
        log_trace("%s::%s(%d) : Setting Country to %s", LOG_INF, value);
        oid = GNUTLS_OID_X520_COUNTRY_NAME;
    }
    else if ( 0 == (strcasecmp(key,"S")) )
    {
        log_trace("%s::%s(%d) : Setting State to %s", LOG_INF, value);
        oid = GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME;
    }
    else if ( 0 == (strcasecmp(key,"L")) )
    {
        log_trace("%s::%s(%d) : Setting locality to %s", LOG_INF, value);
        oid = GNUTLS_OID_X520_LOCALITY_NAME;
    }
    else if ( 0 == (strcasecmp(key,"O")) )
    {
        log_trace("%s::%s(%d) : Setting Organization to %s", LOG_INF, value);
        oid = GNUTLS_OID_X520_ORGANIZATION_NAME;
    }
    else if ( 0 == (strcasecmp(key,"OU")) )
    {
        log_trace("%s::%s(%d) : Setting Organizational Unit to %s", LOG_INF,
                  value);
        oid = GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME;
    }
    else if ( 0 == (strcasecmp(key,"CN")) )
    {
        log_trace("%s::%s(%d) : Setting Common Name to %s", LOG_INF, value);
        oid = GNUTLS_OID_X520_COMMON_NAME;
    }
    else
    {
        log_info("%s::%s(%d) : key = %s is unknown, skipping", LOG_INF, key);
    }
    if (NULL != oid)
        gnutls_x509_crq_set_dn_by_oid(*crq, oid, 0, value, strlen (value));
    // todo error handling

    return 0;
}

int set_subject(const char * subject, gnutls_x509_crq_t * crq) {
    // todo make sure crq is initialized
    char* keyBytes = NULL;
    char* strippedKey = NULL;
    unsigned long keyLen = 0;
    char* valBytes = NULL;
    char* strippedVal = NULL;
    unsigned long valLen = 0;
    char* localSubjectPtr = NULL;
    bool hasError = false;
    char* curPtr = NULL;
    int allocateMemorySize = 0;
    bool endOfSubject = false;

    localSubjectPtr = strdup(subject);
    curPtr = localSubjectPtr;
    log_debug("%s::%s(%d) : Subject \"%s\" is %ld characters long",
              LOG_INF, curPtr, strlen(curPtr));

    log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s", LOG_INF,
              hasError ? "true" : "false", endOfSubject ? "true" : "false");

    while(!hasError && !endOfSubject)
    {
        /* Get the Key */
        keyLen = strcspn(curPtr, "=");
        allocateMemorySize = (int)keyLen + 1;
        keyBytes = calloc(allocateMemorySize,sizeof(*keyBytes));
        if (NULL == keyBytes)
        {
            log_error("%s::%s(%d) : Out of memory", LOG_INF);
            goto cleanup;
        }
        strncpy(keyBytes, curPtr, (int)keyLen);

        strippedKey = strip_blanks(keyBytes, keyLen);
        log_verbose("%s::%s(%d) : Key: \"%s\" is %ld characters long",
                    LOG_INF, strippedKey, strlen(strippedKey));

        /* Now get the value for the key */
        curPtr += (keyLen+1); /* Advance past the equals character */
        if( *curPtr != '\0' )
        {
            log_trace("%s::%s(%d) : localSubject is now \"%s\"",
                      LOG_INF, curPtr);
            valLen = read_subject_value(curPtr, NULL);
            if(valLen != 0)
            {
                allocateMemorySize = (int)valLen + 1;
                valBytes = calloc(allocateMemorySize,sizeof(*valBytes));
                if (NULL == valBytes)
                {
                    log_error("%s::%s(%d) : Out of memory", LOG_INF);
                    goto cleanup;
                }
                read_subject_value(curPtr, valBytes);
                curPtr += (valLen+1); // advance past the comma
                strippedVal = strip_blanks(valBytes, strlen(valBytes));
                log_verbose("%s::%s(%d) : Value: \"%s\" is %ld characters long",
                            LOG_INF, strippedVal, strlen(strippedVal));

                populate_subject(crq, strippedKey, strippedVal);

                /* Don't try to advance if we just advanced past the */
                /* null-terminator */
                if( *(curPtr-1) != '\0' )
                {
                    if ( *curPtr != '\0' )
                    {
                        /* Whitespace between RDNs should be ignored */
                        log_trace("%s::%s(%d) : Stripping leading whitespace "
                                  "from \"%s\"", LOG_INF, curPtr);
                        curPtr = strip_blanks(curPtr, strlen(curPtr));
                    }
                    else
                    {
                        log_trace("%s::%s(%d) : Reached end of subject string",
                                  LOG_INF);
                        endOfSubject = true;
                    }
                }
                else
                {
                    log_trace("%s::%s(%d) : Reached end of subject string",
                              LOG_INF);
                    endOfSubject = true;
                }
            }
            else
            {
                log_error("%s::%s(%d) : Input string '%s' is not a valid X500"
                          " name", LOG_INF, localSubjectPtr);
                hasError = true;
            }
        }
        else
        {
            log_error("%s::%s(%d) : Input string '%s' is not a valid X500 name",
                      LOG_INF, localSubjectPtr);
            hasError = true;
        }
        if (keyBytes) free(keyBytes);
        if (valBytes) free(valBytes);
        /* Remember, *DONT* double free valBytes by freeing strippedVal */
        /* Likewise with strippedKey */
        keyBytes = NULL;
        valBytes = NULL;
        strippedVal = NULL;
        strippedKey = NULL;
        log_trace("%s::%s(%d) : hasError = %s endOfSubject = %s", LOG_INF,
                  hasError ? "true" : "false", endOfSubject ? "true" : "false");
    }

    cleanup:
    if (localSubjectPtr)
    {
        log_trace("%s::%s(%d) : Freeing localSubjectPtr", LOG_INF);
        free(localSubjectPtr);
        localSubjectPtr = NULL;
    }
    if (keyBytes) free(keyBytes);
    if (valBytes) free(valBytes);
    /* Remember, *DONT* double free valBytes by freeing strippedVal */
    /* Likewise with strippedKey */
    keyBytes = NULL;
    valBytes = NULL;
    strippedVal = NULL;
    strippedKey = NULL;

    if (!hasError) {
        return 0;
    }
    else {
        return -1;
    }
}

/**                                                                           */
/* Append to a store a new cert                                               */
/*                                                                            */
/* @param  - [Input] : storePath = the stores location                        */
/* @param  - [Input] : cert = the X509 certificate                            */
/* @return - success = 0;                                                     */
/*           failure = Any other integer                                      */
/*                                                                            */
static int store_append_cert(const char* storePath, gnutls_x509_crt_t cert) {
    int response;
    gnutls_datum_t newCert;

    log_trace("%s::%s(%d) : Finding length of certificate stored inside gnutls_x509_crt_t", LOG_INF);
    response = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, NULL, (size_t*)&newCert.size);
    if (GNUTLS_E_SHORT_MEMORY_BUFFER == response || GNUTLS_E_SUCCESS == response) {
        log_trace("%s::%s(%d) : Certificate is %d bytes long", LOG_INF, newCert.size);
    } else {
        // If the response is not GNUTLS_E_SHORT_MEMORY_BUFFER, the cert size wasn't updated.
        log_warn("%s::%s(%d) : gnutls_x509_crt_export returned code %d", LOG_INF, response);
        log_error("%s::%s(%d) : Failed to get the size of inputted X509 certificate structure", LOG_INF);
        return response;
    }

    log_trace("%s::%s(%d) : Allocating %d bytes for certificate digest", LOG_INF, newCert.size);
    newCert.data = malloc(newCert.size);
    if (!newCert.data) {
        response = -1;
        log_error("%s::%s(%d) : Failed to allocate memory for certificate. Out of memory", LOG_INF);
        return response;
    }

    log_trace("%s::%s(%d) : Exporting certificate to GNUTLS_X509_FMT_PEM format", LOG_INF);
    response = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, newCert.data, (size_t*)&newCert.size);
    if (GNUTLS_E_SHORT_MEMORY_BUFFER == response) {
        // Sometimes the cert buffer expands after calling gnutls_x509_crt_export. Handle this situation here
        log_trace("%s::%s(%d) : Reallocating certificate digest buf to %d - gnutls_x509_crt_export returned %d", LOG_INF, newCert.size, response);
        newCert.data = realloc(newCert.data, newCert.size);
        if (!newCert.data) {
            response = -1;
            log_error("%s::%s(%d) : Failed to allocate memory for certificate. Out of memory", LOG_INF);
            return response;
        }

        response = gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_PEM, newCert.data, (size_t*)&newCert.size);
        if (GNUTLS_E_SUCCESS != response) {
            log_error("%s::%s(%d) : Failed to export certificate", LOG_INF);
            return response;
        }
    } else if (GNUTLS_E_SUCCESS != response) {
        log_warn("%s::%s(%d) : gnutls_x509_crt_export returned code %d", LOG_INF, response);
        log_error("%s::%s(%d) : Failed to export certificate", LOG_INF);
        return response;
    }

    save_datum_to_file(newCert, storePath);

    if (newCert.data) {
        log_trace("%s::%s(%d) : Deallocating %d bytes of heap memory used to append certificate", LOG_INF, newCert.size);
        free(newCert.data);
    }

    return 0;
}

/**                                                                           */
/* Compute the sha1 hash of the certificate                                   */
/* Returned value must be freed.                                              */
/*                                                                            */
/* @param  - [Input] : cert = the X509 cert to compute the thumbprint         */
/* @return - success : an ascii encoded thumbprint                            */
/*         - failure : NULL                                                   */
/*                                                                            */
static char* compute_thumbprint(gnutls_x509_crt_t cert)
{
    unsigned char * buf = NULL;
    size_t len = 0;
    int response;

    // Get size of SHA1
    response = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA1, NULL, &len);
    if (GNUTLS_E_SHORT_MEMORY_BUFFER != response) {
        log_error("%s::%s(%d) : Failed to calculate SHA-1 hash of certificate", LOG_INF);
        return NULL;
    }

    // Allocate memory
    buf = calloc(len, sizeof(unsigned char));

    // Calculate
    response = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA1, buf, &len);
    if (GNUTLS_E_SUCCESS != response) {
        log_error("%s::%s(%d) : Failed to calculate SHA-1 hash of certificate", LOG_INF);
        return NULL;
    }

    return hex_encode(buf, (int)len);
}

/**                                                                           */
/* Populate a PemInventoryItem with a certificate and thumbprint.              */
/* Default the has_private_key bit to false.                                  */
/*                                                                            */
/* @param  - [Output] : pem = the PemInventoryItem to populate                */
/* @param  - [Input]  : cert = the Cert to populate into the pem item         */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PemInventoryItem_populate(PemInventoryItem* pem, gnutls_x509_crt_t cert) {
    bool bResult = false;
    char* thumb = NULL;
    unsigned char* certContent = NULL;
    int response = 0;
    size_t certLen = 0;

    if (pem && cert)
    {
        thumb = compute_thumbprint(cert);
        log_verbose("%s::%s(%d) : Thumbprint: %s", LOG_INF, NULL == thumb ? "" : thumb);

        // Get cert size
        if (GNUTLS_E_SHORT_MEMORY_BUFFER != gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, NULL, &certLen)) {
            log_error("%s::%s:(%d) : Failed to get certificate size", LOG_INF);
            return false;
        }

        // Allocate memory
        certContent = calloc(certLen, sizeof(unsigned char));

        // Export cert
        if (GNUTLS_E_SUCCESS != gnutls_x509_crt_export(cert, GNUTLS_X509_FMT_DER, certContent, &certLen)) {
            log_error("%s::%s:(%d) : Failed to export certificate", LOG_INF);
            return false;
        }

        log_trace("%s::%s(%d) : certLen = %zu", LOG_INF, certLen);

        if (0 < certLen)
        {
            /* Store the b64 encoded DER version of the pem in here */
            log_trace("%s::%s(%d) : Storing certContent into PEMInventoryItem", LOG_INF);
            pem->cert = base64_encode(certContent, certLen, false, NULL);
            pem->thumbprint_string = strdup(thumb);
            pem->has_private_key = false;
            bResult = true;
        }
        else {
            log_error("%s::%s:(%d) : Error decoding cert i2d_X509\n%s", LOG_INF, certContent);
        }
    }
    else {
        log_error("%s::%s(%d) : Bad pem, cert, or certString", LOG_INF);
    }

    return bResult;
}

/**                                                                           */
/* Compare the public key stored in the certificate with a private key and    */
/* determine if they are a matched pair.                                      */
/*                                                                            */
/* @param  - [Input] : cert = An x509 certificate (contining a pub key)       */
/* @param  - [Input] : key = a keypair structure containing a private key     */
/* @return - true = public key is the pair for the private key                */
/*		   - false = they key types or common factors are not equal           */
/*                                                                            */
static bool is_cert_key_match(gnutls_x509_crt_t cert, gnutls_x509_privkey_t key) {
    int res = 0;
    size_t size = 0;
    unsigned char * privSHA1Buf = NULL;
    unsigned char * pubSHA1Buf = NULL;
    bool isMatch = false;

    if (!cert || !key)
        return false;

    // First, compare the key IDs of the certificate and private key

    // Get size of pub key SHA1
    /*
    res = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA1, NULL, &size);
    if (res != GNUTLS_E_SHORT_MEMORY_BUFFER && res != GNUTLS_E_SUCCESS) {
        log_error("%s::%s:(%d) : Failed to get SHA1 length of certificate public key", LOG_INF);
        goto cleanup;
    }*/

    pubSHA1Buf = (unsigned char*)calloc(SHA1LEN, sizeof(unsigned char));
    size = SHA1LEN;

    // Get key ID of pub key
    res = gnutls_x509_crt_get_key_id(cert, GNUTLS_KEYID_USE_SHA1, pubSHA1Buf, &size);
    if (res != GNUTLS_E_SUCCESS) {
        log_error("%s::%s:(%d) : Failed to get SHA1 key ID of public certificate", LOG_INF);
        goto cleanup;
    }

    privSHA1Buf = (unsigned char*)calloc(SHA1LEN, sizeof(unsigned char));
    size = SHA1LEN;

    // Get key ID of pub key
    res = gnutls_x509_privkey_get_key_id(key, GNUTLS_KEYID_USE_SHA1, privSHA1Buf, &size);
    if (res != GNUTLS_E_SUCCESS) {
        log_error("%s::%s:(%d) : Failed to get SHA1 length of certificate public key", LOG_INF);
        goto cleanup;
    }

    if (!pubSHA1Buf || !privSHA1Buf) {
        log_error("%s::%s:(%d) : Out of memory", LOG_INF);
        res = -1;
        goto cleanup;
    }

    // Check if the keys match
    if ((memcmp(pubSHA1Buf, privSHA1Buf, size)) == 0) {
        isMatch = true;
    }

    // TODO check with Ray to see if I need to compare n's

    cleanup:
    if (privSHA1Buf)
        free(privSHA1Buf);
    if (pubSHA1Buf)
        free(pubSHA1Buf);

    return isMatch;
}

/**                                                                           */
/* Add a PemInventoryItem to a PemInventoryList                               */
/*                                                                            */
/* @param  - [Ouput] : list = the list to add to (NULL if the add fails)      */
/* @param  - [Input] : item = the item to add to the list                     */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PemInventoryList_add(PemInventoryList* list, PemInventoryItem* item)
{
    bool bResult = false;
    if(list && item)
    {
        list->items = realloc(list->items,
                              (1 + list->item_count) * sizeof(item));
        if (list->items)
        {
            list->items[list->item_count] = item;
            list->item_count++;
            log_trace("%s::%s(%d) : Added cert with thumbprint %s to local "
                      "inventory", LOG_INF, item->thumbprint_string);
            bResult = true;
        }
        else
        {
            log_error("%s::%s(%d) : Out of memory",	LOG_INF);
        }
    }
    else
    {
        log_error("%s::%s(%d) : Either the list or item was NULL", LOG_INF);
    }
    return bResult;
} /* PemInventoryList_add */

/**                                                                           */
/* Add an X509 cert to a PEMx509List                                          */
/*                                                                            */
/* @param  - [Output] : list = the list to add the cert to                    */
/* @param  - [Input]  : cert = the cert to add to the list                    */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
static bool PEMx509List_add(PEMx509List* list, gnutls_x509_crt_t cert)
{
    bool bResult = false;
    if(list && cert)
    {
        list->certs = realloc(list->certs, \
			(1 + list->item_count) * sizeof(cert));
        if (list->certs)
        {
            log_trace("%s::%s(%d) : Adding X509 cert #%d to PEMx509List",
                      LOG_INF, list->item_count);
            list->certs[list->item_count] = cert;
            list->item_count++;
            bResult = true;
        }
        else
        {
            log_error("%s::%s(%d) : Out of memory",
                      LOG_INF);
        }
    }
    else
    {
        log_error("%s::%s(%d) : Either the list or cert was NULL", LOG_INF);
    }
    return bResult;
} /* PEMx509List_add */

char * PEM_read(FILE * fp, char ** pemBuf, size_t * pemBufSize) {
    int ret = -1;
    bool pemFound = false;
    char * lineBuf = NULL;
    size_t lineBufSize;
    size_t lineLen = 0;

    pemBuf = calloc(0, sizeof(char));
    if (NULL == pemBuf) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        goto cleanup;
    }

    while ((lineLen = getline(&lineBuf, &lineBufSize, fp)) != -1){
        // Search for beginning
        if (strncmp(lineBuf,"-----BEGIN ",11) == 0) {
            log_trace("%s::%s(%d) : Found '%.11s' - setting pemFound = true. Looking for END", LOG_INF, strncpy(lineBuf, lineBuf, 11));
            pemFound = true;
        }

        // If a BEGIN was found, we found a PEM object. Reallocate (lineLen + pemBufSize) for *pemBuf
        if (pemFound) {
            // Resize pemBuf to lineLen bytes greater than it was before
            if ((*pemBuf = realloc(*pemBuf, lineLen + *pemBufSize)) == NULL) {
                log_error("%s::%s(%d) : Out of memory", LOG_INF);
                goto cleanup;
            }

            // Concatenate lineBuf to *pemBuf
            strncpy( *pemBuf + *pemBufSize, lineBuf, lineLen );

            // Update pemBufSize
            *pemBufSize += lineLen;

            if (strncmp(lineBuf, "-----END ", 9) == 0) {
                log_trace("%s::%s(%d) : Found '%.8s' - Placing null terminator", LOG_INF, strncpy(lineBuf, lineBuf, 8));

                // Allocate space for the null terminator
                if ((*pemBuf = realloc(*pemBuf, *pemBufSize + 1)) == NULL) {
                    log_error("%s::%s(%d) : Out of memory", LOG_INF);
                    goto cleanup;
                }


                strcpy(*pemBuf + *pemBufSize, "\0");
                *pemBufSize++;

                log_debug("%s::%s(%d) : Found complete PEM block", LOG_INF);
                ret = 0;
                goto cleanup;
            }
        }
    }

    cleanup:
    if (lineBuf)
        free(lineBuf);

    if (ret < 0)
        return NULL;
    else
        return *pemBuf;
}

/**                                                                           */
/* Read a list of keys from a keystore                                        */
/*                                                                            */
/* @param  - [Input] path = location of the keystore                          */
/* @param  - [Input] password = password of the keys in the keystore          */
/* @param  - [Ouput] keyList = the array of keys                              */
/*                   NOTE: This must be freed by the calling function         */
/* @return - success = 0                                                      */
/*           failure = Any other integer                                      */
/*                                                                            */
static int get_key_inventory(const char* path, const char* password, PrivKeyList** keyList) {
    int ret = 0;
    FILE* fp = NULL;
    char *pemBuf = NULL;
    gnutls_x509_privkey_t key;
    gnutls_datum_t pemDatum;
    size_t pemSize = 0;
    int i = 0;
    char * name;

    *keyList = PrivKeyList_new();
    if ( NULL == *keyList )
    {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        return -1;
    }

    pemBuf = calloc(0, sizeof(char));
    if (!pemBuf) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        ret = -1;
        goto cleanup;
    }

    fp = fopen(path, "r");
    if (!fp) {
        ret = errno;
        char* errStr = strerror(errno);
        log_error("%s::%s(%d) : Unable to open store at %s: %s", LOG_INF, path, errStr);
        free(errStr);
        goto cleanup;
    }

    while ((pemBuf = PEM_read(fp, &pemBuf, &pemSize)) != NULL) {
        log_debug("%s::%s(%d) : Found PEM block with size %zu", LOG_INF, pemSize);

        key = NULL;

        pemDatum.data = NULL;
        pemDatum.size = 0;

        // First, we need to clean up the PEM block.
        if (strncmp(pemBuf,"-----BEGIN ",11) != 0) {
            log_error("%s::%s(%d) : '-----BEGIN' not found", LOG_INF);
            return -1;
        }

        // Trim off the ends of pem (anything less than ASCII 32) and reformat with newline and null character
        while ((pemSize >= 0) && (pemBuf[pemSize] <= ' ')) pemSize--;
        pemBuf[++pemSize]='\n';
        pemBuf[++pemSize]='\0';

        log_trace("%s::%s(%d) : Cleaned up PEM object", LOG_INF);

        // Next, find the index of '-----\n' so we can find the name of the block.
        // IE the PEM block name is between -----BEGIN and -----\n
        for (i = 11; i < pemSize; i++) {
            if (strncmp(&(pemBuf[i]), "-----\n", 5) == 0)
                break;
        }
        if (i == 1 - pemSize) {
            log_error("%s::%s(%d) : Didn't find '-----\\n' after '-----BEGIN '.", LOG_INF);
            goto cleanup;
        }

        name = calloc(i - 11, sizeof(char));
        name = strncpy(name, &(pemBuf[11]), i - 11);

        log_trace("%s::%s(%d) : Determined that PEM type is %s", LOG_INF, name);

        if (strcmp(name, "CERTIFICATE") == 0) {
            log_error("%s::%s(%d) WARNING: Certificate found in keystore -- skipping", LOG_INF);
        } else if (strcmp(name, "PRIVATE KEY") == 0) {
            log_verbose("%s::%s(%d) : Entry is a private key", LOG_INF);

            // Initialize a new GNU TLS X509 structure
            log_trace("%s::%s(%d) : Initializing a new gnutls_x509_privkey_t structure", LOG_INF);
            ret = gnutls_x509_privkey_init(&key);
            if (GNUTLS_E_SUCCESS != ret) {
                log_error("%s::%s(%d) : Failed to initialize gnutls_x509_privkey_t - out of memory - response code %d", LOG_INF, ret);
                goto cleanup;
            }

            // Make a new internal structure to hold the ASCII cert and size
            pemDatum.data = (unsigned char *)pemBuf;
            pemDatum.size = pemSize;

            // Import key into new gnutls_x509_privkey_t structure
            // Note that this takes DER or PEM formatted keys
            log_trace("%s::%s(%d) : Importing private key into gnutls_x509_crt_t structure", LOG_INF);
            ret = gnutls_x509_privkey_import(key, &pemDatum, GNUTLS_X509_FMT_PEM);
            if (GNUTLS_E_SUCCESS != ret) {
                log_error("%s::%s(%d) : Failed to import private key - was it a valid private key? - response code %d", LOG_INF, ret);
                goto cleanup;
            }

            PrivKeyList_add(keyList, key);
        }  else if (strcmp(name, "ENCRYPTED PRIVATE KEY") == 0) {
            log_verbose("%s::%s(%d) : Entry is an encrypted private key", LOG_INF);

            // Initialize a new GNU TLS X509 structure
            log_trace("%s::%s(%d) : Initializing a new gnutls_x509_privkey_t structure", LOG_INF);
            ret = gnutls_x509_privkey_init(&key);
            if (GNUTLS_E_SUCCESS != ret) {
                log_error("%s::%s(%d) : Failed to initialize gnutls_x509_privkey_t - out of memory - response code %d", LOG_INF, ret);
                goto cleanup;
            }

            // Make a new internal structure to hold the ASCII cert and size
            pemDatum.data = (unsigned char *)pemBuf;
            pemDatum.size = pemSize;

            // Import key into new gnutls_x509_privkey_t structure
            // Note that this takes DER or PEM formatted keys
            log_trace("%s::%s(%d) : Importing private key into gnutls_x509_privkey_t structure", LOG_INF);
            ret = gnutls_x509_privkey_import_pkcs8(key, &pemDatum, GNUTLS_X509_FMT_PEM, password, 0);
            if (GNUTLS_E_SUCCESS != ret) {
                log_error("%s::%s(%d) : Unable to decrypt private key - response code %d", LOG_INF, ret);
                goto cleanup;
            }

            PrivKeyList_add(keyList, key);
        } else {
            log_verbose("%s::%s(%d) : Entry is not a key, and will be skipped", LOG_INF);
        }

        if (name)
            free(name);
        pemSize = 0;
    }

    cleanup:
    if (fp)
        fclose(fp);
    if (pemBuf)
        free(pemBuf);
    return ret;
} // get_key_inventory

/**                                                                           */
/* Read the inventory of certificates and keys located at path.               */
/* This function always populates PemInventoryList.  However, it can also     */
/* return the PEMx509List and the PrivKeyList.  The latter two assist in      */
/* key management functions.                                                  */
/*                                                                            */
/* @param  - [Input] : path = the store location                              */
/* @param  - [Input] : password = the password for private keys               */
/* @param  - [Output]: pPemList = the PemInventory                            */
/* @param  - [Output]: (optional) pPemArray = the X509 cert array which is    */
/*                     mapped 1:1 with the pPemList. The latter only contains */
/*                     the ASCII representation of the cert.                  */
/* @param  - [Input] : returnX509array =                                      */
/*                     true if you want the array passed back via pPemArray   */
/*                      NOTE: This means the calling function must dispose    */
/*                            of the allocated memory                         */
/*                     false disposes of the array here                       */
/* @param  - [Output]: (optional) pKeyArray = the list of private keys in the */
/*											  store                           */
/* @param  - [Input] : returnKeyArray =                                       */
/*                     true if you want the array passed back via pKeyArray   */
/*                       NOTE: This means the calling function must dispose   */
/*                             of the allocated memory                        */
/*                     false disposes of the array here                       */
/* @return - success = 0                                                      */
/*         - failure = any other integer                                      */
/*                                                                            */
static int get_inventory(const char* path,
                         const char* password,
                         PemInventoryList** pPemList,
                         PEMx509List** pPemArray,
                         const bool returnX509array,
                         PrivKeyList** pKeyArray,
                         const bool returnKeyArray) {
    int res = -1;
    FILE* fp = NULL;
    char *pemBuf = NULL;
    //char buf[PEM_BUF_SIZE];
    char * buf;
    char * name;
    int i = 0;
    gnutls_x509_crt_t cert;
    gnutls_x509_privkey_t key;
    gnutls_datum_t pemDatum;

    fp = fopen(path, "r");
    if (NULL == fp) {
        log_error("%s::%s(%d) : Failed to open file at path %s", LOG_INF, path);
        goto cleanup;
    }

    pemBuf = calloc(0, sizeof(char));
    if (!pemBuf) {
        log_error("%s::%s(%d) : Out of memory", LOG_INF);
        res = -1;
        goto cleanup;
    }

    buf = calloc(PEM_BUF_SIZE, sizeof(char));
    /* Create the inventory list to share with the agent */
    *pPemList = PemInventoryList_new();

    PEMx509List* x509array = PEMx509List_new();
    /* Also create an array to store keys into */
    PrivKeyList* keyList = PrivKeyList_new();

    if ( (NULL == (*pPemList)) || \
		 (NULL == x509array) || \
		 (NULL == keyList) )
    {
        log_error("%s::%s(%d) : Out of memory",
                  LOG_INF);
        res = -1;
        goto cleanup;
    }

    PemInventoryItem* pem = NULL;

    log_debug("%s::%s(%d) : Starting inventory", LOG_INF);

    size_t pemSize = 0;
    while ((pemBuf = PEM_read(fp, &pemBuf, &pemSize)) != NULL) {
        log_debug("%s::%s(%d) : Found PEM block with size %zu", LOG_INF, pemSize);

        pem = NULL;
        cert = NULL;
        key = NULL;

        pemDatum.data = NULL;
        pemDatum.size = 0;

        if (strncmp(pemBuf,"-----BEGIN ",11) != 0) {
            log_error("%s::%s(%d) : '-----BEGIN' not found", LOG_INF);
            return -1;
        }
        // Trim off the ends of pem (anything less than ASCII 32) and reformat with newline and null character
        while ((pemSize >= 0) && (pemBuf[pemSize] <= ' ')) pemSize--;
        pemBuf[++pemSize]='\n';
        pemBuf[++pemSize]='\0';

        log_trace("%s::%s(%d) : Cleaned up PEM object", LOG_INF);

        // Find index of '-----\n'

        for (i = 11; i < pemSize; i++) {
            if (strncmp(&(pemBuf[i]), "-----\n", 5) == 0)
                break;
        }
        if (i == 1 - pemSize) {
            log_error("%s::%s(%d) : Didn't find '-----\\n' after '-----BEGIN '.", LOG_INF);
            goto cleanup;
        }

        name = calloc(i - 11, sizeof(char));
        name = strncpy(name, &(pemBuf[11]), i - 11);

        log_trace("%s::%s(%d) : Determined that PEM type is %s", LOG_INF, name);

        if (strcmp(name, "CERTIFICATE") == 0) {

            // Initialize a new GNU TLS X509 structure
            log_trace("%s::%s(%d) : Initializing a new gnutls_x509_crt_t structure", LOG_INF);
            res = gnutls_x509_crt_init(&cert);
            if (GNUTLS_E_SUCCESS != res) {
                log_error("%s::%s(%d) : Failed to initialize gnutls_x509_crt_t - out of memory - response code %d", LOG_INF, res);
                goto cleanup;
            }

            // Make a new internal structure to hold the ASCII cert and size
            pemDatum.data = (unsigned char *)pemBuf;
            pemDatum.size = pemSize;

            // Import certificate into new gnutls_x509_crt_t structure
            // Note that this takes DER or PEM formatted certificates (IE CERTIFICATE or not)
            log_trace("%s::%s(%d) : Importing certificate into gnutls_x509_crt_t structure", LOG_INF);
            res = gnutls_x509_crt_import(cert, &pemDatum, GNUTLS_X509_FMT_PEM);
            if (GNUTLS_E_SUCCESS != res) {
                log_error("%s::%s(%d) : Failed to import X509 certificate - was it a valid certificate? - response code %d", LOG_INF, res);
                goto cleanup;
            }

            pem = PemInventoryItem_new();
            if ( PemInventoryItem_populate(pem, cert) ) {
                PemInventoryList_add(*pPemList, pem);
                PEMx509List_add(x509array, cert);
            }
            else {
                log_error("%s::%s(%d) Not adding cert to list of certs in store", LOG_INF);
            }
        } else if (strcmp(name, "PRIVATE KEY") == 0) {
            // Initialize a new GNU TLS X509 structure
            log_trace("%s::%s(%d) : Initializing a new gnutls_x509_privkey_t structure", LOG_INF);
            res = gnutls_x509_privkey_init(&key);
            if (GNUTLS_E_SUCCESS != res) {
                log_error("%s::%s(%d) : Failed to initialize gnutls_x509_privkey_t - out of memory - response code %d", LOG_INF, res);
                goto cleanup;
            }

            // Make a new internal structure to hold the ASCII cert and size
            pemDatum.data = (unsigned char *)pemBuf;
            pemDatum.size = pemSize;

            // Import key into new gnutls_x509_privkey_t structure
            // Note that this takes DER or PEM formatted keys
            log_trace("%s::%s(%d) : Importing private key into gnutls_x509_crt_t structure", LOG_INF);
            res = gnutls_x509_privkey_import(key, &pemDatum, GNUTLS_X509_FMT_PEM);
            if (GNUTLS_E_SUCCESS != res) {
                log_error("%s::%s(%d) : Failed to import private key - was it a valid private key? - response code %d", LOG_INF, res);
                goto cleanup;
            }

            PrivKeyList_add(keyList, key);
        }  else if (strcmp(name, "ENCRYPTED PRIVATE KEY") == 0) {
            // Initialize a new GNU TLS X509 structure
            log_trace("%s::%s(%d) : Initializing a new gnutls_x509_privkey_t structure", LOG_INF);
            res = gnutls_x509_privkey_init(&key);
            if (GNUTLS_E_SUCCESS != res) {
                log_error("%s::%s(%d) : Failed to initialize gnutls_x509_privkey_t - out of memory - response code %d", LOG_INF, res);
                goto cleanup;
            }

            // Make a new internal structure to hold the ASCII cert and size
            pemDatum.data = (unsigned char *)pemBuf;
            pemDatum.size = pemSize;

            // Import key into new gnutls_x509_privkey_t structure
            // Note that this takes DER or PEM formatted keys
            log_trace("%s::%s(%d) : Importing private key into gnutls_x509_privkey_t structure", LOG_INF);
            res = gnutls_x509_privkey_import_pkcs8(key, &pemDatum, GNUTLS_X509_FMT_PEM, password, 0);
            if (GNUTLS_E_SUCCESS != res) {
                log_error("%s::%s(%d) : Unable to decrypt private key - response code %d", LOG_INF, res);
                goto cleanup;
            }

            PrivKeyList_add(keyList, key);
        }
        if (name)
            free(name);
        pemSize = 0;
    }

    log_verbose("%s::%s(%d) : %d items in PEM list", LOG_INF,
                (*pPemList)->item_count);
    if ((*pPemList)->item_count > 0) {
        log_verbose("%s::%s(%d) : Checking for matching private keys", LOG_INF);
        for(int i = 0; i < (*pPemList)->item_count; ++i)
        {
            log_verbose("%s::%s(%d) : Thumbprint: %s", LOG_INF,
                        (*pPemList)->items[i]->thumbprint_string);

            for(int k = 0; k < keyList->key_count; ++k)
            {
                /* Use the x509array to grab the X509 certificate associated with */
                /* the (*pPemList)->items[i]->cert.  Since *pPemList has the cert */
                /* stored as an ASCII encoded string instead of an X509 cert.     */
                /*                                                                */
                /* Remember, the x509array is a 1:1 match with the items array    */
                /* in the *pPemList.                                              */
                /*                                                                */
                if(is_cert_key_match(x509array->certs[i], keyList->keys[k]))
                {
                    log_verbose("%s::%s(%d) : Found matching cert and private key",
                                LOG_INF);
                    (*pPemList)->items[i]->has_private_key = true;
                }
            }
        }
    }

    cleanup:

    if ( x509array )
    {
        if ( !returnX509array || (0 != res) )
        {
            log_trace("%s::%s(%d) : Freeing x509array", LOG_INF);
            // We no longer need the X509 cert versions
            PEMx509List_free(x509array);
        }
        else
        {
            (*pPemArray) = x509array; // Return the array
        }
        x509array = NULL;
    }
    if ( *pPemList && (0 != res) )
    {
        log_trace("%s::%s(%d) : Freeing *pPemList", LOG_INF);
        PemInventoryList_free(*pPemList);
        *pPemList = NULL;
    }
    if ( keyList )
    {
        if ( !returnKeyArray )
        {
            log_trace("%s::%s(%d) : Freeing keyList", LOG_INF);
            PrivKeyList_free(keyList);
        }
        else
        {
            (*pKeyArray) = keyList;

        }
        keyList = NULL;
    }

    if (pemBuf) free(pemBuf);
    if (buf) free(buf);
    fclose(fp);

    return 0;
} // get_inventory

/******************************************************************************/
/*********************** GLOBAL FUNCTION DEFINITIONS **************************/
/******************************************************************************/

void PemInventoryItem_free(PemInventoryItem* pem) {

}

void PemInventoryList_free(PemInventoryList* list) {

}

int ssl_seed_rng(const char* b64entropy) {
    return 0;
}

bool ssl_generate_rsa_keypair(int keySize) {
    bool bResult = false;
    log_trace("%s::%s(%d) : Generating RSA keypair", LOG_INF);

    if (GNUTLS_E_SUCCESS != gnutls_privkey_init(&newPrivKey)) {
        log_error("%s::%s(%d) : Failed to initialize private key", LOG_INF);
        return NULL;
    }

    // Generate new RSA private key pair with specified size, and force
    // prime generation to be provable. Uses algorithms like Shawe-Taylor from FIPS PUB186-4
    log_trace("%s::%s(%d) : Attempting to generate new priv key with forced provable primes in accordance with FIPS"
              "PUB186-4", LOG_INF);
    if (GNUTLS_E_SUCCESS != gnutls_privkey_generate(newPrivKey, GNUTLS_PK_RSA, keySize, GNUTLS_PRIVKEY_FLAG_PROVABLE)) {
        log_error("%s::%s(%d) : Failed to generate new private key", LOG_INF);
        bResult = false;
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully generated %d-bit RSA key", LOG_INF, keySize);
        return true;
    }

    exit:

    gnutls_privkey_deinit(newPrivKey);
    return bResult;
}

bool ssl_generate_ecc_keypair(int keySize) {
    bool bResult = false;
    log_trace("%s::%s(%d) : Generating ECC keypair", LOG_INF);

    if (GNUTLS_E_SUCCESS != gnutls_privkey_init(&newPrivKey)) {
        log_error("%s::%s(%d) : Failed to initialize private key", LOG_INF);
        return NULL;
    }

    /* Match the inputted key length to the associated curve */
    /* More ECC macros: https://gnutls.org/reference/gnutls-gnutls.html#gnutls-ecc-curve-t */
    gnutls_ecc_curve_t curve;
    switch(keySize) {
        case 256:
            curve = GNUTLS_ECC_CURVE_SECP256R1;
            break;
        case 384:
            curve = GNUTLS_ECC_CURVE_SECP384R1;
            break;
        case 521:
            curve = GNUTLS_ECC_CURVE_SECP521R1;
            break;
        default:
            curve = GNUTLS_ECC_CURVE_SECP256R1;
            log_error("%s::%s(%d) : Invalid ECC key length: %d. Falling "
                      "back to default curve", LOG_INF, keySize);
            break;
    }
    log_trace("%s::%s(%d) : Setting ECC curve to %s", LOG_INF, gnutls_ecc_curve_get_name(curve));

    // Generate new RSA private key pair with specified size, and force
    // prime generation to be provable. Uses algorithms like Shawe-Taylor from FIPS PUB186-4
    log_trace("%s::%s(%d) : Attempting to generate new ECC priv key", LOG_INF);
    /* To generate ECC key, substitute the bits field with the GNUTLS_CURVE_TO_BITS() macro */
    /* Complete list of algorithms found here https://gnutls.org/reference/gnutls-gnutls.html#gnutls-pk-algorithm-t */
    if (GNUTLS_E_SUCCESS != gnutls_privkey_generate(newPrivKey, GNUTLS_PK_ECDSA, GNUTLS_CURVE_TO_BITS(curve), 0)) {
        log_error("%s::%s(%d) : Failed to generate new ECC private key", LOG_INF);
        bResult = false;
        goto exit;
    } else {
        log_trace("%s::%s(%d) : Successfully generated ECC key with curve %s", LOG_INF, gnutls_ecc_curve_get_name(curve));
        return true;
    }

    exit:

    gnutls_privkey_deinit(newPrivKey);
    return bResult;
}

char* ssl_generate_csr(const char* asciiSubject, size_t* csrLen, char** pMessage) {
    int response;
    gnutls_x509_crq_t crq;
    gnutls_x509_privkey_t x509Privkey = NULL;
    size_t reqBytesSize = 0;
    const char * fail_msg;
    unsigned char * reqBytes = NULL;

    /*************************************************************************/
    /* 1.) Set up the CSR as a new x509 request by creating a blank request  */
    /*     then adding in the public key, setting the subject, and signing   */
    /*     it with the private key.                                          */
    /*************************************************************************/

    // Initialize the certificate request
    log_trace("%s::%s(%d) : Initializing a certificate request", LOG_INF);
    response = gnutls_x509_crq_init(&crq);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to initialize certificate request - out of memory";
        goto csr_fail;
    }

    response = gnutls_x509_crq_set_version (crq, 1);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to set certificate request version";
        goto csr_fail;
    }

    log_trace("%s::%s(%d) : Adding subject %s to certificate request", LOG_INF, asciiSubject);
    /* Use local set_subject function to set req subject values */
    response = set_subject(asciiSubject, &crq);
    if (0 != response) {
        fail_msg = "Failed to set certificate request subject";
        goto csr_fail;
    }

    /* Export gnutls_privkey_t to gnutls_x509_privkey_t for attachment to CSR */
    log_trace("%s::%s(%d) : Attempting to export priv key to X509 format", LOG_INF);
    // x509 structure must be uninitialized to export private key to this structure. Force de-init to make sure
    gnutls_x509_privkey_deinit(x509Privkey); // No return here
    response = gnutls_privkey_export_x509(newPrivKey, &x509Privkey);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to export private key to X509 format";
        goto csr_fail;
    }

    /* Associate certificate request with private key */
    log_trace("%s::%s(%d) : Setting certificate request key", LOG_INF);
    response = gnutls_x509_crq_set_key(crq, x509Privkey);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to set key pair for REQ";
        goto csr_fail;
    }

    /* Self-sign CSR with x509Privkey */
    log_trace("%s::%s(%d) : Signing certificate request with private key", LOG_INF);
    response = gnutls_x509_crq_sign(crq, x509Privkey);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to sign certificate REQ";
        goto csr_fail;
    }

    /*************************************************************************/
    /* 2.) Take the resulting REQ, encode it and convert it to a             */
    /*     string; the result is a PEM with the BEGIN CERTIFICATE REQUEST    */
    /*     and END CERTIFICATE REQUEST                                       */
    /*************************************************************************/

    /* Ask for heap memory for CSR PEM */
    log_trace("%s::%s(%d) : Allocating %zu bytes for certificate request", LOG_INF, reqBytesSize);
    reqBytes = calloc(MAX_CRQ_BUFFER_SIZE, sizeof(*reqBytes));
    reqBytesSize = sizeof(*reqBytes) * MAX_CRQ_BUFFER_SIZE;
    if (!reqBytes) {
        response = -1;
        fail_msg = "Failed to allocate memory for CSR PEM digest";
        goto csr_fail;
    }

    /* Export CRQ to PEM format and fill reqBytes buffer */
    log_trace("%s::%s(%d) : Exporting certificate request to PEM format", LOG_INF);
    response = gnutls_x509_crq_export (crq, GNUTLS_X509_FMT_PEM, reqBytes, &reqBytesSize);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to export CRQ";
        goto csr_fail;
    }

    // Todo figure out if I need to encode this to base64

    *csrLen = reqBytesSize;

    if (crq) gnutls_x509_crq_deinit(crq);
    return (char *)reqBytes;

    csr_fail:
    log_error("%s::%s(%d) : %s - response code %d", LOG_INF, fail_msg, response);
    append_linef(pMessage, "%s::%s(%d) : %s - response code %d", LOG_INF, fail_msg, response);
    gnutls_x509_crq_deinit(crq);
    return NULL;
}

unsigned long ssl_save_cert_key(const char* storePath, const char* keyPath,
                                const char* password, const char* cert, char** pMessage) {
    return 0;
}

/**                                                                           */
/* Read all of the certificates inside of the store at the path requested.    */
/* Convert each of these into a PemInventoryItem & add it into the variable   */
/* provided.                                                                  */
/*                                                                            */
/* @param  - [Input]  : path = the path to the store (or the id of the store)  */
/* @param  - [Input]  : password = the password of private keys in the store   */
/* @param  - [Output] : pPemList an array to hold the inventory               */
/*                     (SEND IN A NULL VARIABLE - we create the list in the   */
/*                      wrapper)                                              */
/* @return - success : 0                                                      */
/*		   - failure : the error code from opening the file or such           */
/*                                                                            */
int ssl_read_store_inventory(const char* path, const char* password,
                             PemInventoryList** pPemList) {
    return get_inventory(path, password, pPemList, NULL, false, NULL, false);
}

/**                                                                           */
/* Create a PemInventoryItem (with has_private_key set to false) from an      */
/* ASCII cert.  Verify the cert is valid & compute its thumbprint.            */
/*                                                                            */
/* NOTE: The PemInventoryItem must be freed by the calling function by        */
/*       invoking PemInventoryItem_free(pem);                                 */
/*                                                                            */
/* @param  - [Output] : pem = the variable which points to the new item       */
/* @param  - [Input] : certASCII = the b64 encoded NULL terminated certificate*/
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_PemInventoryItem_create(struct PemInventoryItem** pem,
                                 const char* certASCII) {

    return false;
}

/**                                                                           */
/* Append the certificate provided to the store.                              */
/*                                                                            */
/* @param  - [Input] : storePath = where to find the store                    */
/* @param  - [Input] : certASCII = the b64 encoded PEM string of the cert     */
/* @return - success : true                                                   */
/*         - failure : false                                                  */
/*                                                                            */
bool ssl_Store_Cert_add(const char* storePath, const char* certASCII) {
    int response;
    bool bResult = false;
    char * fail_msg = NULL;
    size_t certLen;
    gnutls_x509_crt_t cert;

    log_trace("%s::%s(%d) : Safely getting size of certASCII", LOG_INF);
    certLen = strnlen(certASCII, MAX_X509_CERT_SIZE);

    log_trace("%s::%s(%d) : certASCII is %zu bytes long", LOG_INF, certLen);

    // Initialize a new GNU TLS X509 structure
    log_trace("%s::%s(%d) : Initializing a new gnutls_x509_crt_t structure", LOG_INF);
    response = gnutls_x509_crt_init(&cert);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to initialize certificate request - out of memory";
        log_error("%s::%s(%d) : %s - response code %d", LOG_INF, fail_msg, response);
        return false;
    }

    // Make a new internal structure to hold the ASCII cert and size
    gnutls_datum_t certDataDatum;
    certDataDatum.data = (unsigned char *)certASCII;
    certDataDatum.size = certLen;

    // Import certificate into new gnutls_x509_crt_t structure
    // Note that this takes DER or PEM formatted certificates (IE CERTIFICATE or not)
    log_trace("%s::%s(%d) : Importing certificate into gnutls_x509_crt_t structure", LOG_INF);
    response = gnutls_x509_crt_import(cert, &certDataDatum, GNUTLS_X509_FMT_PEM);
    if (GNUTLS_E_SUCCESS != response) {
        fail_msg = "Failed to import X509 certificate - was it a valid certificate?";
        goto fail;
    }

    response = backup_file(storePath);
    if(response != 0 && response != ENOENT)
    {
        char* errStr = strerror(response);
        log_error("%s::%s(%d) : Unable to backup store at %s: %s\n",
                  LOG_INF, storePath, errStr);
    }

    response = store_append_cert(storePath, cert);
    if (0 != response) {
        fail_msg = "Failed to append certificate to certificate store";
        goto fail;
    }

    log_trace("%s::%s(%d) : De-initializing gnutls_x509_crt_t structure", LOG_INF);
    gnutls_x509_crt_deinit(cert);

    return true;

    fail:
    log_error("%s::%s(%d) : %s - response code %d", LOG_INF, fail_msg, response);
    gnutls_x509_crt_deinit(cert);
    return NULL;
}

/**                                                                           */
/* Remove a cert (and associated key) from a store/keystore                   */
/*                                                                            */
/* @param  - [Input] : storePath = the path for the certificate store         */
/* @param  - [Input] : searchThumb = the sha1 hash of the cert to remove      */
/* @param  - [Input] : keyPath = the path of the keystore.                    */
/*                     if NULL an use storePath                               */
/* @param  - [Input] : password = password for any encrypted keys             */
/* @return - success : true                                                   */
/*           failure : false                                                  */
/*                                                                            */
bool ssl_remove_cert_from_store(const char* storePath, const char* searchThumb,
                                const char* keyPath, const char* password)
{
    bool ret = false;
    PemInventoryList* pemList = NULL;
    PEMx509List* pemX509Array = NULL;
    PrivKeyList* keyArray = NULL;
    gnutls_datum_t datum;
    bool certFound = false;
    unsigned char * buf = NULL;
    size_t size = 0;
    int i = 0;

    log_trace("%s::%s(%d) : Get PEM inventory", LOG_INF);

    // First, try to get PEM inventory. If we fail, clean up returned structures since get_inventory doesn't
    // guarantee that structures are freed when it fails.
    if (0 != get_inventory(storePath, password, &pemList, &pemX509Array, true, &keyArray, true)) {
        if (pemList) {
            PemInventoryList_free(pemList);
            pemList = NULL;
        }
        if ( pemX509Array ) {
            PEMx509List_free(pemX509Array);
            pemX509Array = NULL;
        }
        if ( keyArray ) {
            PrivKeyList_free(keyArray);
            keyArray = NULL;
        }
        log_error("%s::%s(%d) : Failed to get inventory", LOG_INF);
        return false;
    }

    // Next, search for the certificate by SHA1 hash (thumbprint)
    log_trace("%s::%s(%d) : Search for matching hash to remove from inventory", LOG_INF);
    i = pemList->item_count-1;
    while ( !certFound && 0 <= i) {
        char * compare = pemList->items[i]->thumbprint_string;
        log_trace("%s::%s(%d) : Comparing certificate %d with thumbprint %s to %s", LOG_INF, i, compare, searchThumb);
        if (0 == strcasecmp(searchThumb, compare))
        {
            certFound = true;
        }
        else
        {
            i--;
        }
    }
    log_verbose("%s::%s(%d) : %s", LOG_INF, certFound ? "Found matching cert" : "Did not find matching cert");

    // Update the store if and only if the certificate was found
    if (!certFound)
        goto cleanup;
    log_trace("%s::%s(%d) : Writing certs to store", LOG_INF);
    // Recall that 'i' points to the pemList and PEMx509List entry of the cert to remove

    int pairListSize = pemList->item_count-1;

    // Clear file contents
    if (0 != clear_file(storePath, true))
        goto cleanup;

    // Add all certificates and keys to the store from certificate inventory to file.
    for (int j = 0; pemList->item_count > j; j++) {
        if (i != j) {
            datum.data = (unsigned char *)pemList->items[j]->cert;
            datum.size = strlen(pemList->items[j]->cert);
            if (0 != save_datum_to_file(datum, storePath)) {
                log_error("%s::%s(%d) : Failed to add cert to store %s", LOG_INF, storePath);
                goto cleanup;
            }
        }
    }

    // Next, find all private keys and add these to the store too.
    for (int k = 0; k < keyArray->key_count; k++) {
        if (!is_cert_key_match(pemX509Array->certs[i], keyArray->keys[k])) {
            // If the key doesn't match the certificate we're removing, export it as a PEM encoded
            // PKCS#8 key. If a password was provided, encrypt the key using AES256 symmetric encryption.

            // Get the size of the private key in PEM format
            if (password && strcmp(password, "") != 0) {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[k], GNUTLS_X509_FMT_PEM, password, GNUTLS_PKCS_PBES2_AES_256, NULL, &size) != GNUTLS_E_SHORT_MEMORY_BUFFER) {
                    log_error("%s::%s(%d) : Failed to get size of private key", LOG_INF);
                    goto cleanup;
                }
            } else {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[k], GNUTLS_X509_FMT_PEM, "", GNUTLS_PKCS_PLAIN, NULL, &size) != GNUTLS_E_SHORT_MEMORY_BUFFER) {
                    log_error("%s::%s(%d) : Failed to get size of private key", LOG_INF);
                    goto cleanup;
                }
            }

            // Allocate memory to store the key
            buf = (unsigned char*)calloc(size, sizeof(unsigned char));
            if (!buf) {
                log_error("%s::%s(%d) : Failed to allocate memory for private key", LOG_INF);
                goto cleanup;
            }

            // Export the private key.
            if (password && strcmp(password, "") != 0) {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[k], GNUTLS_X509_FMT_PEM, password, GNUTLS_PKCS_PBES2_AES_256, buf, &size) != GNUTLS_E_SUCCESS) {
                    log_error("%s::%s(%d) : Failed to export private key.", LOG_INF);
                    goto cleanup;
                }
            } else {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[k], GNUTLS_X509_FMT_PEM,"", GNUTLS_PKCS_PLAIN, buf, &size) != GNUTLS_E_SUCCESS) {
                    log_error("%s::%s(%d) : Failed to export private key.", LOG_INF);
                    goto cleanup;
                }
            }

            datum.data = buf;
            datum.size = size;

            if (0 != save_datum_to_file(datum, storePath)) {
                log_error("%s::%s(%d) : Failed to write private key to file.", LOG_INF);
                goto cleanup;
            }

            if (buf)
                free(buf);
        }
    }

    // Optional: If a keystore was provided, remove the key from the keystore.
    if (keyPath) {
        // Clear file contents
        if (0 != clear_file(keyPath, true))
            goto cleanup;

        if ( keyArray )
        {
            PrivKeyList_free(keyArray); /* Free this bit of keys */
        }

        // And populate it with the keystore located at keyPath

        ret = get_key_inventory(keyPath, password, &keyArray);
        if (0 != ret) {
            log_error("%s::%s(%d) : Failed to get key inventory at %s", LOG_INF, keyPath);
            goto cleanup;
        }

        for (int j = 0; j < keyArray->key_count; j++) {
            // Get the size of the private key in PEM format
            if (password && strcmp(password, "") != 0) {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[j], GNUTLS_X509_FMT_PEM, password, GNUTLS_PKCS_PBES2_AES_256, NULL, &size) != GNUTLS_E_SHORT_MEMORY_BUFFER) {
                    log_error("%s::%s(%d) : Failed to get size of private key", LOG_INF);
                    goto cleanup;
                }
            } else {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[j], GNUTLS_X509_FMT_PEM, "", GNUTLS_PKCS_PLAIN, NULL, &size) != GNUTLS_E_SHORT_MEMORY_BUFFER) {
                    log_error("%s::%s(%d) : Failed to get size of private key", LOG_INF);
                    goto cleanup;
                }
            }

            // Allocate memory to store the key
            buf = (unsigned char*)calloc(size, sizeof(unsigned char));
            if (!buf) {
                log_error("%s::%s(%d) : Failed to allocate memory for private key", LOG_INF);
                goto cleanup;
            }

            // Export the private key.
            if (password && strcmp(password, "") != 0) {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[j], GNUTLS_X509_FMT_PEM, password, GNUTLS_PKCS_PBES2_AES_256, buf, &size) != GNUTLS_E_SUCCESS) {
                    log_error("%s::%s(%d) : Failed to export private key.", LOG_INF);
                    goto cleanup;
                }
            } else {
                if (gnutls_x509_privkey_export_pkcs8(keyArray->keys[j], GNUTLS_X509_FMT_PEM,"", GNUTLS_PKCS_PLAIN, buf, &size) != GNUTLS_E_SUCCESS) {
                    log_error("%s::%s(%d) : Failed to export private key.", LOG_INF);
                    goto cleanup;
                }
            }

            datum.data = buf;
            datum.size = size;

            if (0 != save_datum_to_file(datum, keyPath)) {
                log_error("%s::%s(%d) : Failed to write private key to file.", LOG_INF);
                goto cleanup;
            }

            if (buf)
                free(buf);
        }
    }

    cleanup:
    if ( pemList )
    {
        PemInventoryList_free(pemList);
        pemList = NULL;
    }
    if ( pemX509Array )
    {
        PEMx509List_free(pemX509Array);
        pemX509Array = NULL;
    }
    if ( keyArray )
    {
        PrivKeyList_free(keyArray);
        keyArray = NULL;
    }
    if (buf)
        free(buf);

    return ret;
}

void ssl_init(void) {
    const char * version;
    if (NULL == (version = gnutls_check_version(MIN_GNUTLS_VERSION))) {
        log_error("%s::%s(%d) : Check that the proper GNU TLS version is installed (version >= %s). Found version %s", LOG_INF, MIN_GNUTLS_VERSION, gnutls_check_version(NULL));
        assert("invalid gnutls version");
    }
    log_trace("%s::%s(%d) : Initializing GNU TLS version %s", LOG_INF, version);
    // todo figure out if this entails configuring a client or server service
    gnutls_global_init();
}

void ssl_cleanup(void) {
    if (newPrivKey) {gnutls_privkey_deinit(newPrivKey);}
    gnutls_global_deinit();
}

/******************************************************************************/
/******************************* END OF FILE **********************************/
/******************************************************************************/