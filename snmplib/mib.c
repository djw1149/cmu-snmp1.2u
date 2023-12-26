#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/snmplib/mib.c,v 1.5 1996/11/14 15:29:42 tpt2 Exp $";
#endif

/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "parse.h"

static void sprint_by_type();

static char *
uptimeString(timeticks, buf)
    register u_long timeticks;
    char *buf;
{
    int	seconds, minutes, hours, days;

    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (days == 0){
	sprintf(buf, "%d:%02d:%02d", hours, minutes, seconds);
    } else if (days == 1) {
	sprintf(buf, "%d day, %d:%02d:%02d", days, hours, minutes, seconds);
    } else {
	sprintf(buf, "%d days, %d:%02d:%02d", days, hours, minutes, seconds);
    }
    return buf;
}

static sprint_hexstring(buf, cp, len)
    char *buf;
    u_char  *cp;
    int	    len;
{

    for(; len >= 16; len -= 16){
	sprintf(buf, "%02X %02X %02X %02X %02X %02X %02X %02X ", cp[0], cp[1],
cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
	sprintf(buf, "%02X %02X %02X %02X %02X %02X %02X %02X\n", cp[0],
cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
    }
    for(; len > 0; len--){
	sprintf(buf, "%02X ", *cp++);
	buf += strlen(buf);
    }
    *buf = '\0';
}

static sprint_asciistring(buf, cp, len)
    char *buf;
    u_char  *cp;
    int	    len;
{
    int	x;

    for(x = 0; x < len; x++){
	if (isprint(*cp)){
	    *buf++ = *cp++;
	} else {
	    *buf++ = '.';
	    cp++;
	}
#if 0
	if ((x % 48) == 47)
	    *buf++ = '\n';
#endif
    }
    *buf = '\0';
}

#ifdef UNUSED
int
read_rawobjid(input, output, out_len)
    char *input;
    oid *output;
    int	*out_len;
{
    char    buf[12], *cp;
    oid	    *op = output;
    u_long  subid;

    while(*input != '\0'){
	if (!isdigit(*input))
	    break;
	cp = buf;
	while(isdigit(*input))
	    *cp++ = *input++;
	*cp = '\0';
	subid = atoi(buf);
	if(subid > MAX_SUBID){
	    fprintf(stderr, "sub-identifier too large: %s\n", buf);
	    return 0;
	}
	if((*out_len)-- <= 0){
	    fprintf(stderr, "object identifier too long\n");
	    return 0;
	}
	*op++ = subid;
	if(*input++ != '.')
	    break;
    }
    *out_len = op - output;
    if (*out_len == 0)
	return 0;
    return 1;
}

#endif /* UNUSED */

/*ARGSUSED*/
static void
sprint_octet_string(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    int hex, x;
    u_char *cp;

    if (var->type != ASN_OCTET_STR){
	sprintf(buf, "Wrong Type (should be OCTET STRING): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    hex = 0;
    for(cp = var->val.string, x = 0; x < var->val_len; x++, cp++){
	if (!(isprint(*cp) || isspace(*cp)))
	    hex = 1;
    }
    if (var->val_len <= 4)
	hex = 1;    /* not likely to be ascii */
    if (hex){
	sprintf(buf, "OCTET STRING-   (hex):\t");
	buf += strlen(buf);
	sprint_hexstring(buf, var->val.string, var->val_len);
    } else {
	sprintf(buf, "OCTET STRING- (ascii):\t");
	buf += strlen(buf);
	sprint_asciistring(buf, var->val.string, var->val_len);
    }
}

/*ARGSUSED*/
static void
sprint_opaque(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{

    if (var->type != OPAQUE){
	sprintf(buf, "Wrong Type (should be Opaque): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    sprintf(buf, "OPAQUE -   (hex):\t");
    buf += strlen(buf);
    sprint_hexstring(buf, var->val.string, var->val_len);
}

/*ARGSUSED*/
static void
sprint_object_identifier(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    if (var->type != ASN_OBJECT_ID){
	sprintf(buf, "Wrong Type (should be OBJECT IDENTIFIER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    sprintf(buf, "OBJECT IDENTIFIER:\t");
    buf += strlen(buf);
    sprint_objid(buf, (oid *)(var->val.objid), var->val_len / sizeof(oid));
}

/*ARGSUSED*/
static void
sprint_timeticks(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    char timebuf[32];

    if (var->type != TIMETICKS){
	sprintf(buf, "Wrong Type (should be Timeticks): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    sprintf(buf, "Timeticks: (%d) %s", *(u_long *)(var->val.integer),
uptimeString(*(u_long *)(var->val.integer), timebuf));
}

static void
sprint_integer(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    char    *enum_string = NULL;

    if (var->type != ASN_INTEGER){
	sprintf(buf, "Wrong Type (should be INTEGER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    for (; enums; enums = enums->next)
	if (enums->value == *var->val.integer){
	    enum_string = enums->label;
	    break;
	}
    if (enum_string == NULL)
	sprintf(buf, "INTEGER: %d", *var->val.integer);
    else
	sprintf(buf, "INTEGER: %s(%d)", enum_string, *var->val.integer);
}

/*ARGSUSED*/
static void
sprint_gauge(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    if (var->type != GAUGE){
	sprintf(buf, "Wrong Type (should be Gauge): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    sprintf(buf, "Gauge: %lu", *var->val.integer);
}

/*ARGSUSED*/
static void
sprint_counter(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    if (var->type != COUNTER){
	sprintf(buf, "Wrong Type (should be Counter): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    sprintf(buf, "Counter: %lu", *var->val.integer);
}

/*ARGSUSED*/
static void
sprint_networkaddress(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    int x, len;
    u_char *cp;

    sprintf(buf, "Network Address:\t");
    buf += strlen(buf);
    cp = var->val.string;    
    len = var->val_len;
    for(x = 0; x < len; x++){
	sprintf(buf, "%02X", *cp++);
	buf += strlen(buf);
	if (x < (len - 1))
	    *buf++ = ':';
    }
}

/*ARGSUSED*/
static void
sprint_ipaddress(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    u_char *ip;

    if (var->type != IPADDRESS){
	sprintf(buf, "Wrong Type (should be Ipaddress): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    ip = var->val.string;
    sprintf(buf, "IpAddress:\t%d.%d.%d.%d",ip[0], ip[1], ip[2], ip[3]);
}

#ifdef notdef
/*ARGSUSED*/
static void
sprint_unsigned_short(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    if (var->type != ASN_INTEGER){
	sprintf(buf, "Wrong Type (should be INTEGER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    sprintf(buf, "INTEGER (0..65535): %lu", *var->val.integer);
}
#endif /* notdef */

/*ARGSUSED*/
static void
sprint_null(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    if (var->type != ASN_NULL){
	sprintf(buf, "Wrong Type (should be NULL): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, (struct enum_list *)NULL);
	return;
    }
    sprintf(buf, "NULL");
}

/*ARGSUSED*/
static void
sprint_unknowntype(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
/*    sprintf(buf, "Variable has bad type"); */
    sprint_by_type(buf, var, NULL);
}

/*ARGSUSED*/
static void
sprint_badtype(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    sprintf(buf, "Variable has bad type");
}

static void
sprint_by_type(buf, var, enums)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
{
    switch (var->type){
	case ASN_INTEGER:
	    sprint_integer(buf, var, enums);
	    break;
	case ASN_OCTET_STR:
	    sprint_octet_string(buf, var, enums);
	    break;
	case OPAQUE:
	    sprint_opaque(buf, var, enums);
	    break;
	case ASN_OBJECT_ID:
	    sprint_object_identifier(buf, var, enums);
	    break;
	case TIMETICKS:
	    sprint_timeticks(buf, var, enums);
	    break;
	case GAUGE:
	    sprint_gauge(buf, var, enums);
	    break;
	case COUNTER:
	    sprint_counter(buf, var, enums);
	    break;
	case IPADDRESS:
	    sprint_ipaddress(buf, var, enums);
	    break;
	case ASN_NULL:
	    sprint_null(buf, var, enums);
	    break;
	default:
	    sprint_badtype(buf, var, enums);
	    break;
    }
}

struct tree *get_symbol();
struct tree *get_tree();

oid RFC1066_MIB[] = { 1, 3, 6, 1, 2, 1 };
unsigned char RFC1066_MIB_text[] = ".iso.org.dod.internet.mgmt.mib";
#define RFC1066_MIB_text_len (sizeof(RFC1066_MIB_text)-1)
unsigned char EXPERIMENTAL_MIB_text[] = ".iso.org.dod.internet.experimental";
unsigned char PRIVATE_MIB_text[] = ".iso.org.dod.internet.private";
unsigned char RFC1158_MIB_text[] = ".iso.org.dod.internet.mgmt.mib-2";
#define RFC1158_MIB_text_len (sizeof(RFC1158_MIB_text)-1)

struct tree *Mib;

char Standard_Prefix[] = ".1.3.6.1.2.1.";
char *Prefix;

init_mib()
{
    char *filename, *getenv();
    char  fbuf[255];

    Mib = NULL;

    filename = getenv("MIBFILE");
    if (filename)
    {
	/*
	 * If given an explicit $MIBFILE, then it *must* exist as named
	 */
	Mib = read_mib(filename);
	if (Mib)
	    goto read_mib;
	else
	{
	    fprintf(stderr, "Couldn't find mib file \"%s\"\n", filename);
	    exit(2);
	}
    }
    filename = getenv("ANMCONFDIR");
    if (filename)
    {
	sprintf(fbuf, "%s/cmu-snmp-mib.txt", filename);
	Mib = read_mib(fbuf);
    }
    if (!Mib)
	Mib = read_mib("cmu-snmp-mib.txt");

    if (!Mib)
	Mib = read_mib("/etc/cmu-snmp-mib.txt");

    if (!Mib) {
	fprintf(stderr,
	 "Couldn't find cmu-snmp-mib.txt file in $ANMCONFDIR, ., nor /etc/\n");
	exit(2);
    }
    /* $$$ it would be nice to be able to print out what mib file
     * was actually used if some level of debugging was enabled, 
     * but that is not possible without changing all of the
     * applications that use this API
     */
  read_mib:
    Prefix = getenv("PREFIX");
    if (!Prefix)
        Prefix = Standard_Prefix;
    if (Prefix[strlen(Prefix) - 1] != '.')
        strcat(Prefix, ".");  /* add a trailing dot in case user didn't */ 
    Prefix++;    /* get past leading dot. */

    set_functions(Mib);
}

static
set_functions(subtree)
    struct tree *subtree;
{
    for(; subtree; subtree = subtree->next_peer){
	switch(subtree->type){
	    case TYPE_OBJID:
		subtree->printer = sprint_object_identifier;
		break;
	    case TYPE_OCTETSTR:
		subtree->printer = sprint_octet_string;
		break;
	    case TYPE_INTEGER:
		subtree->printer = sprint_integer;
		break;
	    case TYPE_NETADDR:
		subtree->printer = sprint_networkaddress;
		break;
	    case TYPE_IPADDR:
		subtree->printer = sprint_ipaddress;
		break;
	    case TYPE_COUNTER:
		subtree->printer = sprint_counter;
		break;
	    case TYPE_GAUGE:
		subtree->printer = sprint_gauge;
		break;
	    case TYPE_TIMETICKS:
		subtree->printer = sprint_timeticks;
		break;
	    case TYPE_OPAQUE:
		subtree->printer = sprint_opaque;
		break;
	    case TYPE_NULL:
		subtree->printer = sprint_null;
		break;
	    case TYPE_OTHER:
	    default:
		subtree->printer = sprint_unknowntype;
		break;
	}
	set_functions(subtree->child_list);
    }
}

#ifdef testing
int snmp_dump_packet = 0;

main(argc, argv)
     int argc;
     char *argv[];
{
    oid objid[64];
    int objidlen = sizeof (objid);
    int count;
    struct variable variable;

    init_mib(&Mib);
    if (argc < 2)
	print_subtree(Mib, 0);
    variable.type = ASN_INTEGER;
    variable.val.integer = 3;
    variable.val_len = 4;
    for (argc--; argc; argc--, argv++) {
	objidlen = sizeof (objid);
	printf("read_objid(%s) = %d\n",
	       argv[1], read_objid(argv[1], objid, &objidlen));
	for(count = 0; count < objidlen; count++)
	    printf("%d.", objid[count]);
	printf("\n");
	print_variable(objid, objidlen, &variable);
    }
}

#endif testing

#ifdef notdef
static struct tree *
find_rfc1066_mib(root)
    struct tree *root;
{
    oid *op = RFC1066_MIB;
    struct tree *tp;
    int len;

    for(len = sizeof(RFC1066_MIB)/sizeof(oid); len; len--, op++){
	for(tp = root; tp; tp = tp->next_peer){
	    if (tp->subid == *op){
		root = tp->child_list;
		break;
	    }
	}
	if (tp == NULL)
	    return NULL;
    }
    return root;
}
#endif /* notdef */

int read_objid(input, output, out_len)
    char *input;
    oid *output;
    int	*out_len;   /* number of subid's in "output" */
{
    struct tree *root = Mib;
    oid *op = output;
    char buf[512];


    if (*input == '.')
	input++;
    else {
        strcpy(buf, Prefix);
	strcat(buf, input);
	input = buf;
    }

    if (root == NULL){
	fprintf(stderr, "Mib not initialized.  Exiting.\n");
	exit(1);
    }
    if ((*out_len =
	 parse_subtree(root, input, output, out_len)) == 0)
	return (0);
    *out_len += output - op;

    return (1);
}

#ifdef notdef
int read_objid(input, output, out_len)
    char *input;
    oid *output;
    int	*out_len;   /* number of subid's in "output" */
{
    struct tree *root = Mib;
    oid *op = output;
    int i;

    if (*input == '.')
	input++;
    else {
	root = find_rfc1066_mib(root);
	for (i = 0; i < sizeof (RFC1066_MIB)/sizeof(oid); i++) {
	    if ((*out_len)-- > 0)
		*output++ = RFC1066_MIB[i];
	    else {
		fprintf(stderr, "object identifier too long\n");
		return (0);
	    }
	}
    }

    if (root == NULL){
	fprintf(stderr, "Mib not initialized.  Exiting.\n");
	exit(1);
    }
    if ((*out_len =
	 parse_subtree(root, input, output, out_len)) == 0)
	return (0);
    *out_len += output - op;

    return (1);
}
#endif

static
parse_subtree(subtree, input, output, out_len)
    struct tree *subtree;
    char *input;
    oid	*output;
    int	*out_len;   /* number of subid's */
{
    char buf[128], *to = buf;
    u_long subid = 0;
    struct tree *tp;

    /*
     * No empty strings.  Can happen if there is a trailing '.' or two '.'s
     * in a row, i.e. "..".
     */
    if ((*input == '\0') ||
	(*input == '.'))
	return (0);

    if (isdigit(*input)) {
	/*
	 * Read the number, then try to find it in the subtree.
	 */
	while (isdigit(*input)) {
	    subid *= 10;
	    subid += *input++ - '0';
	}
	for (tp = subtree; tp; tp = tp->next_peer) {
	    if (tp->subid == subid)
		goto found;
	}
	tp = NULL;
    }
    else {
	/*
	 * Read the name into a buffer.
	 */
	while ((*input != '\0') &&
	       (*input != '.')) {
	    *to++ = *input++;
	}
	*to = '\0';

	/*
	 * Find the name in the subtree;
	 */
	for (tp = subtree; tp; tp = tp->next_peer) {
	    if (lc_cmp(tp->label, buf) == 0) {
		subid = tp->subid;
		goto found;
	    }
	}

	/*
	 * If we didn't find the entry, punt...
	 */
	if (tp == NULL) {
	    fprintf(stderr, "sub-identifier not found: %s\n", buf);
	    return (0);
	}
    }

found:
    if(subid > (u_long)MAX_SUBID){
	fprintf(stderr, "sub-identifier too large: %s\n", buf);
	return (0);
    }

    if ((*out_len)-- <= 0){
	fprintf(stderr, "object identifier too long\n");
	return (0);
    }
    *output++ = subid;

    if (*input != '.')
	return (1);
    if ((*out_len =
	 parse_subtree(tp ? tp->child_list : NULL, ++input, output, out_len)) == 0)
	return (0);
    return (++*out_len);
}

print_objid(objid, objidlen)
    oid	    *objid;
    int	    objidlen;	/* number of subidentifiers */
{
    char    buf[256];
    struct tree    *subtree = Mib;

    *buf = '.';	/* this is a fully qualified name */
    get_symbol(objid, objidlen, subtree, buf + 1);
    printf("%s\n", buf);
        
}

sprint_objid(buf, objid, objidlen)
    char *buf;
    oid	    *objid;
    int	    objidlen;	/* number of subidentifiers */
{
    struct tree    *subtree = Mib;

    *buf = '.';	/* this is a fully qualified name */
    get_symbol(objid, objidlen, subtree, buf + 1);
}


print_variable(objid, objidlen, variable)
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    buf[2048], *cp;
    struct tree    *subtree = Mib;

    *buf = '.';	/* this is a fully qualified name */
    subtree = get_symbol(objid, objidlen, subtree, buf + 1);
    cp = buf;
    if ((strlen(buf) >= RFC1158_MIB_text_len) && /* STT Issue: bcmp   */ 
	!memcmp((void *)buf, (void *)RFC1158_MIB_text, (size_t)RFC1158_MIB_text_len)){
	    cp += RFC1158_MIB_text_len + 1;
    } else if ((strlen(buf) >= RFC1066_MIB_text_len) /* STT Issue: bcmp   */ 
 	&& !memcmp((void *)buf, (void *)RFC1066_MIB_text, (size_t)RFC1066_MIB_text_len)){
 	    cp += RFC1066_MIB_text_len+1;
    }			/* STT Issue: bcmp   */ 
    if ((strlen(buf) >= strlen((char *)EXPERIMENTAL_MIB_text)) && 
	!memcmp((void *)buf, (void *)EXPERIMENTAL_MIB_text, (size_t)strlen((char*)EXPERIMENTAL_MIB_text))){
            cp += sizeof(EXPERIMENTAL_MIB_text);
    }			/* STT Issue: bcmp   */ 
    if ((strlen(buf) >= strlen((char *)PRIVATE_MIB_text)) && 
	!memcmp((void *)buf, (void *)PRIVATE_MIB_text, (size_t)strlen((char*)PRIVATE_MIB_text))){
            cp += sizeof(PRIVATE_MIB_text);
    }
    printf("Name: %s -> ", cp);
    *buf = '\0';
    if (subtree->printer)
	(*subtree->printer)(buf, variable, subtree->enums);
    else {
	sprint_by_type(buf, variable, subtree->enums);
    }
    printf("%s\n", buf);
}

sprint_variable(buf, objid, objidlen, variable)
    char *buf;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048], *cp;
    struct tree    *subtree = Mib;

    *tempbuf = '.';	/* this is a fully qualified name */
    subtree = get_symbol(objid, objidlen, subtree, tempbuf + 1);
    cp = tempbuf;		/* STT Issue: bcmp   */
    if ((strlen(buf) >= strlen((char *)RFC1066_MIB_text))
	&& !memcmp((void *)buf, (void *)RFC1066_MIB_text,
		   (size_t)strlen((char*)RFC1066_MIB_text))){
	    cp += sizeof(RFC1066_MIB_text);
    }		/* STT Issue: bcmp   */ 
    if ((strlen(buf) >= strlen((char *)EXPERIMENTAL_MIB_text))
	&& !memcmp((void *)buf, (void *)EXPERIMENTAL_MIB_text,
		   (size_t)strlen((char*)EXPERIMENTAL_MIB_text))){
            cp += sizeof(EXPERIMENTAL_MIB_text);
    }		/* STT Issue: bcmp   */ 
    if ((strlen(buf) >= strlen((char *)PRIVATE_MIB_text))
	&& !memcmp((void *)buf, (void *)PRIVATE_MIB_text,
		   (size_t)strlen((char*)PRIVATE_MIB_text))){
            cp += sizeof(PRIVATE_MIB_text);
    }
    sprintf(buf, "Name: %s -> ", cp);
    buf += strlen(buf);
    if (subtree->printer)
	(*subtree->printer)(buf, variable, subtree->enums);
    else {
	sprint_by_type(buf, variable, subtree->enums);
    }
    strcat(buf, "\n");
}

sprint_value(buf, objid, objidlen, variable)
    char *buf;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];
    struct tree    *subtree = Mib;

    subtree = get_symbol(objid, objidlen, subtree, tempbuf);
    if (subtree->printer)
	(*subtree->printer)(buf, variable, subtree->enums);
    else {
	sprint_by_type(buf, variable, subtree->enums);
    }
}

print_value(objid, objidlen, variable)
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];
    struct tree    *subtree = Mib;

    subtree = get_symbol(objid, objidlen, subtree, tempbuf);
    if (subtree->printer)
	(*subtree->printer)(tempbuf, variable, subtree->enums);
    else {
	sprint_by_type(tempbuf, variable, subtree->enums);
    }
    printf("%s\n", tempbuf);
}

struct tree *
get_symbol(objid, objidlen, subtree, buf)
    oid	    *objid;
    int	    objidlen;
    struct tree    *subtree;
    char    *buf;
{
    struct tree    *return_tree = NULL;

    for(; subtree; subtree = subtree->next_peer){
	if (*objid == subtree->subid){
	    strcpy(buf, subtree->label);
	    goto found;
	}
    }

    /* subtree not found */
    while(objidlen--){	/* output rest of name, uninterpreted */
	sprintf(buf, "%u.", *objid++);
	while(*buf)
	    buf++;
    }
    *(buf - 1) = '\0'; /* remove trailing dot */
    return NULL;

found:
    if (objidlen > 1){
	while(*buf)
	    buf++;
	*buf++ = '.';
	*buf = '\0';
	return_tree = get_symbol(objid + 1, objidlen - 1, subtree->child_list, buf);
    } 
    if (return_tree != NULL)
	return return_tree;
    else
	return subtree;
}

/*
 * Clone of get_symbol that doesn't take a buffer argument
 */
struct tree *
get_tree(objid, objidlen, subtree)
    oid	    *objid;
    int	    objidlen;
    struct tree    *subtree;
{
    struct tree    *return_tree = NULL;

    for(; subtree; subtree = subtree->next_peer){
	if (*objid == subtree->subid)
	    goto found;
    }

    return NULL;

found:
    if (objidlen > 1)
	return_tree = get_tree(objid + 1, objidlen - 1, subtree->child_list);
    if (return_tree != NULL)
	return return_tree;
    else
	return subtree;
}

static int
lc_cmp(s1, s2)
    char *s1, *s2;
{
    char c1, c2;

    while(*s1 && *s2){
	if (isupper(*s1))
	    c1 = tolower(*s1);
	else
	    c1 = *s1;
	if (isupper(*s2))
	    c2 = tolower(*s2);
	else
	    c2 = *s2;
	if (c1 != c2)
	    return ((c1 - c2) > 0 ? 1 : -1);
	s1++;
	s2++;
    }

    if (*s1)
	return -1;
    if (*s2)
	return 1;
    return 0;
}

char *get_description(objid, objidlen)
    oid	    *objid;
    int	    objidlen;	/* number of subidentifiers */
{
    struct tree    *subtree = Mib;

    subtree = get_tree(objid, objidlen, subtree);
    if (subtree)
	return (subtree->description);
    else
	return NULL;
}

void
print_description(objid, objidlen)
    oid	    *objid;
    int	    objidlen;	/* number of subidentifiers */
{
    char *desc = get_description(objid, objidlen);

    if (desc && desc[0] != '\0')
	printf("Description: \"%s\"\n", desc);
    else
	printf("No description\n");
}

