#ifndef lint
static char rcsid[]="$Header: /nfs/medea/u0/rel5/rcs/Tools/cmusnmp/apps/kernel.c,v 1.3 1996/11/14 15:16:03 tpt2 Exp $";
#endif


#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>

static mode_t kmem;
mode_t swap, mem;

init_kmem(file)
    char *file;
{
    kmem = open(file, 0);
    if (kmem < 0){
	fprintf(stderr, "cannot open ");
	perror(file);
	exit(1);
    }
#ifdef ibm032
    mem = open("/dev/mem");    
    if (mem < 0){
	fprintf(stderr, "cannot open ");
	perror(file);
	exit(1);
    }
    swap = open("/dev/drum");
    if (swap < 0){
	fprintf(stderr, "cannot open ");
	perror(file);
	exit(1);
    }
#endif
}

/*
 * Seek into the kernel for a value.
 */
off_t
klseek(base)
	off_t base;
{
	return (lseek(kmem, (off_t)base, 0));
}

klread(buf, buflen)
    char *buf;
    int buflen;
{
    read(kmem, buf, buflen);
}

