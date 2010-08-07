/*
 * Copyright (c) 2010- Iwata <iwata@quasiquote.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <ohash.h>
#include <sys/cdefs.h>
#include <sys/queue.h>


static void *
dis_xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr)
		return ptr;
	abort();
}


typedef struct {
	FILE *fp;
	int low;
	uint8_t buf;
} FILE4;

static FILE4*
fopen4(const char *path, const char *mode)
{
	FILE4 *f4;

	f4 = dis_xmalloc(sizeof(FILE4));
	if (!f4)
		return NULL;
	f4->low = 0;
	f4->buf = 0;
	if ((f4->fp = fopen(path, mode)) == NULL) {
		free(f4);
		return NULL;
	}
	return f4;
}

static int
fclose4(FILE4 *f4)
{
	if (!f4)
		return 0;
	fclose(f4->fp);
	free(f4);
	return 1;
}

static int
fgetc4(FILE4 *f4)
{
	int c;

	if (f4->low == 0) {
		c = getc(f4->fp);
		if (c == EOF)
			return EOF;
		f4->low = 1;
		f4->buf = c & 0xf;
		return c >> 4;
	} else {
		f4->low = 0;
		return f4->buf;
	}
}

#define NO_JUMP -1

struct rom_entry {
	int addr;
	char *from_label;
	char *dis;
	char *dump;
	int jump_to;
	char *to_label;

        TAILQ_ENTRY(rom_entry) rom_entries;
};
typedef TAILQ_HEAD(, rom_entry) rom_head;

void *
hash_alloc(size_t s, void *u)
{
	void *p = dis_xmalloc(s);
	if (p)
		memset(p, 0, s);
	return p;
}

void
hash_free(void *p, size_t s, void *u)
{
	free(p);
}

void *
element_alloc(size_t s, void *u)
{
	return dis_xmalloc(s);
}

struct label_list {
	int num;
};

static void
regist_label(struct ohash *h, int addr, int *num)
{
	struct label_list *l;

	l = ohash_find(h, addr);
	if (l == NULL) {
		struct label_list *new_label = dis_xmalloc(sizeof(struct label_list));

		new_label->num = *num;
		ohash_insert(h, addr, new_label);
		/* printf("insert addr %x num %d\n", addr, *num); */
		*num = *num + 1;
	}
}

static int
dis(rom_head *rom, FILE4 *fp)
{
	int count = 0;
	int inc;
	struct ohash label_hash;
	struct ohash_info label_info = {
		offsetof(struct label_list, num), NULL, hash_alloc, hash_free,
		element_alloc
	};
	int label_nr = 0;
	struct rom_entry *np;

	ohash_init(&label_hash, 20, &label_info);

	for ( ; ; ) {
		int opr1, opa1;
		int opr2, opa2;
		struct rom_entry *entry;

#define FETCH_NEXT(opr, opa) if ((opr = fgetc4(fp)) == EOF || (opa = fgetc4(fp)) == EOF) break; inc++
#define ADD_LABEL_SHORT()						\
		regist_label(&label_hash, (count & 0xff00) | (opr2 << 4) | opa2, &label_nr); \
		entry->jump_to = (count & 0xff00) | (opr2 << 4) | opa2;
#define ADD_LABEL_LONG(hi)						\
		regist_label(&label_hash, hi | (opr2 << 4) | opa2, &label_nr); \
		entry->jump_to = hi | (opr2 << 4) | opa2;

		inc = 0;

		entry = dis_xmalloc(sizeof(struct rom_entry));
		entry->addr = count;
		entry->dis = NULL;
		entry->dump = 0;
		entry->jump_to = NO_JUMP;
		entry->from_label = entry->to_label = NULL;

		FETCH_NEXT(opr1, opa1);

		switch (opr1 << 4 | opa1) {
		case 0x00:
			entry->dis = strdup("NOP");
			break;
		case 0x01:
			entry->dis = strdup("NOP");
			break;
		case 0x02:
			entry->dis = strdup("NOP");
			break;
		case 0x03:
			entry->dis = strdup("NOP");
			break;
		case 0x04:
			entry->dis = strdup("NOP");
			break;
		case 0x05:
			entry->dis = strdup("NOP");
			break;
		case 0x06:
			entry->dis = strdup("NOP");
			break;
		case 0x07:
			entry->dis = strdup("NOP");
			break;
		case 0x08:
			entry->dis = strdup("NOP");
			break;
		case 0x09:
			entry->dis = strdup("NOP");
			break;
		case 0x0a:
			entry->dis = strdup("NOP");
			break;
		case 0x0b:
			entry->dis = strdup("NOP");
			break;
		case 0x0c:
			entry->dis = strdup("NOP");
			break;
		case 0x0d:
			entry->dis = strdup("NOP");
			break;
		case 0x0e:
			entry->dis = strdup("NOP");
			break;
		case 0x0f:
			entry->dis = strdup("NOP");
			break;

		case 0x10:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=0000");
			break;
		case 0x11:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			/* entry->dis = strdup("JCN CN=0001(=JNT)"); */
			entry->dis = strdup("JNT");
			break;
		case 0x12:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			/* entry->dis = strdup("JCN CN=0010(=JC)"); */
			entry->dis = strdup("JC");
			break;
		case 0x13:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=0011");
			break;
		case 0x14:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			/* entry->dis = strdup("JCN CN=0100(=JZ)"); */
			entry->dis = strdup("JZ");
			break;
		case 0x15:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=0101");
			break;
		case 0x16:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=0110");
			break;
		case 0x17:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=0111");
			break;
		case 0x18:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=1000");
			break;
		case 0x19:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			/* entry->dis = strdup("JCN CN=1001(=JT)"); */
			entry->dis = strdup("JT");
			break;
		case 0x1a:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			/* entry->dis = strdup("JCN CN=1010(=JNC)"); */
			entry->dis = strdup("JNC");
			break;
		case 0x1b:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=1011");
			break;
		case 0x1c:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			/* entry->dis = strdup("JCN CN=1100(=JNZ)"); */
			entry->dis = strdup("JNZ");
			break;
		case 0x1d:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=1101");
			break;
		case 0x1e:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=1110");
			break;
		case 0x1f:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("JCN CN=1111");
			break;

		case 0x20:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r0r1, 0x%x%x", opr2, opa2);
			break;
		case 0x21:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r0r1, 0x%x%x", opr2, opa2);
			break;
		case 0x22:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r2r3, 0x%x%x", opr2, opa2);
			break;
		case 0x23:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r2r3, 0x%x%x", opr2, opa2);
			break;
		case 0x24:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r4r5, 0x%x%x", opr2, opa2);
			break;
		case 0x25:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r4r5, 0x%x%x", opr2, opa2);
			break;
		case 0x26:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r6r7, 0x%x%x", opr2, opa2);
			break;
		case 0x27:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r6r7, 0x%x%x", opr2, opa2);
			break;
		case 0x28:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r8r9, 0x%x%x", opr2, opa2);
			break;
		case 0x29:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r8r9, 0x%x%x", opr2, opa2);
			break;
		case 0x2a:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r10r11, 0x%x%x", opr2, opa2);
			break;
		case 0x2b:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r10r1, 0x%x%x", opr2, opa2);
			break;
		case 0x2c:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r12r13, 0x%x%x", opr2, opa2);
			break;
		case 0x2d:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r12r13, 0x%x%x", opr2, opa2);
			break;
		case 0x2e:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "FIM r14r15, 0x%x%x", opr2, opa2);
			break;
		case 0x2f:
			FETCH_NEXT(opr2, opa2);
			asprintf(&entry->dis, "SRC r14r15, 0x%x%x", opr2, opa2);
			break;

		case 0x30:
			entry->dis = strdup("FIN r0r1");
			break;
		case 0x31:
			entry->dis = strdup("JIN r0r1");
			break;
		case 0x32:
			entry->dis = strdup("FIN r2r3");
			break;
		case 0x33:
			entry->dis = strdup("JIN r2r3");
			break;
		case 0x34:
			entry->dis = strdup("FIN r4r5");
			break;
		case 0x35:
			entry->dis = strdup("JIN r4r5");
			break;
		case 0x36:
			entry->dis = strdup("FIN r6r7");
			break;
		case 0x37:
			entry->dis = strdup("JIN r6r7");
			break;
		case 0x38:
			entry->dis = strdup("FIN r8r9");
			break;
		case 0x39:
			entry->dis = strdup("JIN r8r9");
			break;
		case 0x3a:
			entry->dis = strdup("FIN r10r11");
			break;
		case 0x3b:
			entry->dis = strdup("JIN r10r11");
			break;
		case 0x3c:
			entry->dis = strdup("FIN r12r13");
			break;
		case 0x3d:
			entry->dis = strdup("JIN r12r13");
			break;
		case 0x3e:
			entry->dis = strdup("FIN r14r15");
			break;
		case 0x3f:
			entry->dis = strdup("JIN r14r15");
			break;

		case 0x40:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x000);
			entry->dis = strdup("JUN");
			break;
		case 0x41:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x100);
			entry->dis = strdup("JUN");
			break;
		case 0x42:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x200);
			entry->dis = strdup("JUN");
			break;
		case 0x43:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x300);
			entry->dis = strdup("JUN");
			break;
		case 0x44:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x400);
			entry->dis = strdup("JUN");
			break;
		case 0x45:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x500);
			entry->dis = strdup("JUN");
			break;
		case 0x46:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x600);
			entry->dis = strdup("JUN");
			break;
		case 0x47:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x700);
			entry->dis = strdup("JUN");
			break;
		case 0x48:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x800);
			entry->dis = strdup("JUN");
			break;
		case 0x49:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x900);
			entry->dis = strdup("JUN");
			break;
		case 0x4a:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xa00);
			entry->dis = strdup("JUN");
			break;
		case 0x4b:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xb00);
			entry->dis = strdup("JUN");
			break;
		case 0x4c:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xc00);
			entry->dis = strdup("JUN");
			break;
		case 0x4d:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xd00);
			entry->dis = strdup("JUN");
			break;
		case 0x4e:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xe00);
			entry->dis = strdup("JUN");
			break;
		case 0x4f:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xf00);
			entry->dis = strdup("JUN");
			break;

		case 0x50:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x000);
			entry->dis = strdup("JMS");
			break;
		case 0x51:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x100);
			entry->dis = strdup("JMS");
			break;
		case 0x52:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x200);
			entry->dis = strdup("JMS");
			break;
		case 0x53:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x300);
			entry->dis = strdup("JMS");
			break;
		case 0x54:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x400);
			entry->dis = strdup("JMS");
			break;
		case 0x55:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x500);
			entry->dis = strdup("JMS");
			break;
		case 0x56:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x600);
			entry->dis = strdup("JMS");
			break;
		case 0x57:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x700);
			entry->dis = strdup("JMS");
			break;
		case 0x58:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x800);
			entry->dis = strdup("JMS");
			break;
		case 0x59:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0x900);
			entry->dis = strdup("JMS");
			break;
		case 0x5a:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xa00);
			entry->dis = strdup("JMS");
			break;
		case 0x5b:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xb00);
			entry->dis = strdup("JMS");
			break;
		case 0x5c:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xc00);
			entry->dis = strdup("JMS");
			break;
		case 0x5d:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xd00);
			entry->dis = strdup("JMS");
			break;
		case 0x5e:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xe00);
			entry->dis = strdup("JMS");
			break;
		case 0x5f:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_LONG(0xf00);
			entry->dis = strdup("JMS");
			break;

		case 0x60:
			entry->dis = strdup("INC r0");
			break;
		case 0x61:
			entry->dis = strdup("INC r1");
			break;
		case 0x62:
			entry->dis = strdup("INC r2");
			break;
		case 0x63:
			entry->dis = strdup("INC r3");
			break;
		case 0x64:
			entry->dis = strdup("INC r4");
			break;
		case 0x65:
			entry->dis = strdup("INC r5");
			break;
		case 0x66:
			entry->dis = strdup("INC r6");
			break;
		case 0x67:
			entry->dis = strdup("INC r7");
			break;
		case 0x68:
			entry->dis = strdup("INC r8");
			break;
		case 0x69:
			entry->dis = strdup("INC r9");
			break;
		case 0x6a:
			entry->dis = strdup("INC r10");
			break;
		case 0x6b:
			entry->dis = strdup("INC r11");
			break;
		case 0x6c:
			entry->dis = strdup("INC r12");
			break;
		case 0x6d:
			entry->dis = strdup("INC r13");
			break;
		case 0x6e:
			entry->dis = strdup("INC r14");
			break;
		case 0x6f:
			entry->dis = strdup("INC r15");
			break;

		case 0x70:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r0,");
			break;
		case 0x71:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r1,");
			break;
		case 0x72:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r2,");
			break;
		case 0x73:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r3,");
			break;
		case 0x74:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r4,");
			break;
		case 0x75:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r5,");
			break;
		case 0x76:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r6,");
			break;
		case 0x77:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r7,");
			break;
		case 0x78:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r8,");
			break;
		case 0x79:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r9,");
			break;
		case 0x7a:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r10,");
			break;
		case 0x7b:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r11,");
			break;
		case 0x7c:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r12,");
			break;
		case 0x7d:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r13,");
			break;
		case 0x7e:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r14,");
			break;
		case 0x7f:
			FETCH_NEXT(opr2, opa2);
			ADD_LABEL_SHORT();
			entry->dis = strdup("ISZ r15,");
			break;

		case 0x80:
			entry->dis = strdup("ADD r0");
			break;
		case 0x81:
			entry->dis = strdup("ADD r1");
			break;
		case 0x82:
			entry->dis = strdup("ADD r2");
			break;
		case 0x83:
			entry->dis = strdup("ADD r3");
			break;
		case 0x84:
			entry->dis = strdup("ADD r4");
			break;
		case 0x85:
			entry->dis = strdup("ADD r5");
			break;
		case 0x86:
			entry->dis = strdup("ADD r6");
			break;
		case 0x87:
			entry->dis = strdup("ADD r7");
			break;
		case 0x88:
			entry->dis = strdup("ADD r8");
			break;
		case 0x89:
			entry->dis = strdup("ADD r9");
			break;
		case 0x8a:
			entry->dis = strdup("ADD r10");
			break;
		case 0x8b:
			entry->dis = strdup("ADD r11");
			break;
		case 0x8c:
			entry->dis = strdup("ADD r12");
			break;
		case 0x8d:
			entry->dis = strdup("ADD r13");
			break;
		case 0x8e:
			entry->dis = strdup("ADD r14");
			break;
		case 0x8f:
			entry->dis = strdup("ADD r15");
			break;

		case 0x90:
			entry->dis = strdup("SUB r0");
			break;
		case 0x91:
			entry->dis = strdup("SUB r1");
			break;
		case 0x92:
			entry->dis = strdup("SUB r2");
			break;
		case 0x93:
			entry->dis = strdup("SUB r3");
			break;
		case 0x94:
			entry->dis = strdup("SUB r4");
			break;
		case 0x95:
			entry->dis = strdup("SUB r5");
			break;
		case 0x96:
			entry->dis = strdup("SUB r6");
			break;
		case 0x97:
			entry->dis = strdup("SUB r7");
			break;
		case 0x98:
			entry->dis = strdup("SUB r8");
			break;
		case 0x99:
			entry->dis = strdup("SUB r9");
			break;
		case 0x9a:
			entry->dis = strdup("SUB r10");
			break;
		case 0x9b:
			entry->dis = strdup("SUB r11");
			break;
		case 0x9c:
			entry->dis = strdup("SUB r12");
			break;
		case 0x9d:
			entry->dis = strdup("SUB r13");
			break;
		case 0x9e:
			entry->dis = strdup("SUB r14");
			break;
		case 0x9f:
			entry->dis = strdup("SUB r15");
			break;

		case 0xa0:
			entry->dis = strdup("LD r0");
			break;
		case 0xa1:
			entry->dis = strdup("LD r1");
			break;
		case 0xa2:
			entry->dis = strdup("LD r2");
			break;
		case 0xa3:
			entry->dis = strdup("LD r3");
			break;
		case 0xa4:
			entry->dis = strdup("LD r4");
			break;
		case 0xa5:
			entry->dis = strdup("LD r5");
			break;
		case 0xa6:
			entry->dis = strdup("LD r6");
			break;
		case 0xa7:
			entry->dis = strdup("LD r7");
			break;
		case 0xa8:
			entry->dis = strdup("LD r8");
			break;
		case 0xa9:
			entry->dis = strdup("LD r9");
			break;
		case 0xaa:
			entry->dis = strdup("LD r10");
			break;
		case 0xab:
			entry->dis = strdup("LD r11");
			break;
		case 0xac:
			entry->dis = strdup("LD r12");
			break;
		case 0xad:
			entry->dis = strdup("LD r13");
			break;
		case 0xae:
			entry->dis = strdup("LD r14");
			break;
		case 0xaf:
			entry->dis = strdup("LD r15");
			break;

		case 0xb0:
			entry->dis = strdup("XCH r0");
			break;
		case 0xb1:
			entry->dis = strdup("XCH r1");
			break;
		case 0xb2:
			entry->dis = strdup("XCH r2");
			break;
		case 0xb3:
			entry->dis = strdup("XCH r3");
			break;
		case 0xb4:
			entry->dis = strdup("XCH r4");
			break;
		case 0xb5:
			entry->dis = strdup("XCH r5");
			break;
		case 0xb6:
			entry->dis = strdup("XCH r6");
			break;
		case 0xb7:
			entry->dis = strdup("XCH r7");
			break;
		case 0xb8:
			entry->dis = strdup("XCH r8");
			break;
		case 0xb9:
			entry->dis = strdup("XCH r9");
			break;
		case 0xba:
			entry->dis = strdup("XCH r10");
			break;
		case 0xbb:
			entry->dis = strdup("XCH r11");
			break;
		case 0xbc:
			entry->dis = strdup("XCH r12");
			break;
		case 0xbd:
			entry->dis = strdup("XCH r13");
			break;
		case 0xbe:
			entry->dis = strdup("XCH r14");
			break;
		case 0xbf:
			entry->dis = strdup("XCH r15");
			break;

		case 0xc0:
			entry->dis = strdup("BBL 0x0");
			break;
		case 0xc1:
			entry->dis = strdup("BBL 0x1");
			break;
		case 0xc2:
			entry->dis = strdup("BBL 0x2");
			break;
		case 0xc3:
			entry->dis = strdup("BBL 0x3");
			break;
		case 0xc4:
			entry->dis = strdup("BBL 0x4");
			break;
		case 0xc5:
			entry->dis = strdup("BBL 0x5");
			break;
		case 0xc6:
			entry->dis = strdup("BBL 0x6");
			break;
		case 0xc7:
			entry->dis = strdup("BBL 0x7");
			break;
		case 0xc8:
			entry->dis = strdup("BBL 0x8");
			break;
		case 0xc9:
			entry->dis = strdup("BBL 0x9");
			break;
		case 0xca:
			entry->dis = strdup("BBL 0xa");
			break;
		case 0xcb:
			entry->dis = strdup("BBL 0xb");
			break;
		case 0xcc:
			entry->dis = strdup("BBL 0xc");
			break;
		case 0xcd:
			entry->dis = strdup("BBL 0xd");
			break;
		case 0xce:
			entry->dis = strdup("BBL 0xe");
			break;
		case 0xcf:
			entry->dis = strdup("BBL 0xf");
			break;

		case 0xd0:
			entry->dis = strdup("LDM 0x0");
			break;
		case 0xd1:
			entry->dis = strdup("LDM 0x1");
			break;
		case 0xd2:
			entry->dis = strdup("LDM 0x2");
			break;
		case 0xd3:
			entry->dis = strdup("LDM 0x3");
			break;
		case 0xd4:
			entry->dis = strdup("LDM 0x4");
			break;
		case 0xd5:
			entry->dis = strdup("LDM 0x5");
			break;
		case 0xd6:
			entry->dis = strdup("LDM 0x6");
			break;
		case 0xd7:
			entry->dis = strdup("LDM 0x7");
			break;
		case 0xd8:
			entry->dis = strdup("LDM 0x8");
			break;
		case 0xd9:
			entry->dis = strdup("LDM 0x9");
			break;
		case 0xda:
			entry->dis = strdup("LDM 0xa");
			break;
		case 0xdb:
			entry->dis = strdup("LDM 0xb");
			break;
		case 0xdc:
			entry->dis = strdup("LDM 0xc");
			break;
		case 0xdd:
			entry->dis = strdup("LDM 0xd");
			break;
		case 0xde:
			entry->dis = strdup("LDM 0xe");
			break;
		case 0xdf:
			entry->dis = strdup("LDM 0xf");
			break;

		case 0xe0:
			entry->dis = strdup("WRM");
			break;
		case 0xe1:
			entry->dis = strdup("EMP");
			break;
		case 0xe2:
			entry->dis = strdup("WRR");
			break;
		case 0xe3:
			entry->dis = strdup("WPM");
			break;
		case 0xe4:
			entry->dis = strdup("WR0");
			break;
		case 0xe5:
			entry->dis = strdup("WR1");
			break;
		case 0xe6:
			entry->dis = strdup("WR2");
			break;
		case 0xe7:
			entry->dis = strdup("WR3");
			break;
		case 0xe8:
			entry->dis = strdup("SBM");
			break;
		case 0xe9:
			entry->dis = strdup("RDM");
			break;
		case 0xea:
			entry->dis = strdup("RDR");
			break;
		case 0xeb:
			entry->dis = strdup("ADM");
			break;
		case 0xec:
			entry->dis = strdup("RD0");
			break;
		case 0xed:
			entry->dis = strdup("RD1");
			break;
		case 0xee:
			entry->dis = strdup("RD2");
			break;
		case 0xef:
			entry->dis = strdup("RD3");
			break;

		case 0xf0:
			entry->dis = strdup("CLB");
			break;
		case 0xf1:
			entry->dis = strdup("CLC");
			break;
		case 0xf2:
			entry->dis = strdup("IAC");
			break;
		case 0xf3:
			entry->dis = strdup("CMC");
			break;
		case 0xf4:
			entry->dis = strdup("CMA");
			break;
		case 0xf5:
			entry->dis = strdup("RAL");
			break;
		case 0xf6:
			entry->dis = strdup("RAR");
			break;
		case 0xf7:
			entry->dis = strdup("TCC");
			break;
		case 0xf8:
			entry->dis = strdup("DAC");
			break;
		case 0xf9:
			entry->dis = strdup("TCS");
			break;
		case 0xfa:
			entry->dis = strdup("STC");
			break;
		case 0xfb:
			entry->dis = strdup("DAA");
			break;
		case 0xfc:
			entry->dis = strdup("KBP");
			break;
		case 0xfd:
			entry->dis = strdup("DCL");
			break;
		case 0xfe:
			entry->dis = strdup("-");
			break;
		case 0xff:
			entry->dis = strdup("-");
			break;
		}
		if (inc == 1)
			asprintf(&entry->dump, "0x%x%x", opr1, opa1);
		else
			asprintf(&entry->dump, "0x%x%x%x%x", opr1, opa1, opr2, opa2);

		TAILQ_INSERT_TAIL(rom, entry, rom_entries);
		count += inc;
	}

	/* insert labels */
	for (np = TAILQ_FIRST(rom); np != NULL; np = TAILQ_NEXT(np, rom_entries)) {
		struct label_list *l;

		l = ohash_find(&label_hash, np->addr);
		if (l != NULL) {
			asprintf(&np->from_label, "L%d", l->num);
		}

		if (np->jump_to != NO_JUMP) {
			l = ohash_find(&label_hash, np->jump_to);
			if (l == NULL)
				printf("internal error, ignored...\n");
			else
				asprintf(&np->to_label, "L%d", l->num);
		}

	}

	ohash_delete(&label_hash);

	return 1;
}

int
main(int argc, char *argv[])
{
	rom_head rom;
	struct rom_entry *np;
	FILE4 *fp;

	if (argc != 2)
		return 1;

	if ((fp = fopen4(argv[1], "r")) == NULL) {
		perror("fopen4");
		return 1;
	}

	TAILQ_INIT(&rom);
	dis(&rom, fp);

	TAILQ_FOREACH(np, &rom, rom_entries) {
		if (np->from_label) {
			printf("%04x: %s:\n", np->addr, np->from_label);
			if (np->dis)
				printf("        %s", np->dis);
			if (np->to_label)
				printf(" %s", np->to_label);
			/* printf(" (%s)", np->dump); */
			printf("\n");
		} else if (np->dis) {
			printf("%04x:   %s", np->addr, np->dis);
			if (np->to_label)
				printf(" %s", np->to_label);
			/* printf(" (%s)", np->dump); */
			printf("\n");
		}
	}

	while ((np = TAILQ_FIRST(&rom)) != NULL) {
		free(np->from_label);
		free(np->dis);
		free(np->dump);
		free(np->to_label);
		TAILQ_REMOVE(&rom, np, rom_entries);
		free(np);
	}

	fclose4(fp);
	return 0;
}

