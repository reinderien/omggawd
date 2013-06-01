/*

   stompy - Session Stomper
   ------------------------

   Copyright (C) 2007 by Michal Zalewski <lcamtuf@coredump.cx>

*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>

#include <openssl/ssl.h>

#include <gmp.h>

#include "types.h"

#define MAXRANGE      (200*1024)		/* Max. page length to be analyzed */
#define MAXVARS       32			/* Max. number of IDs to track */
#define BUFSIZE	      1024			/* Working buffer size for misc uses */
#define MAXVARLEN     128			/* Maximum length of a tracked SID */
#define REQ_RETRY     3				/* Retry request that many times */

#define say_tofile(x...) do { if (OUTFILE) fprintf(OUTFILE,x); } while (0)
#define say(x...)        do { printf(x); if (OUTFILE) fprintf(OUTFILE,x); } while (0)
#define debug(x...)      do { fprintf(stderr,x); if (OUTFILE) fprintf(OUTFILE,x); } while (0)
#define fatal(x...)      do { debug("[-] ERROR: " x); exit(1); } while (0)
#define pfatal(x)        do { debug("[-] ERROR: "); perror(x); exit(1); } while (0)


#define SAMPLESET     20000			/* All checks are calibrated for 20k!    */
						/* FIPS-140-2 spec requires 20k samples. */


static FILE* OUTFILE;
static FILE* read_from_file;
static _u32  fields_per_page;

static _s32 farthest_var = MAXRANGE;
static _u8  reading_from_raw;
static _u8  no_gmp;
static _u8  use_ssl;

#define MDEV(_x) (500 / pow(_x,0.375) + 5)

struct dyn_recv_buf {
  _u8* buf;
  _u32 blen;
};


#define BUF_APPEND(_b,_str,_slen) do { \
    (_b)->buf = realloc((_b)->buf,(_b)->blen + _slen + 1); \
    memcpy((_b)->buf + (_b)->blen, _str, _slen); \
    (_b)->blen += _slen; \
  } while (0)

#define BUF_DESTROY(_b) do { free((_b)->buf); free(_b); } while (0)


/* This is absent on some older systems; stolen from ucLib by Erik Andersen, LGPL */
_u8 *own_strcasestr(const _u8 *s1, const _u8 *s2) {
  register const _u8 *s = s1;
  register const _u8 *p = s2;

  do {
    if (!*p) return (_u8*)s1;
    if ((*p == *s) || (tolower(*p) == tolower(*s))) { p++; s++; }
    else { p = s2; if (!*s) return 0; s = ++s1; }
  } while (1);

}


static SSL_CTX *ctx;

static void init_ssl(void) {

  SSL_library_init();
  SSL_load_error_strings();

  ctx = SSL_CTX_new(SSLv23_client_method());
  if (!ctx) fatal("Unable to create SSL CTX.\n");

}


static struct dyn_recv_buf* issue_request(_u8* hname, _u32 d_addr, _u16 port, _u8* uri,_u8* req) {
  static _u32 reqcnt;
  struct sockaddr_in sin;
  _s32 cs, i;
  _u8 tmp[BUFSIZE];
  struct dyn_recv_buf* ret;
  static _u32 request_retry;
  SSL* ssl = 0;

  ret = calloc(1, sizeof(struct dyn_recv_buf));

  reqcnt++;

  if (read_from_file) {
    _u8 type[32],name[128],val[128];
    _u32 xx;

    sprintf(tmp,"HTTP/1.1 200 Replay from file\n");
    BUF_APPEND(ret,tmp,strlen(tmp));

    if (reading_from_raw) strcpy(type,"custom");

    for (xx=0;xx<fields_per_page;xx++) {
      _u8 buf[1024];
      if (!fgets(buf,sizeof(buf)-1,read_from_file))
        fatal("Premature EOF in replayed file (request = %u).\n",reqcnt);
      if (reading_from_raw) {
        if (sscanf(buf,"%100[ -~]\n",val) != 1)
          fatal("Format error in replayed file (request = %u).\n",reqcnt);
      } else {
        if (sscanf(buf,"%16[^|]|%100[^|]|%100[ -~]\n",type,name,val) != 3)
          fatal("Format error in replayed file (request = %u).\n",reqcnt);
      }
      if (type[0] == 'r' && type[1] == 'e' /* redir */) {
        sprintf(tmp,"Location: %s\n",val);
        BUF_APPEND(ret,tmp,strlen(tmp));
      } else if (type[0] == 'c' && type[1] == 'o' /* cookie */) {
        sprintf(tmp,"Set-cookie: %s=%s\n",name,val);
        BUF_APPEND(ret,tmp,strlen(tmp));
      } else if (type[0] == 'f' && type[1] == 'o' /* form */) {
        sprintf(tmp,"\n<form name=\"dat\"><input name=\"%s\" value=\"%s\"></form>\n",name,val);
        BUF_APPEND(ret,tmp,strlen(tmp));
      } else {
        sprintf(tmp,"Stompy-custom-value: %s\n",val);
        BUF_APPEND(ret,tmp,strlen(tmp));
      }
    }

    return ret;

  }

try_again:

  cs = socket(PF_INET, SOCK_STREAM, 0);
  if (cs < 0) pfatal("socket");

  sin.sin_family = PF_INET;
  sin.sin_port   = htons(port);

  memcpy(&sin.sin_addr, &d_addr, sizeof(d_addr));

  if (connect(cs,(struct sockaddr*)&sin,sizeof(struct sockaddr_in))) {
    if (request_retry < REQ_RETRY) {
      request_retry++;
      close(cs);
      usleep(250000 * request_retry); /* Wait a moment */
      goto try_again;
    } else fatal("Repeatedly unable to connect to target host (req #%u).\n", reqcnt);
  }

  if (use_ssl) {
    _u32 err;
    if (!ctx) init_ssl();
    ssl = SSL_new(ctx);
    if (!ssl) fatal("Unable to create SSL object.\n");
    SSL_set_fd(ssl, cs);
    err = SSL_connect(ssl);
    if (err != 1) {
      if (request_retry < REQ_RETRY) {
        request_retry++;
        close(cs);
        usleep(250000 * request_retry); /* Wait a moment */
        goto try_again;
      } else fatal("Repeatedly unable to negotiate SSL session with peer (req #%u).\n", reqcnt);
    }

  }

  if (!req)
    sprintf(tmp,"GET /%.512s HTTP/1.1\r\n"
                "Host: %.128s:%d\r\n"
                "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; Session Stomper)\r\n"
                "Connection: close\r\n"
                "Range: bytes=0-%u\r\n\r\n", uri, hname, port, farthest_var);

  if (!use_ssl) {

    if (send(cs, req ? req : tmp, strlen(req ? req : tmp), 0) <= 0) {
      if (request_retry < REQ_RETRY) {
        request_retry++;
        close(cs);
        usleep(250000 * request_retry); /* Wait a moment */
        goto try_again;
      } else fatal("Repeatedly unable to send request to target (req #%u).\n", reqcnt);
    }

    while ((i = recv(cs, tmp, sizeof(tmp), 0)) > 0 && ret->blen <= farthest_var)
      BUF_APPEND(ret,tmp,i);

  } else {

    if (SSL_write(ssl, req ? req : tmp, strlen(req ? req : tmp)) <= 0) {
      if (request_retry < REQ_RETRY) {
        request_retry++;
        SSL_free(ssl);
        close(cs);
        usleep(250000 * request_retry); /* Wait a moment */
        goto try_again;
      } else fatal("Repeatedly unable to send request to target (req #%u).\n", reqcnt);
    }

    while ((i = SSL_read(ssl, tmp, sizeof(tmp))) > 0 && ret->blen <= farthest_var)
      BUF_APPEND(ret,tmp,i);

    SSL_free(ssl);

  }

  close(cs);

  if (!ret->blen) {
    if (request_retry < REQ_RETRY) {
      request_retry++;
      usleep(250000 * request_retry); /* Wait a moment */
      goto try_again;
    } else fatal("Reoccuring null HTTP response from target (req #%u).\n", reqcnt);
  }

  request_retry = 0;

  ret->buf[ret->blen] = 0;
  return ret;

}


#define TRACK_NONE	0
#define TRACK_LOCATION	1
#define TRACK_COOKIE	2
#define TRACK_FORM	3
#define TRACK_CUSTOM	4

static _u8* tracking[MAXVARS];
static _u8 ttype[MAXVARS];
static _u32 tcount;

static _u8* tval[MAXVARS][SAMPLESET];

#define GETBUFLINE(_t,_o,_l) do { \
    _u32 _x = strcspn((_t), header ? "\r\n" : "<"), _skip = 1; \
    if (_x > BUFSIZE - 1) _x = BUFSIZE - 1; \
    (_o) = (_t); \
    if (((_t)[_x] == '\r' && (_t)[_x+1] == '\n') || \
        ((_t)[_x] == '\n' && (_t)[_x+1] == '\r')) _skip = 2; \
    (_t)[_x]=0; \
    (_t) += _x + _skip; \
    (_l) -= _x + _skip; \
  } while (0)


#define CKBOTH(_str) (strncasecmp(l1,_str,strlen(_str)) || strncasecmp(l2,_str,strlen(_str)))

static void compare_docs(struct dyn_recv_buf* doc1, struct dyn_recv_buf* doc2) {
  _u8  header = 1;
  _u8  *d1=doc1->buf, *d2 = doc2->buf, *l1, *l2;
  _s32 d1l = doc1->blen, d2l = doc2->blen;
  _u8  *form_name = 0;

  _u32 form_no = 0, input_no = 0;
  _s32 same_inputs = 0;

  farthest_var = 0;

  while (d1l > 0 && d2l > 0) {
    GETBUFLINE(d1,l1,d1l);
    GETBUFLINE(d2,l2,d2l);

    if (header) {
      if (!CKBOTH("Location:")) {

        if (strcmp(l1,l2)) {
          say("[+] Redirects differ and seem to contain session data:\n"
              "    #1: %s\n"
              "    #2: %s\n", l1 + 9 + strspn(l1 + 9, ": \t"),
                                 l2 + 9 + strspn(l2 + 9, ": \t")); 

          {
            _u32 i;
            for (i=0;i<tcount;i++) 
              if (ttype[i] == TRACK_LOCATION) {
                say("    WARNING: Duplicate field, ignoring...\n");
                break;
              }
            if (i == tcount) {
              tracking[tcount] = "-";
              ttype[tcount] = TRACK_LOCATION;
              tcount++;
            }
          }
 
        } else
          say("[-] Both redirects point to '%s'.\n"
              "    (maybe you should test that URI instead?)\n",l1 + 9 + strspn(l1 + 9, ": \t"));

      } else if (!CKBOTH("Stompy-custom-value:")) {

          tracking[tcount] = "-";
          ttype[tcount] = TRACK_CUSTOM;
          tcount++;

      } else if (!CKBOTH("Set-Cookie")) {
        _u8 n1[128], n2[128], v1[128], v2[128], *tmp1, *tmp2;

        tmp1 = strchr(l1,':');
        tmp2 = strchr(l2,':');

        if (tmp1++ && tmp2++)
          while (sscanf(tmp1,"%*[ \t]%100[^;=]=%100[^;]",n1,v1) == 2 && 
                 sscanf(tmp2,"%*[ \t]%100[^;=]=%100[^;]",n2,v2) == 2 &&
                 !strcmp(n1,n2)) {
          while (*n1 && strchr(" \t",n1[strlen(n1)-1])) n1[strlen(n1)-1] = 0;
          while (*n2 && strchr(" \t",n2[strlen(n2)-1])) n2[strlen(n2)-1] = 0;

          if (!strcasecmp(n1,"expires") || !strcasecmp(n1,"domain") ||
              !strcasecmp(n1,"path")    || !strcasecmp(n1,"max-age") ||
              !strcasecmp(n1,"port")) goto next_cookie_bit;

          if (strcmp(v1,v2)) {
            say("[+] Cookie parameter '%s' may contain session data:\n"
                "    #1: %s\n"
                "    #2: %s\n",n1,v1,v2);

            {
              _u32 i;
              for (i=0;i<tcount;i++) 
                if (ttype[i] == TRACK_COOKIE && !strcmp(n1,tracking[i])) {
                  say("    WARNING: Duplicate field, ignoring...\n");
                  break;
                }

              if (i == tcount) {
                tracking[tcount] = strdup(n1);
                ttype[tcount] = TRACK_COOKIE;
                tcount++;
              }
            }

          } else
            say("[-] Cookie parameter '%s' is constant.\n",n1);

next_cookie_bit:

          tmp1 += strcspn(tmp1,";");
          tmp2 += strcspn(tmp2,";");
        }
        
      } else
        if (!l1[0]) header = 0; /* EOH */

    } else {

      if (!CKBOTH("form ")) {
        _u8* name = own_strcasestr(l1,"name=");
        _u8 nv[128];
        if (form_name) { free(form_name); form_name = 0; }
        if (name) {
          name+=5;
          if (sscanf(name,"%*[\"']%100[^\"']",nv) == 1) form_name = strdup(nv);
          else if (sscanf(name,"%100s",nv) == 1) form_name = strdup(nv);
        }
        if (!form_name) 
          { sprintf(nv,"_form[%u]",form_no); form_name = strdup(nv); }

        form_no++;
      } else if (!CKBOTH("input ")) {
        _u8 *name   = own_strcasestr(l1,"name="),
            *value1 = own_strcasestr(l1,"value="),
            *value2 = own_strcasestr(l2,"value=");
        _u8 nv[128], fn[256], vv1[128], vv2[128];

        if (value1 && value2) {

          if (!name) {
            sprintf(fn,"%s._input[%u]", form_name ? form_name : (_u8*)"", input_no);
          } else {
            name+=5;
            if (sscanf(name,"%*[\"']%100[^\"']",nv) == 1) sprintf(fn,"%s.%s",form_name ?
              form_name : (_u8*)"", nv);
            else if (sscanf(name,"%100s",nv) == 1) sprintf(fn,"%s.%s",form_name ?
              form_name : (_u8*)"", nv);
            else sprintf(fn,"%s._input[%u]", form_name ? form_name : (_u8*)"", input_no);
          }

          value1+=6;
          vv1[0]=0;
          if (sscanf(value1,"%*[\"']%100[^\"']",vv1) != 1)
            sscanf(value1,"%100s",vv1);

          value2+=6;
          vv2[0]=0;
          if (sscanf(value2,"%*[\"']%100[^\"']",vv2) != 1)
            sscanf(value2,"%100s",vv2);

          if (!strcmp(vv1,vv2)) { if (same_inputs >= 0) same_inputs++; } else {
            say("[+] Form parameter '%s' may contain session data:\n"
                "    #1: %s\n"
                "    #2: %s\n",fn,vv1,vv2);

            {
              _u32 i;
              for (i=0;i<tcount;i++) 
                if (ttype[i] == TRACK_FORM && !strcmp(fn,tracking[i])) {
                  say("    WARNING: Duplicate field, ignoring...\n");
                  break;
                }
             
              if (i == tcount) {
                tracking[tcount] = strdup(fn);
                ttype[tcount] = TRACK_FORM;
                tcount++;
                same_inputs = -1;
                farthest_var = d1 - doc1->buf + BUFSIZE;
              }
            }
          }

        }

        input_no++;
      } else if (!CKBOTH("/form>")) {

        if (form_name) { free(form_name); form_name = 0; }
      }
    }

  }

  if (same_inputs > 0)
    say("[-] Examined %u form inputs, no session data found.\n",same_inputs);
  
}


static void find_ids(_u8* hostname, _u32 addr, _u16 port, _u8* uri,_u8* req) {
  struct dyn_recv_buf *rq1, *rq2;
  _u32 code;
  _u8  text[128];

  rq1 = issue_request(hostname, addr, port, uri, req);

  if (sscanf(rq1->buf,"HTTP/1.%*u %u %128[ -~]",&code,text) != 2)
    fatal("Server responded with non-HTTP data.\n");

  if (code < 200 || code >= 400)
    say("    WARNING: Request #1 returns error code");
  else if (code >= 300)
    say("    NOTE: Request #1 answered with a redirect");
  else say("    Request #1 OK");

  say(" (%u %s) [%.02f kB]\n", code, text, rq1->blen / 1024.0);

  rq2 = issue_request(hostname, addr, port, uri, req);

  if (sscanf(rq2->buf,"HTTP/1.%*u %u %128[ -~]",&code,text) != 2)
    fatal("Server responded with non-HTTP data.\n");

  if (code < 200 || code >= 400)
    say("    WARNING: Request #2 returns error code");
  else if (code >= 300)
    say("    NOTE: Request #2 answered with a redirect");
  else say("    Request #2 OK");

  say(" (%u %s) [%.02f kB]\n", code, text, rq2->blen / 1024.0);

  if (rq1->blen > MAXRANGE || rq2->blen > MAXRANGE)
    say("    NOTE: Page length exceeds %u kB fetch limit.\n", MAXRANGE / 1024);

  compare_docs(rq1,rq2);

  BUF_DESTROY(rq1);
  BUF_DESTROY(rq2);

  if (!tcount) {
    say("\n=> Unable to find session data - sorry it didn't work out.\n\n");
    exit(1);
  } else
    say("\n=> Found %u field(s) to track, ready to collect data.\n\n",tcount);


}

static _u32 minlen[MAXVARS], maxlen[MAXVARS];


static void record_data(_u32 tnum,_u8* value, FILE* f,_u32 snum) {
  _u32 l;

  if ((l = strlen(value)) > MAXVARLEN)
    value[l = MAXVARLEN] = 0;

  if (f)
    fprintf(f,"%s|%s|%s\n",ttype[tnum] == TRACK_LOCATION ? "redir" : 
                           ttype[tnum] == TRACK_COOKIE ? "cookie" : 
                           ttype[tnum] == TRACK_FORM ? "form" : "custom" ,tracking[tnum],value);

  if (!minlen[tnum] || minlen[tnum] > l) minlen[tnum] = l;
  if (maxlen[tnum] < l) maxlen[tnum] = l;

  tval[tnum][snum] = strdup(value);
}



static void grab_analyzed_data(struct dyn_recv_buf* doc, FILE* f,_u32 snum) {
  _u8 header = 1;
  _u8 *d=doc->buf, *l;
  _s32 dl = doc->blen;
  _u32 form_no = 0, input_no = 0, i;
  _u8  *form_name = 0;

  while (dl > 0) {
    GETBUFLINE(d,l,dl);

    if (header) {
      if (!strncasecmp(l,"Location:",9)) {
        _u32 i;
        for (i=0;i<tcount;i++) 
          if (ttype[i] == TRACK_LOCATION) {
            record_data(i, l + 9 + strspn(l + 9, ": \t"), f, snum);
            break;
          }
      } else if (!strncasecmp(l,"Stompy-custom-value: ",21)) {
        _u32 i;
        for (i=0;i<tcount;i++) 
          if (ttype[i] == TRACK_CUSTOM) {
            record_data(i, l + 21, f, snum);
            break;
          }
      } else if (!strncasecmp(l,"Set-Cookie",10)) {
        _u8 n[128], v[128], *tmp;

        tmp = strchr(l,':');

        if (tmp++)
        while (sscanf(tmp,"%*[ \t]%100[^;=]=%100[^;]",n,v) == 2) {
          _u32 i;
          while (*n && strchr(" \t",n[strlen(n)-1])) n[strlen(n)-1] = 0;
 
          for (i=0;i<tcount;i++)
            if (ttype[i] == TRACK_COOKIE && !strcmp(tracking[i],n)) {
              record_data(i, v, f, snum);
              break;
            }
 
          tmp += strcspn(tmp,";");
        }
        
      } else
        if (!l[0]) header = 0; /* EOH */

    } else {
      if (!strncasecmp(l,"form ",5)) {

        _u8* name = own_strcasestr(l,"name=");
        _u8 nv[128];
        if (form_name) { free(form_name); form_name = 0; }
        if (name) {
          name+=5;
          if (sscanf(name,"%*[\"']%100[^\"']",nv) == 1) form_name = strdup(nv);
          else if (sscanf(name,"%100s",nv) == 1) form_name = strdup(nv);
        }
        if (!form_name) 
          { sprintf(nv,"_form[%u]",form_no); form_name = strdup(nv); }

        form_no++;

      } else if (!strncasecmp(l,"input ",6)) {

        _u8 *name   = own_strcasestr(l,"name="),
            *value  = own_strcasestr(l,"value=");
        _u8 nv[128], fn[256], vv[128];
        _u32 i;

        if (value) {

          if (!name) {
            sprintf(fn,"%s._input[%u]", form_name ? form_name : (_u8*)"", input_no);
          } else {
            name+=5;
            if (sscanf(name,"%*[\"']%100[^\"']",nv) == 1) sprintf(fn,"%s.%s",form_name ?
              form_name : (_u8*)"", nv);
            else if (sscanf(name,"%100s",nv) == 1) sprintf(fn,"%s.%s",form_name ?
              form_name : (_u8*)"", nv);
            else sprintf(fn,"%s._input[%u]", form_name ? form_name : (_u8*)"", input_no);
          }

          for (i=0;i<tcount;i++) 
            if (ttype[i] == TRACK_FORM && !strcmp(fn,tracking[i])) {

              value+=6;
              vv[0]=0;
              if (sscanf(value,"%*[\"']%100[^\"']",vv) != 1)
                sscanf(value,"%100s",vv);

              record_data(i, vv, f, snum);              

              break;

            }

        }

        input_no++;

      } else if (!strncasecmp(l,"/form>",6)) {
        if (form_name) { free(form_name); form_name = 0; }
      }
    }

  }

  for (i=0;i<tcount;i++)
    if (!tval[i][snum]) { 
      say("\n"); 
      fatal("Field '%s' suddenly missing in sample #%u.\n",
            ttype[i] == TRACK_LOCATION ? (_u8*)"(redirect)" : tracking[i],snum);
    }
  
}


static char* rate_random(_s32 bits) {
  if (bits <= 0) return "deterministic?";
  else if (bits < 19) return "very trivial!";
  else if (bits < 39) return "vulnerable!"; 
  else if (bits < 59) return "fairly robust";
  else if (bits < 79) return "very good";
  else return "excellent";
}


static _u16 alphabet[MAXVARS][MAXVARLEN][256];
static _u16 alsize[MAXVARS][MAXVARLEN];
static _u8  al_off[MAXVARS][MAXVARLEN][256];


static _u8 bitstream[MAXVARLEN*8][SAMPLESET/8];

static void analyze_samples(void) {
  _u32 i,l,s;
  _s32 c;
  float ignored_data;
  _u32 used_data;
  _u8 badbits[MAXVARLEN*8];
  _u8 badbytes[MAXVARLEN]; 
  _u8  bitcnt[MAXVARLEN];

  say("=> Samples acquired, ready to perform initial analysis.\n\n");

  say("[*] Alphabet reconstruction / enumeration: ");

  for (i=0;i<tcount;i++) {

    say(".");
    fflush(0);

    for (s=0;s<SAMPLESET;s++) {
      _u32 l = strlen(tval[i][s]);

      for (c=0;c<maxlen[i];c++) {
        if (c < l) { 
          if (!alphabet[i][c][tval[i][s][c]]++) alsize[i][c]++; 
        } else { 
          if (!alphabet[i][c][0]++) alsize[i][c]++;
        }
      }

    }

    /* Map characters to bit values... */
    for (c=0;c<maxlen[i];c++) {
      _u8 curno = 0;
      for (s=0;s<256;s++) if (alphabet[i][c][s]) al_off[i][c][s]=curno++;
    }

  }

  say(" done\n\n");

  for (i=0;i<tcount;i++) {
    float entbits = 0;
    _u32 printed = 0;
    _u32 reported_flaws, skipped_flaws;
    float entropy_loss;
    _u8 window;
    _u8 non_pow2_alpha = 0;

    memset(badbits,0,sizeof(badbits));
    memset(badbytes,0,sizeof(badbytes));
    
    if (ttype[i] == TRACK_LOCATION) say("=== Redirect (length %u) ===\n\n", maxlen[i]);
    else if (ttype[i] == TRACK_COOKIE) say("=== Cookie '%s' (length %u) ===\n\n", tracking[i],maxlen[i]);
    else if (ttype[i] == TRACK_FORM) say("=== Form field '%s' (length %u) ===\n\n", tracking[i],maxlen[i]);
    else say("=== Custom input (length %u) ===\n\n", maxlen[i]);

    say_tofile("[+] Full alphabet dump:\n");
    for (c=0;c<maxlen[i];c++) {
      _u32 x;
      if (alsize[i][c] < 2) continue;
      say_tofile("    Position #%u: '",c);
      for (x=0;x<256;x++) 
        if (alphabet[i][c][x] > 1) say_tofile("%c",x);
      say_tofile("' (%u)\n",alsize[i][c]);

      if (alsize[i][c] != 2 &&
          alsize[i][c] != 4 &&
          alsize[i][c] != 8 &&
          alsize[i][c] != 16 &&
          alsize[i][c] != 32 &&
          alsize[i][c] != 64 &&
          alsize[i][c] != 128 &&
          alsize[i][c] != 256) non_pow2_alpha++;

    }
    say_tofile("\n");

    say("[+] Alphabet structure summary:");

    for (c=256;c>0;c--) {
      _u32 scnt = 0;
      for (l=0;l<maxlen[i];l++) 
        if (alsize[i][l] == c) scnt++;
      if (scnt) { 
        if (!(printed++ % 4)) say("\n    ");
        if (c == 1) say("A[---]=%05u",scnt);
        else {
          say("A[%03u]=%05u ",c,scnt);

#define port_log2(_x) (log(_x) / log(2))

          entbits += scnt * port_log2(c);
        }
      }
    }

    say("\n    %sTheoretical maximum entropy: %0.02f bits (%s)\n\n",
           entbits < 39 ? "WARNING: " : "", entbits, rate_random(entbits));

    if (minlen[i] != maxlen[i]) 
      say("NOTE: Field length varies (%u-%u bytes), aligned LEFT. Consider manually\n"
          "      examining dump file and re-running stompy if appropriate.\n\n",minlen[i],maxlen[i]);

    if (non_pow2_alpha)
      say("NOTE: Found %u alphabets of fractional bit width. Consider manually\n"
          "      examining dump file and re-running stompy if this looks odd. Note\n"
          "      that in such cases, most significant bits may exhibit some bias.\n\n",non_pow2_alpha);

    /* Check alphabet distribution */
    reported_flaws = skipped_flaws = 0;
    entropy_loss = 0;

    say("=> Analysis done, ready to execute statistical tests.\n\n");

    say("[*] Checking alphabet usage uniformity... ");
    fflush(0);

    for (l=0;l<maxlen[i];l++) {
      _s32 min, max;
      float mid, dev;
      if (alsize[i][l] <= 1) continue;
      mid = 20000.0 / alsize[i][l];
      dev = MDEV(alsize[i][l]);
      min = mid - dev;
      max = mid + dev;
      for (c=0;c<256;c++) {
        if (alphabet[i][l][c] && alphabet[i][l][c] < min) {
          if (reported_flaws < 6) {
            if (!reported_flaws) say("FAILED\n");
            reported_flaws++;
          } else skipped_flaws++;

#define say_rep(x...) do { if (reported_flaws < 6) say(x); else say_tofile(x); } while (0)

          say_rep("    Character '%c' is too rare at position #%u (%u, accept min: %d).\n",
                  c,l,alphabet[i][l][c],min);
          badbytes[l]++;
          entropy_loss += port_log2(alsize[i][l]) * 1.0 / alsize[i][l];

        } else if (alphabet[i][l][c] && alphabet[i][l][c] > max) {
          if (reported_flaws < 6) {
            if (!reported_flaws) say("FAILED\n");
            reported_flaws++;
          } else skipped_flaws++;
          say_rep("    Character '%c' is too common at position #%u (%u, accept max: %d).\n",
              c,l,alphabet[i][l][c],max);
          badbytes[l]++;
          entropy_loss += port_log2(alsize[i][l])  * 1.0 / alsize[i][l];
        }
      }
    }

    if (entropy_loss > entbits) entropy_loss = entbits;

    if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
    if (entropy_loss) say("    WARNING: Total %0.02f bits of entropy anomalous (%0.02f OK - %s)\n\n",
                             entropy_loss,entbits-entropy_loss,rate_random(entbits-entropy_loss));

    if (!reported_flaws) say("PASSED\n");

    reported_flaws = skipped_flaws = 0;
    entropy_loss = 0;

    say("[*] Checking alphabet transition uniformity... ");
    fflush(0);

    for (l=0;l<maxlen[i];l++) {
      _u32 c1, c2;
      static _s32 trans[256][256];
      _s32 min, max;
      float mid, dev;

      memset(trans,0,sizeof(trans));

      if (alsize[i][l] <= 1) continue;
      mid = 20000.0 / alsize[i][l] / alsize[i][l];
      dev = MDEV(alsize[i][l]);
      min = mid - dev;
      max = mid + dev;

      for (c=1;c<SAMPLESET;c++) {
        _u32 ll1 = strlen(tval[i][c-1]),
             ll2 = strlen(tval[i][c]);
        _u8 p1 = l < ll1 ? tval[i][c-1][l] : 0;
        _u8 p2 = l < ll2 ? tval[i][c][l] : 0;
        trans[p1][p2]++;
      }

      for (c1=0;c1<256;c1++)
        for (c2=0;c2<256;c2++) {
          if (alphabet[i][l][c1] <= 1 || alphabet[i][l][c2] <= 1) continue;
          if (trans[c1][c2] < min) {
            if (reported_flaws < 6) {
              if (!reported_flaws) say("FAILED\n");
              reported_flaws++;
            } else skipped_flaws++;
            say_rep("    Transition '%c' -> '%c' is too rare at position #%u (%u, accept min: %d).\n",
                    c1,c2,l,trans[c1][c2],min);
            badbytes[l]++;
            entropy_loss += port_log2(alsize[i][l]) * 1.0 / (alsize[i][l] * alsize[i][l]);
          } else if (trans[c1][c2] > max) {
            if (reported_flaws < 6) {
              if (!reported_flaws) say("FAILED\n");
              reported_flaws++;
            } else skipped_flaws++;
            say_rep("    Transition '%c' -> '%c' is too common at position #%u (%u, accept max: %d).\n",
                     c1,c2,l,trans[c1][c2],max);
            badbytes[l]++;
            entropy_loss += port_log2(alsize[i][l]) * 1.0 / (alsize[i][l] * alsize[i][l]);
          }

        }

    }

    if (entropy_loss > entbits) entropy_loss = entbits;

    if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
    if (entropy_loss) say("    WARNING: Total %0.02f bits of entropy anomalous (%0.02f OK - %s)\n\n",
                             entropy_loss,entbits-entropy_loss,rate_random(entbits-entropy_loss));

    if (!reported_flaws) say("PASSED\n");

    if (!no_gmp) {

      /* Use GMP to convert all data to integers */

      say("[*] Converting data to temporal binary streams (GMP)... ");
      fflush(0);

      used_data = entbits;
      ignored_data = 0;

      for (c=0;c<SAMPLESET;c++) {
        _u32 ll = maxlen[i], len, actual_l = strlen(tval[i][c]);
        _u8* text;
        static mpz_t bin_conv;
        mpz_t multiplier;
        _s32 xx;
  
        mpz_init(bin_conv);
        mpz_init_set_ui(multiplier,1);
 
        /* Use a bignum arithmetic approach to deal with non-power-of-two
           alphabet sizes. */
 
        for (xx=ll-1;xx>=0;xx--) {
          _u8 cur_char = xx < actual_l ? tval[i][c][xx] : 0;
          cur_char = al_off[i][xx][cur_char];
          mpz_addmul_ui(bin_conv,multiplier,cur_char);
          mpz_mul_ui(multiplier,multiplier,alsize[i][xx]);
        }

        /* Since there's no mpz_and_ui, and mpz_tdiv_q_2expmpz_div_ui (rshift) 
           is very recent and thus not available everywhere, text conversion
           is actually the most straightforward way to do this. */
  
        text = mpz_get_str(0,2,bin_conv);
  
        len = strlen(text);
        for (l=0;l<len;l++) 
          if (text[len-1-l] == '1') bitstream[l][c/8] |= (1<<(c%8));
        free(text);

        mpz_clear(multiplier);
        mpz_clear(bin_conv);
    
      }
 
      say("done\n");

    } else {

      /* Chop off non-power-of-two alphabets, sorry. */
      say("[*] Converting data to temporal binary streams (non-GMP)... ");
      fflush(0);


      ignored_data = 0;
      used_data = 0;
  
      for (l=0;l<MAXVARLEN;l++) {
        switch (alsize[i][l]) {
  
          /* 0 bits */
          case 1: bitcnt[l] = 0; break;
  
          /* 1 bit */
          case 3: ignored_data += (4-i) / 2.0;
          case 2: bitcnt[l] = 1; used_data += 1; break;
  
          /* 2 bits */
          case 5 ... 7: ignored_data += (8-i) / 4.0;
          case 4: bitcnt[l] = 2; used_data += 2; break;
  
          /* 3 bits */
          case 9 ... 15: ignored_data += (16-i) / 8.0;
          case 8: bitcnt[l] = 3; used_data += 3; break;
  
          /* 4 bits */
          case 17 ... 31: ignored_data += (32-i) / 16.0;
          case 16: bitcnt[l] = 4; used_data += 4; break;
  
          /* 5 bits */
          case 33 ... 63: ignored_data += (64-i) / 32.0;
          case 32: bitcnt[l] = 5; used_data += 5; break;
  
          /* 6 bits */
          case 65 ... 127: ignored_data += (128-i) / 64.0;
          case 64: bitcnt[l] = 6; used_data += 6; break;
  
          /* 7 bits */
          case 129 ... 254: ignored_data += (256-i) / 128.0;
          case 128: bitcnt[l] = 7; used_data += 7; break;
  
          /* 8 bits */
          case 256: bitcnt[l] = 8; used_data += 8; break;
  
        }
      }
  
      for (c=0;c<SAMPLESET;c++) {
        _u32 ll = maxlen[i], actual_l = strlen(tval[i][c]);
        _u32 bitoff = 0;
        _s32 xx;
        /* printf("-- Processing sample #%d: %s --\n",c,tval[i][c]); */

        for (xx=ll-1;xx>=0;xx--) {
          _u32 x;
          _u8 cur_char = xx < actual_l ? tval[i][c][xx] : 0;
  
          /* printf("  Character %d: '%c', translated to value %d, bitcount %d, alsize %d\n",
             l,cur_char,al_off[i][l][cur_char],bitcnt[l],alsize[i][l]); */
  
          cur_char = al_off[i][xx][cur_char];
  
          for (x=0;x<bitcnt[xx];x++) {
  
            /* printf("   Processing bit %d (which is: %d)\n",x,(cur_char&(1<<x)) !=0); */
            /* printf("   Setting bitstream[%d + %d][%d] bit %d\n",bitoff,x,c/8,c%8); */
  
            if (cur_char & (1<<x))
              bitstream[bitoff + x][c/8] |= (1<<(c%8));
          }
  
          /* printf("  Advancing bitoff by %d.\n",x); */
 
          bitoff += x;

        }
  
      }

      say("done\n");

      if (ignored_data) 
        say("    WARNING: Ignored %0.02f%% of data due to fractional bit width alphabets.\n",
               ignored_data * 100.0 / (used_data + ignored_data));

    }

    say("[*] Running FIPS-140-2 monobit test (1/4)... ");
    fflush(0);

    reported_flaws = 0; skipped_flaws = 0;

    for (l=0;l<used_data;l++) {
      _u32 ones = 0;
      for (c=0;c<SAMPLESET;c++)
        if (bitstream[l][c/8] & (1<<(c%8))) ones++;
      if (ones < 9725 || ones > 10275) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (ones = %u, need 9725-10275).\n",l,ones);
        badbits[l]++;
      }
    }

    if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
    if (reported_flaws + skipped_flaws) 
      say("    WARNING: Total %u bits of entropy anomalous (%d OK - %s)\n\n",
                             reported_flaws + skipped_flaws ,used_data-(reported_flaws + skipped_flaws),
                             rate_random(used_data-(reported_flaws + skipped_flaws)));
    else
      say("PASSED\n");

    say("[*] Running FIPS-140-2 poker test (2/4)... ");
    fflush(0);

    reported_flaws = 0; skipped_flaws = 0;

    for (l=0;l<used_data;l++) {
      _u32 valdist[16];
      float sum = 0;
      memset(valdist,0,sizeof(valdist));
      for (c=0;c<SAMPLESET/8;c++) {
        valdist[bitstream[l][c] >> 4]++;
        valdist[bitstream[l][c] & 15]++;
      }

      for (c=0;c<16;c++) sum += valdist[c] * valdist[c];
      sum = 16.0 * sum / 5000.0 - 5000;

      if (sum < 2.16 || sum > 46.17) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (sum = %0.02f, accept: 2.16-46.17).\n",l,sum);
        badbits[l]++;
      }

    }

    if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
    if (reported_flaws + skipped_flaws) 
      say("    WARNING: Total %u bits of entropy anomalous (%d OK - %s)\n\n",
                             reported_flaws + skipped_flaws ,used_data-(reported_flaws + skipped_flaws),
                             rate_random(used_data-(reported_flaws + skipped_flaws)));
    else
      say("PASSED\n");

    say("[*] Running FIPS-140-2 runs test (3/4)... ");
    fflush(0);

    reported_flaws = 0; skipped_flaws = 0;

    for (l=0;l<used_data;l++) {
      _u32 runlen[7];
      _u8 prevbit = 0, crun = 0;
      memset(runlen,0,sizeof(runlen));
      for (c=0;c<SAMPLESET;c++) {
        if (((bitstream[l][c/8] & (1<<(c % 8))) != 0) ^ prevbit) {
          runlen[crun > 6 ? 6 : crun]++;
          prevbit ^= 1;
          crun = 0;
        } else crun++;
      }

      if (runlen[1] < 2315 || runlen[1] > 2685) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (runs[1] = %u, accept: 2315-2685).\n",l,runlen[1]);
        badbits[l]++;
      } else
      if (runlen[2] < 1114 || runlen[2] > 1386) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (runs[2] = %u, accept: 1114-1386).\n",l,runlen[2]);
        badbits[l]++;
      } else
      if (runlen[3] < 527 || runlen[3] > 723) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (runs[3] = %u, accept: 527-723).\n",l,runlen[3]);
        badbits[l]++;
      } else
      if (runlen[4] < 240 || runlen[4] > 384) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (runs[4] = %u, accept: 240-384).\n",l,runlen[4]);
        badbits[l]++;
      } else
      if (runlen[5] < 103 || runlen[5] > 209) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (runs[5] = %u, accept: 103-209).\n",l,runlen[5]);
        badbits[l]++;
      } else
      if (runlen[6] < 103 || runlen[6] > 209) {
        if (reported_flaws < 6) {
          if (!reported_flaws) say("FAILED\n");
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (runs[6+] = %u, accept: 103-209).\n",l,runlen[6]);
        badbits[l]++;
      }

    }

    if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
    if (reported_flaws + skipped_flaws) 
      say("    WARNING: Total %u bits of entropy anomalous (%d OK - %s)\n\n",
                             reported_flaws + skipped_flaws ,used_data-(reported_flaws + skipped_flaws),
                             rate_random(used_data-(reported_flaws + skipped_flaws)));
    else
      say("PASSED\n");

    say("[*] Running FIPS-140-2 longest run test (4/4)... ");
    fflush(0);

    reported_flaws = 0; skipped_flaws = 0;

    for (l=0;l<used_data;l++) {
      _u32 longest = 0;
      _u8 prevbit = 0, crun = 0;
      for (c=0;c<SAMPLESET;c++) {
        if (((bitstream[l][c/8] & (1<<(c % 8))) != 0) ^ prevbit) {
          prevbit ^= 1;
          crun = 0;
        } else crun++;
        if (crun > longest) longest = crun;
      }

      if (longest >= 26) {
        if (!reported_flaws) say("FAILED\n");
        if (reported_flaws < 6) {
          reported_flaws++; 
        } else skipped_flaws++;
        say_rep("    Bit #%u fails the test (longest = %u, accept: 0-25).\n",l,longest);
        badbits[l]++;
      }

    }

    if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
    if (reported_flaws + skipped_flaws) 
      say("    WARNING: Total %u bits of entropy anomalous (%d OK - %s)\n\n",
                             reported_flaws + skipped_flaws ,used_data-(reported_flaws + skipped_flaws),
                             rate_random(used_data-(reported_flaws + skipped_flaws)));
    else
      say("PASSED\n");

#define WINSIZE (1<<window)

    for (window=2;window<=8;window++) {

      _u16 space[WINSIZE][WINSIZE];

      say("[*] Running 2D spectral test (%u bit window)... ",window);
      fflush(0);

      reported_flaws = 0; skipped_flaws = 0;
      entropy_loss = 0;

      for (l=0;l<used_data;l++) {
        _u8 p1 = 0, cur = 0, off;
        _s32 min, max, c1, c2;
        float mid, dev;

        memset(space,0,sizeof(space));

        for (off=0;off<window;off++)
        for (c=off;c<SAMPLESET-window;c += window) {
          p1 = cur;
          cur = ((bitstream[l][c/8] | (bitstream[l][c/8+1] << 8)) >> (c%8)) & (WINSIZE - 1);
          if (c > 1) space[p1][cur]++;
        }

        mid = 20000.0 / (WINSIZE*WINSIZE);
        dev = MDEV(WINSIZE*WINSIZE);
        min = mid - dev;
        if (min < 0) min = 0;
        max = mid + dev;

        for (c1=0;c1<WINSIZE;c1++) for (c2=0;c2<WINSIZE;c2++) {
          if (space[c1][c2] < min || space[c1][c2] > max) {
             if (reported_flaws < 6) {
               if (!reported_flaws) say("FAILED\n");
               reported_flaws++;
             } else skipped_flaws++;
             say_rep("    Bit #%u at (%u,%u): cluster size %u, accept: <%d,%d>\n",
                    l,c1,c2,space[c1][c2],min,max);
             badbits[l]++;
             entropy_loss += 1.0 / (WINSIZE * WINSIZE);
          }
        }
      }

      if (entropy_loss > used_data) entropy_loss = used_data;

      if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
      if (reported_flaws + skipped_flaws) 
        say("    WARNING: Entropy loss estimate %0.02f bits (%0.02f OK - %s)\n\n",
                               entropy_loss ,used_data-entropy_loss,
                               rate_random(used_data-entropy_loss));
      else
        say("PASSED\n");

    }

    for (window=1;window<=4;window++) {

      _u16 space[WINSIZE][WINSIZE][WINSIZE];

      say("[*] Running 3D spectral test (%u bit window)... ",window);
      fflush(0);

      reported_flaws = 0; skipped_flaws = 0;
      entropy_loss = 0;

      for (l=0;l<used_data;l++) {
        _u8 p1 = 0, p2 = 0, cur = 0, off;
        _s32 min, max, c1, c2, c3;
        float mid, dev;

        memset(space,0,sizeof(space));

        for (off=0;off<window;off++)
        for (c=off;c<SAMPLESET-window;c += window) {
          p2 = p1; p1 = cur;
          cur = ((bitstream[l][c/8] | (bitstream[l][c/8+1] << 8)) >> (c%8)) & (WINSIZE - 1);
          if (c > 2) space[p2][p1][cur]++;
        }

        mid = 20000.0 / (WINSIZE*WINSIZE*WINSIZE);
        dev = MDEV(WINSIZE*WINSIZE*WINSIZE);
        min = mid - dev;
        if (min < 0) min = 0;
        max = mid + dev;

        for (c1=0;c1<WINSIZE;c1++) for (c2=0;c2<WINSIZE;c2++) for (c3=0;c3<WINSIZE;c3++) {
          if (space[c1][c2][c3] < min || space[c1][c2][c3] > max) {
             if (reported_flaws < 6) {
               if (!reported_flaws) say("FAILED\n");
               reported_flaws++;
             } else skipped_flaws++;
             say_rep("    Bit #%u at (%u,%u,%u): cluster size %u, accept: <%d,%d>.\n",
                    l,c1,c2,c3,space[c1][c2][c3],min,max);
             entropy_loss += 1.0 / (WINSIZE * WINSIZE * WINSIZE);
             badbits[l]++;
          }
        }
      }

      if (entropy_loss > used_data) entropy_loss = used_data;

      if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
      if (reported_flaws + skipped_flaws) 
        say("    WARNING: Entropy loss estimate: %0.02f bits (%0.02f OK - %s)\n\n",
                               entropy_loss ,used_data-entropy_loss,
                               rate_random(used_data-entropy_loss));
      else
        say("PASSED\n");

    }

    for (window=1;window<=2;window++) {

      _u16 space[WINSIZE][WINSIZE][WINSIZE][WINSIZE][WINSIZE][WINSIZE];

      say("[*] Running 6D spectral test (%u bit window)... ",window);
      fflush(0);

      reported_flaws = 0; skipped_flaws = 0;
      entropy_loss = 0;

      for (l=0;l<used_data;l++) {
        _u8 p1 = 0, p2 = 0, p3 = 0, p4 = 0, p5 = 0, cur = 0, off;
        _s32 min, max, c1, c2, c3, c4, c5, c6;
        float mid, dev;

        memset(space,0,sizeof(space));

        for (off=0;off<window;off++)
        for (c=off;c<SAMPLESET-window;c += window) {
          p5 = p4; p4 = p3; p3 = p2; p2 = p1; p1 = cur;
          cur = ((bitstream[l][c/8] | (bitstream[l][c/8+1] << 8)) >> (c%8)) & (WINSIZE - 1);
          if (c > 5) space[p5][p4][p3][p2][p1][cur]++;
        }

        mid = 20000.0 / (WINSIZE*WINSIZE*WINSIZE*WINSIZE*WINSIZE*WINSIZE);
        dev = MDEV(WINSIZE*WINSIZE*WINSIZE*WINSIZE*WINSIZE);
        min = mid - dev;
        if (min < 0) min = 0;
        max = mid + dev;

        for (c1=0;c1<WINSIZE;c1++) for (c2=0;c2<WINSIZE;c2++) for (c3=0;c3<WINSIZE;c3++) 
        for (c4=0;c4<WINSIZE;c4++) for (c5=0;c5<WINSIZE;c5++) for (c6=0;c6<WINSIZE;c6++) {
          if (space[c1][c2][c3][c4][c5][c6] < min || space[c1][c2][c3][c4][c5][c6] > max) {
             if (reported_flaws < 6) {
               if (!reported_flaws) say("FAILED\n");
               reported_flaws++;
             } else skipped_flaws++;
             say_rep("    Bit #%u at (%u,%u,%u,%u,%u,%u): cluster size %u, accept: <%d,%d>.\n",
                      l,c1,c2,c3,c4,c5,c6,space[c1][c2][c3][c4][c5][c6],min,max);
             entropy_loss += 1.0 / (WINSIZE * WINSIZE * WINSIZE * WINSIZE * WINSIZE * WINSIZE);
             badbits[l]++;
          }
        }
      }

      if (entropy_loss > used_data) entropy_loss = used_data;

      if (skipped_flaws) printf("    (...and %u more...)\n",skipped_flaws);
      if (reported_flaws + skipped_flaws) 
        say("    WARNING: Entropy loss estimate: %0.02f bits (%0.02f OK - %s)\n\n",
                               entropy_loss ,used_data-entropy_loss,
                               rate_random(used_data-entropy_loss));
      else
        say("PASSED\n");

    }

    {
      _u32 b1, b2;

      say("[*] Running spatial correlation checks... ");
      fflush(0);

      reported_flaws = 0; skipped_flaws = 0;
      entropy_loss = 0;

      for (b1=0;b1<((_s32)used_data)-1;b1++) {
        printf("\r[*] Running spatial correlation checks... %0.02f%%",b1 * 100.0 / used_data);
        fflush(0);
        for (b2=b1+1;b2<used_data;b2++) {
          _s32 csum = 0;
          for (c=0;c<SAMPLESET;c++) {
            _u8 b1b = ((bitstream[b1][c/8] & (1<<(c%8))) != 0),
                b2b = ((bitstream[b2][c/8] & (1<<(c%8))) != 0);
            if (b1b ^ b2b) csum--; else csum++;
          }
          if (csum < -725 || csum > 725) {
            if (reported_flaws < 6) {
              if (!reported_flaws) {
                printf("\r[*] Running spatial correlation checks... FAILED\n");
                say_tofile("FAILED\n");
              } else printf("\r");
              reported_flaws++;
            } else skipped_flaws++;
            say_rep("    Bit #%u has a %s correlation with bit #%u (sum = %u, accept max: 725).\n",
                    b2, csum < 0 ? "negative" : "positive", b1, csum < 0 ? -csum : csum);
            entropy_loss += (abs(csum)-725.0)/(SAMPLESET-725.0);
            badbits[b2]++;
          }
        }
      }

      if (entropy_loss > used_data) entropy_loss = used_data;

      if (skipped_flaws) printf("\r    (...and %u more...)"
                                "                                        \n",skipped_flaws);
      if (reported_flaws + skipped_flaws) {
        printf("\r"); 
        say("    WARNING: Entropy loss estimate: %0.02f bits (%0.02f OK - %s)\n\n",
                               entropy_loss ,used_data-entropy_loss,
                               rate_random(used_data-entropy_loss));
      } else {
        printf("\r[*] Running spatial correlation checks... PASSED\n");
        say_tofile("PASSED\n");
      }

    }

    /* Do a quick summary */

    {
       float badbytebitcount = 0;
       _u32  badbitcount = 0;
       _s32  xx;

       for (l=0;l<used_data;l++)
         if (badbits[l]) badbitcount++;

       for (l=0;l<maxlen[i];l++)
         if (badbytes[l]) badbytebitcount += port_log2(alsize[i][l]);

       if (!reported_flaws) say("\n");

       say("RESULTS SUMMARY:\n"
           "  Alphabet-level : %u anomalous bits, %u OK (%s).\n"
           "  Bit-level      : %u anomalous bits, %u OK (%s).\n",
               (_u32)badbytebitcount, (_u32)(entbits - badbytebitcount), rate_random(entbits - badbytebitcount),
               badbitcount, used_data - badbitcount, rate_random(used_data - badbitcount));

       say("\nANOMALY MAP:\n"
           "  Alphabet-level : ");

       for (l=0;l<((maxlen[i] > 60) ? 60 : maxlen[i]);l++) 
         if (alsize[i][l] < 2) printf("o"); else printf("%c",badbytes[l] ? '!' : '.');

       if (maxlen[i] > 60) printf(" (...)\n"); else printf("\n");

       for (l=0;l<maxlen[i];l++) 
         if (alsize[i][l] < 2) say_tofile("o"); else say_tofile("%c",badbytes[l] ? '!' : '.');
       say_tofile("\n");


       say("  Bit-level      : ");

       for (xx=used_data - 1;xx >= (_s32)(used_data > 60 ? used_data - 60 : 0);xx--) 
         printf("%c",badbits[xx] ? '!' : '.'); 
       if (used_data > 60 ) printf(" (...)\n"); else printf("\n");

       for (xx=used_data - 1;xx >= 0;xx--) 
         say_tofile("%c",badbits[xx] ? '!' : '.'); 
       say_tofile("\n");


       if (no_gmp && non_pow2_alpha && badbitcount)
         say("\n"
             "NOTE: Evenly spaced patterns of bit-level failures might indicate inherent conversion\n"
             "      bias caused by non-GMP mode of analysis for non-power-of-two alphabets.\n");

    }

  }


}


static void gather_data(_u8* hostname, _u32 addr, _u16 port, _u8* uri,_u8* fname,_u8* req) {
  struct dyn_recv_buf *rq;
  _u32 code;
  _u8  text[128];
  _u32 i, st_t, cur_t = 0;
  FILE* f = 0;

  if (!read_from_file) {
    f = fopen(fname,"w+");
    if (!f) pfatal(fname);
    say("[*] Capture diverted to '%s'.\n",fname);
    fprintf(f,"stompy %u\n",tcount);
  }

  st_t = time(0);

  for (i=1;i<=SAMPLESET;i++) {
      printf("\r[*] Sending request #%u (%0.02f%% done",i,i/(SAMPLESET / 100.0));
      if (i > 4) {
        _u32 eta = (cur_t - st_t) * (SAMPLESET - i) / (i-1) ;
        printf(", ETA %02uh%02um%02us",eta/3600, (eta/60) % 60, eta % 60);
      }
      printf(")... ");

    fflush(0);

    rq = issue_request(hostname, addr, port, uri, req);

    if (sscanf(rq->buf,"HTTP/1.%*u %u %128[ -~]",&code,text) != 2)
      fatal("Server responded with non-HTTP data.\n");

    grab_analyzed_data(rq,f,i - 1);

    BUF_DESTROY(rq);
    cur_t = time(0);

  }

  if (f) fclose(f);

  if (OUTFILE)
    fprintf(OUTFILE,"    All requests sent.");

  printf(" done");
  say("\n\n");

}


static void usage(_u8* argv0) {
  debug("Usage: %s [ -g ] [ -o file.out ] [ -e file.dat ] [ -p file.req ] http://example.com/\n"
        "       %s [ -g ] [ -o file.out ] ( -R | -A ) filename.txt\n"
        "  -g      - inhibit use of GNU MP library\n"
        "  -o file - write report to specified file [stompy-$date.log]\n"
        "  -e file - write capture data to specified file [stompy-$date.dat]\n"
        "  -p file - use HTTP request from specified file\n"
        "  -R      - read raw tokens from file\n"
        "  -A      - re-analyze tokens from -e file\n",argv0,argv0);
  exit(1);
}


static _u8 reqbuf[8192];

int main(int argc,char** argv) {
  _u8* hostname = 0, *uri = 0, *x = 0, tmp[128];
  _s32 port = 80;
  _u32 d_addr;
  _s32 r;
  _u8  use_file = 0, use_raw = 0;
  _u8 *outfile = 0, *datfile = 0,*reqfile = 0; 

  time_t tm;
  struct hostent* he;

  while ((r = getopt(argc, argv, "RAge:o:p:")) != -1) switch (r) {
    case 'R': use_raw = 1; break;
    case 'A': use_file = 1; break;
    case 'g': no_gmp = 1; break;
    case 'e': datfile = optarg; break;
    case 'o': outfile = optarg; break;
    case 'p': reqfile = optarg; break;
    default: usage(argv[0]);
  }

  if (argc-optind != 1) usage(argv[0]);

  if (use_file && use_raw)
    fatal("-R and -A are mutually exclusive.\n");

  if ((use_file || use_raw) && (datfile || reqfile))
    fatal("-e and -p have no effect when -R or -A is in effect.\n");

  tm = time(0);

  if (!outfile) {
    strftime(tmp,sizeof(tmp) - 1, "stompy-%Y%m%d%H%M%S.out", localtime(&tm));
    OUTFILE = fopen(tmp,"w+");
  } else {
    OUTFILE = fopen(outfile,"w+");
    if (!OUTFILE) pfatal(outfile);
  }

  if (reqfile) {
    _s32 f = open(reqfile,O_RDONLY), n;
    if (f < 0) pfatal(reqfile);
    n = read(f,reqbuf,sizeof(reqbuf)-1);
    close(f);
  }

  if (use_file) {

    read_from_file = fopen(argv[optind],"r");
    if (!read_from_file) pfatal(argv[optind]);

    if (fgets(tmp,32,read_from_file) == 0 || 
        sscanf(tmp,"stompy %u\n",&fields_per_page) != 1)
      fatal("Replay file format mismatch.\n");

  } else if (use_raw) {

    read_from_file = fopen(argv[optind],"r");
    if (!read_from_file) pfatal(argv[optind]);

    reading_from_raw = 1;
    fields_per_page = 1;

  } else {

    hostname = argv[optind];
    if (!strncasecmp(argv[optind],"http://",7)) hostname+=7;
    if (!strncasecmp(argv[optind],"https://",8)) { hostname+=8; use_ssl = 1; port = 443; }
    uri = strchr(hostname,'/');
    if (!uri) uri=""; else { *uri = 0; uri++; }
  
    if ((x = strchr(hostname,':'))) {
      *x = 0;
      port = atoi(x+1);
      if (port <= 0 || port >= 65536) 
        fatal("Invalid port number in URL.\n");
    }

    if (!(he = gethostbyname(hostname)) || !(he->h_addr_list[0]))
      fatal("Unable to resolve host name '%s'.\n",hostname);

    d_addr = *(_u32*)he->h_addr_list[0];
    x = (_u8*) &d_addr;
  }

  say("Session Stomper 0.04 by <lcamtuf@coredump.cx>\n"
      "---------------------------------------------\n\n");

  strftime(tmp, sizeof(tmp) - 1, "%Y/%m/%d %H:%M", localtime(&tm));

  if (!read_from_file) {
    say("Start time  : %s\n"
        "Target host : %s:%d [%u.%u.%u.%u]\n"
        "Target URI  : /%s%s\n\n", tmp, hostname, port,
        x[0], x[1], x[2], x[3], uri,reqfile ? " [custom request]" : "");
  } else {
    say("Start time  : %s\n"
        "Replay file : %s%s (%u fields)\n\n",tmp,argv[optind],
          reading_from_raw ? " [raw]" : "", fields_per_page);
  }

  say("=> Target acquired, ready to issue test requests.\n\n");

  say("[+] Sending initial requests to locate session IDs...\n");

  find_ids(hostname, d_addr, port, uri, reqfile ? reqbuf : 0);

  if (read_from_file) {
    if (fseek(read_from_file,0,SEEK_SET))
      pfatal("lseek on input file");
    if (!reading_from_raw) fgets(tmp,32,read_from_file);
  }

  if (!datfile) strftime(datfile = tmp,sizeof(tmp) - 1, "stompy-%Y%m%d%H%M%S.dat", localtime(&tm));

  gather_data(hostname, d_addr, port, uri, datfile, reqfile ? reqbuf : 0);
  analyze_samples();

  say("\n=> Testing is complete. How about a nice game of chess?\n\n");

  return 0;

}

