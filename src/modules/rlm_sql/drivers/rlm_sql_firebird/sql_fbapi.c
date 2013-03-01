/*
 * sql_fbapi.c Part of Firebird rlm_sql driver
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Copyright 2006  The FreeRADIUS server project
 * Copyright 2006  Vitaly Bodzhgua <vitaly@eastera.net>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include "sql_fbapi.h"

#include <stdarg.h>

int fb_lasterror(rlm_sql_firebird_sock *sock) {
 char msg[512+2];
 int l;
 ISC_LONG *pstatus;
 char *p=0;

 sock->sql_code=0;

 if (IS_ISC_ERROR(sock->status)) {
//if error occured, free the previous error's text and create a new one
   pstatus=sock->status;
   if (sock->lasterror) free(sock->lasterror);
   sock->lasterror=0;
   sock->sql_code=isc_sqlcode(sock->status);
   isc_interprete(msg,&pstatus);
   p=strdup(msg);
   msg[0]='.';msg[1]=' ';
   while (isc_interprete(msg+2,&pstatus)) {
     l=strlen(p);
     p=(char *) realloc(p,l+strlen(msg)+2);
     strcat(p,msg);
   }
   sock->lasterror=p;
 } else {
//return empty (but not null) string if there are  no error
  if (sock->lasterror) *sock->lasterror=0;
  else sock->lasterror=strdup("");
 }
 return sock->sql_code;
}


void fb_set_tpb(rlm_sql_firebird_sock * sock, int count,...) {
 int i;
 va_list arg;
 va_start(arg,count);
 sock->tpb=(char *) malloc(count);
 for (i=0; i<count; i++) {
    sock->tpb[i]=(char ) va_arg(arg,int);
 }
 sock->tpb_len=count;
}


void fb_dpb_add_str(char **dpb, char name, char *value) {
 int l;
 if (!value) return;
 l=strlen(value);

 *(*dpb)++ = name;
 *(*dpb)++ = (char ) l;
 memmove(*dpb,value,l);
 *dpb+=l;

}

void fb_free_sqlda(XSQLDA *sqlda) {
 int i;
 for (i=0; i<sqlda->sqld; i++) {
  free(sqlda->sqlvar[i].sqldata);
  free(sqlda->sqlvar[i].sqlind);
 }
 sqlda->sqld=0;
}

void fb_set_sqlda(XSQLDA *sqlda) {
 int i;
 for (i=0; i<sqlda->sqld; i++) {
  if ((sqlda->sqlvar[i].sqltype & ~1)==SQL_VARYING)
    sqlda->sqlvar[i].sqldata = (char*)malloc(sqlda->sqlvar[i].sqllen + sizeof(short));
  else
   sqlda->sqlvar[i].sqldata = (char*)malloc(sqlda->sqlvar[i].sqllen);

  if (sqlda->sqlvar[i].sqltype & 1) sqlda->sqlvar[i].sqlind = (short*)calloc(sizeof(short),1);
  else sqlda->sqlvar[i].sqlind = 0;
 }
}


//Macro for NULLs check
#define IS_NULL(x) (x->sqltype & 1) && (*x->sqlind < 0)

//Structure to manage a SQL_VARYING Firebird's data types
typedef struct vary_fb {
  short vary_length;
  char vary_string[1];
} VARY;

//function fb_store_row based on fiebird's apifull example
void fb_store_row(rlm_sql_firebird_sock *sock) {
 int dtype;
 struct tm times;
 ISC_QUAD bid;
 int i;
 XSQLVAR *var;
 VARY * vary;

//assumed: id,username,attribute,value,op
 if (sock->row_fcount<sock->sqlda_out->sqld)  {
   i=sock->row_fcount;
   sock->row_fcount=sock->sqlda_out->sqld;
   sock->row=(char **) realloc(sock->row,sock->row_fcount*sizeof(char *));
   sock->row_sizes=(int *) realloc(sock->row_sizes,sock->row_fcount*sizeof(int));
   while(i<sock->row_fcount) {
     sock->row[i]=0;
     sock->row_sizes[i++]=0;
   }
 }

for (i=0, var=sock->sqlda_out->sqlvar; i<sock->sqlda_out->sqld; var++,i++) {
//Initial buffer size to store field's data is 256 bytes
  if (sock->row_sizes[i]<256) {
   sock->row[i]=(char *) realloc(sock->row[i],256);
   sock->row_sizes[i]=256;
  }

 if (IS_NULL(var)) {
  strcpy(sock->row[i],"NULL");
  continue;
 }
 dtype=var->sqltype & ~1;
 switch (dtype) {
   case SQL_TEXT:
           if (sock->row_sizes[i]<=var->sqllen) {
	    sock->row_sizes[i]=var->sqllen+1;
	    sock->row[i]=(char *) realloc(sock->row[i],sock->row_sizes[i]);
	   }
	   memmove(sock->row[i],var->sqldata,var->sqllen);
	   sock->row[i][var->sqllen]=0;
	   break;
   case	SQL_VARYING:
	   vary = (VARY*) var->sqldata;
           if (sock->row_sizes[i]<=vary->vary_length) {
	    sock->row_sizes[i]=vary->vary_length+1;
	    sock->row[i]=(char *) realloc(sock->row[i],sock->row_sizes[i]);
	   }
	   memmove(sock->row[i],vary->vary_string,vary->vary_length);
           sock->row[i][vary->vary_length] =0;
           break;

    case SQL_FLOAT:
            snprintf(sock->row[i],sock->row_sizes[i], "%15g", *(float ISC_FAR *) (var->sqldata));
            break;
    case SQL_SHORT:
    case SQL_LONG:
    case SQL_INT64:
		{
		ISC_INT64	value = 0;
		short		field_width = 0;
		short		dscale = 0;
		char *p;
		p=sock->row[i];
		switch (dtype)
		    {
		    case SQL_SHORT:
			value = (ISC_INT64) *(short *) var->sqldata;
			field_width = 6;
			break;
		    case SQL_LONG:
			value = (ISC_INT64) *(int *) var->sqldata;
			field_width = 11;
			break;
		    case SQL_INT64:
			value = (ISC_INT64) *(ISC_INT64 *) var->sqldata;
			field_width = 21;
			break;
		    }
		dscale = var->sqlscale;
		if (dscale < 0)
		    {
		    ISC_INT64	tens;
		    short	j;

		    tens = 1;
		    for (j = 0; j > dscale; j--) tens *= 10;

		    if (value >= 0)
			sprintf (p, "%*lld.%0*lld",
				field_width - 1 + dscale,
				(ISC_INT64) value / tens,
				-dscale,
				(ISC_INT64) value % tens);
		    else if ((value / tens) != 0)
			sprintf (p, "%*lld.%0*lld",
				field_width - 1 + dscale,
				(ISC_INT64) (value / tens),
				-dscale,
				(ISC_INT64) -(value % tens));
		    else
			sprintf (p, "%*s.%0*lld",
				field_width - 1 + dscale,
				"-0",
				-dscale,
				(ISC_INT64) -(value % tens));
		    }
		else if (dscale)
		    sprintf (p, "%*lld%0*d",
			    field_width,
			    (ISC_INT64) value,
			    dscale, 0);
		else
		    sprintf (p, "%*lld",
			    field_width,
			    (ISC_INT64) value);
		}
                break;


    case SQL_DOUBLE: case SQL_D_FLOAT:
  	    snprintf(sock->row[i],sock->row_sizes[i], "%24f", *(double ISC_FAR *) (var->sqldata));
            break;

    case SQL_TIMESTAMP:
		isc_decode_timestamp((ISC_TIMESTAMP ISC_FAR *)var->sqldata, &times);
		snprintf(sock->row[i],sock->row_sizes[i],"%04d-%02d-%02d %02d:%02d:%02d.%04d",
				times.tm_year + 1900,
				times.tm_mon+1,
				times.tm_mday,
				times.tm_hour,
				times.tm_min,
				times.tm_sec,
				((ISC_TIMESTAMP *)var->sqldata)->timestamp_time % 10000);
		break;

    case SQL_TYPE_DATE:
		isc_decode_sql_date((ISC_DATE ISC_FAR *)var->sqldata, &times);
		snprintf(sock->row[i],sock->row_sizes[i], "%04d-%02d-%02d",
				times.tm_year + 1900,
				times.tm_mon+1,
				times.tm_mday);
		break;

    case SQL_TYPE_TIME:
		isc_decode_sql_time((ISC_TIME ISC_FAR *)var->sqldata, &times);
		snprintf(sock->row[i],sock->row_sizes[i], "%02d:%02d:%02d.%04d",
				times.tm_hour,
				times.tm_min,
				times.tm_sec,
				(*((ISC_TIME *)var->sqldata)) % 10000);
		break;

    case SQL_BLOB:
    case SQL_ARRAY:
                /* Print the blob id on blobs or arrays */
                bid = *(ISC_QUAD ISC_FAR *) var->sqldata;
                snprintf(sock->row[i],sock->row_sizes[i],"%08lx:%08lx", bid.gds_quad_high, bid.gds_quad_low);
                break;

 } //END SWITCH
} //END FOR
}


//=================
int fb_init_socket(rlm_sql_firebird_sock *sock) {
    memset(sock, 0, sizeof(*sock));
    sock->sqlda_out = (XSQLDA ISC_FAR *) calloc(XSQLDA_LENGTH (5),1);
    sock->sqlda_out->sqln = 5;
    sock->sqlda_out->version =  SQLDA_VERSION1;
    sock->sql_dialect=3;
#ifdef _PTHREAD_H
    pthread_mutex_init (&sock->mut, NULL);
    radlog(L_DBG,"Init mutex %p\n",&sock->mut);
#endif


//set tpb to read_committed/wait/no_rec_version
    fb_set_tpb(sock,5,
        isc_tpb_version3,
	isc_tpb_wait,
	isc_tpb_write,
	isc_tpb_read_committed,
	isc_tpb_no_rec_version);
    if (!sock->tpb) return -1;
    return 0;
}

int fb_connect(rlm_sql_firebird_sock * sock,rlm_sql_config_t *config) {
 char *p;
 char * database;

 sock->dpb_len=4;
 if (config->sql_login) sock->dpb_len+=strlen(config->sql_login)+2;
 if (config->sql_password) sock->dpb_len+=strlen(config->sql_password)+2;

 sock->dpb=(char *) malloc(sock->dpb_len);
 p=sock->dpb;

 *sock->dpb++ = isc_dpb_version1;
 *sock->dpb++ = isc_dpb_num_buffers;
 *sock->dpb++ = 1;
 *sock->dpb++ = 90;

 fb_dpb_add_str(&sock->dpb,isc_dpb_user_name,config->sql_login);
 fb_dpb_add_str(&sock->dpb,isc_dpb_password,config->sql_password);

 sock->dpb=p;
// Check if database and server in the form of server:database.
// If config->sql_server contains ':', then config->sql_db
// parameter ignored
 if (strchr(config->sql_server,':'))  database=strdup(config->sql_server);
 else {
// Make database and server to be in the form of server:database
  int ls=strlen(config->sql_server);
  int ld=strlen(config->sql_db);
  database=(char *) calloc(ls+ld+2,1);
  strcpy(database,config->sql_server);
  database[ls]=':';
  memmove(database+ls+1,config->sql_db,ld);
 }
 isc_attach_database(sock->status, 0, database, &sock->dbh, sock->dpb_len, sock->dpb);
 free(database);
 return fb_lasterror(sock);
}


int fb_fetch(rlm_sql_firebird_sock *sock) {
 long fetch_stat;
 if (sock->statement_type!=isc_info_sql_stmt_select) return 100;
 fetch_stat=isc_dsql_fetch(sock->status, &sock->stmt, SQL_DIALECT_V6, sock->sqlda_out);
 if (fetch_stat) {
   if (fetch_stat!=100L) fb_lasterror(sock);
   else  sock->sql_code=0;
 }
 return fetch_stat;
}

int fb_prepare(rlm_sql_firebird_sock *sock,char *sqlstr) {
 static char     stmt_info[] = { isc_info_sql_stmt_type };
 char            info_buffer[128];
 short l;

 if (!sock->trh) {
  isc_start_transaction(sock->status,&sock->trh,1,&sock->dbh,sock->tpb_len,sock->tpb);
  if (!sock->trh) return -4;
 }

 fb_free_statement(sock);
 if (!sock->stmt) {
   isc_dsql_allocate_statement(sock->status, &sock->dbh, &sock->stmt);
   if (!sock->stmt) return -1;
 }

 fb_free_sqlda(sock->sqlda_out);
 isc_dsql_prepare(sock->status, &sock->trh, &sock->stmt, 0, sqlstr, sock->sql_dialect, sock->sqlda_out);
 if (IS_ISC_ERROR(sock->status)) return -2;

 if (sock->sqlda_out->sqln<sock->sqlda_out->sqld) {
   sock->sqlda_out->sqln=sock->sqlda_out->sqld;
   sock->sqlda_out = (XSQLDA ISC_FAR *) realloc(sock->sqlda_out, XSQLDA_LENGTH (sock->sqlda_out->sqld));
   isc_dsql_describe(sock->status,&sock->stmt,SQL_DIALECT_V6,sock->sqlda_out);
   if (IS_ISC_ERROR(sock->status)) return -3;
 }

//get statement type
 isc_dsql_sql_info(sock->status, &sock->stmt, sizeof (stmt_info), stmt_info,sizeof (info_buffer), info_buffer);
 if (IS_ISC_ERROR(sock->status)) return -4;

 l = (short) isc_vax_integer((char ISC_FAR *) info_buffer + 1, 2);
 sock->statement_type = isc_vax_integer((char ISC_FAR *) info_buffer + 3, l);

 if (sock->sqlda_out->sqld) fb_set_sqlda(sock->sqlda_out); //set out sqlda

 return 0;
}


int fb_sql_query(rlm_sql_firebird_sock *sock,char *sqlstr) {
 if (fb_prepare(sock,sqlstr)) return fb_lasterror(sock);
 switch (sock->statement_type) {
    case isc_info_sql_stmt_exec_procedure:
         isc_dsql_execute2(sock->status, &sock->trh, &sock->stmt, SQL_DIALECT_V6,0,sock->sqlda_out);
	 break;
    default:
         isc_dsql_execute(sock->status, &sock->trh, &sock->stmt, SQL_DIALECT_V6,0);
	 break;
 }
 return fb_lasterror(sock);
}

int fb_affected_rows(rlm_sql_firebird_sock *sock) {
 static char    count_info[] = {isc_info_sql_records};
 char            info_buffer[128];
 char *p ;
 int affected_rows=-1;

 if (!sock->stmt) return -1;

 isc_dsql_sql_info(sock->status, &sock->stmt,
    sizeof (count_info), count_info,sizeof (info_buffer), info_buffer);
 if (IS_ISC_ERROR(sock->status)) return fb_lasterror(sock);

 p=info_buffer+3;
 while (*p != isc_info_end) {
       p++;
       short len = (short)isc_vax_integer(p,2);
       p+=2;
       affected_rows = isc_vax_integer(p,len);
       if (affected_rows>0) break;
       p += len;
 }
 return affected_rows;
}

int fb_close_cursor(rlm_sql_firebird_sock *sock) {
 isc_dsql_free_statement(sock->status, &sock->stmt, DSQL_close);
 return fb_lasterror(sock);
}

void fb_free_statement(rlm_sql_firebird_sock *sock) {
 if (sock->stmt) {
  isc_dsql_free_statement(sock->status, &sock->stmt, DSQL_drop);
  sock->stmt=0;
 }
}

int fb_rollback(rlm_sql_firebird_sock *sock) {
    sock->sql_code=0;
    if (sock->trh)  {
       isc_rollback_transaction (sock->status,&sock->trh);
//       sock->in_use=0;
#ifdef _PTHREAD_H
	 pthread_mutex_unlock(&sock->mut);
#endif

       if (IS_ISC_ERROR(sock->status)) {
         return fb_lasterror(sock);
       }
    }
    return sock->sql_code;
}

int fb_commit(rlm_sql_firebird_sock *sock) {
    sock->sql_code=0;
    if (sock->trh)  {
       isc_commit_transaction (sock->status,&sock->trh);
       if (IS_ISC_ERROR(sock->status)) {
         fb_lasterror(sock);
	 radlog(L_ERR,"Fail to commit. Error: %s. Try to rollback.\n",sock->lasterror);
	 return fb_rollback(sock);
       }
    }
//    sock->in_use=0;
#ifdef _PTHREAD_H
    pthread_mutex_unlock(&sock->mut);
#endif
    return sock->sql_code;
}

int fb_disconnect(rlm_sql_firebird_sock *sock) {
 if (sock->dbh) {
   fb_free_statement(sock);
   isc_detach_database(sock->status,&sock->dbh);
   return fb_lasterror(sock);
 }
 return 0;
}

void fb_destroy_socket(rlm_sql_firebird_sock *sock) {
 int i;
 fb_commit(sock);
 if (fb_disconnect(sock)) {
  radlog(L_ERR,"Fatal. Fail to disconnect DB. Error :%s\n",sock->lasterror);
 }
#ifdef _PTHREAD_H
 pthread_mutex_destroy (&sock->mut);
#endif
 for (i=0; i<sock->row_fcount;i++) free(sock->row[i]);
 free(sock->row);free(sock->row_sizes);
 fb_free_sqlda(sock->sqlda_out);
 free(sock->sqlda_out);
 free(sock->tpb);
 free(sock->dpb);
 if (sock->lasterror) free(sock->lasterror);
 memset(sock,0,sizeof(rlm_sql_firebird_sock));
}
