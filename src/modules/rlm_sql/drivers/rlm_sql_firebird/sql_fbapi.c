/*
 * sql_fbapi.c	Part of Firebird rlm_sql driver
 *
 * Copyright 2006  Vitaly Bodzhgua <vitaly@eastera.net>
 */

#include "sql_fbapi.h"

#include <stdarg.h>

int fb_lasterror(rlm_sql_firebird_sock *sock) {
 char msg[512];
 int l;
 ISC_LONG *pstatus;
 char *p=0;
 
 sock->sql_code=0;
 
 if (IS_ISC_ERROR(sock->status)) {
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


int fb_prepare(rlm_sql_firebird_sock *sock,char *sqlstr) {
 static char     stmt_info[] = { isc_info_sql_stmt_type };
 char            info_buffer[20];
 short l;
 
 //isc_dsql_free_statement(sock->status, &sock->stmt, DSQL_close);
 
 fb_free_sqlda(sock->sqlda_out);
 if (!sock->trh) 
    isc_start_transaction(sock->status,&sock->trh,1,&sock->dbh,sock->tpb_len,sock->tpb);
  
 if (!sock->stmt) {
   isc_dsql_allocate_statement(sock->status, &sock->dbh, &sock->stmt);
   if (!sock->stmt) return -1;
 }

 isc_dsql_prepare(sock->status, &sock->trh, &sock->stmt, 0, sqlstr, sock->sql_dialect, sock->sqlda_out);
 if (IS_ISC_ERROR(sock->status)) return -2;
  
 if (sock->sqlda_out->sqln<sock->sqlda_out->sqld) {
   sock->sqlda_out->sqln=sock->sqlda_out->sqld;
   sock->sqlda_out = (XSQLDA ISC_FAR *) realloc(sock->sqlda_out, XSQLDA_LENGTH (sock->sqlda_out->sqld));
   isc_dsql_describe(sock->status,&sock->stmt,SQL_DIALECT_V6,sock->sqlda_out);    
   if (IS_ISC_ERROR(sock->status)) return -3;
 }

//get sql type  
 isc_dsql_sql_info(sock->status, &sock->stmt, sizeof (stmt_info), stmt_info,sizeof (info_buffer), info_buffer);
 if (IS_ISC_ERROR(sock->status)) return -4; 
  
 l = (short) isc_vax_integer((char ISC_FAR *) info_buffer + 1, 2);
 sock->statement_type = isc_vax_integer((char ISC_FAR *) info_buffer + 3, l);
  
 if (sock->sqlda_out->sqld) fb_set_sqlda(sock->sqlda_out); //set out sqlda
  
 return 0;
}

#define IS_NULL(x) (x->sqltype & 1) && (*x->sqlind < 0)

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
		ISC_INT64	value;
		short		field_width;
		short		dscale;
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
                snprintf(sock->row[i],sock->row_sizes[i],"%08x:%08x", bid.gds_quad_high, bid.gds_quad_low);
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
//set tpb to read_committed/wait    
    fb_set_tpb(sock,5,isc_tpb_version3, isc_tpb_write, isc_tpb_read_committed,
	      isc_tpb_no_rec_version,isc_tpb_wait);
    if (!sock->tpb) return -1;	      
    return 0;
}

int fb_connect(rlm_sql_firebird_sock * sock,SQL_CONFIG *config) {
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
 if (strchr(config->sql_server,':'))  database=strdup(config->sql_server);
 else {
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
//   isc_commit_transaction(sock->status,&sock->trh);
//   isc_dsql_free_statement(sock->status, &sock->stmt, DSQL_close);
 }
 return fetch_stat;
 
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
 fb_lasterror(sock);
 if (sock->sql_code) fb_free_result(sock);
      
 return sock->sql_code;
}

int fb_disconnect(rlm_sql_firebird_sock *sock) {
 if (sock->dbh) {
   isc_detach_database(sock->status,&sock->dbh);
   return fb_lasterror(sock);
 }  
 return 0;
}


void fb_destroy_socket(rlm_sql_firebird_sock *sock) {
 int i;
 fb_free_result(sock);
 isc_dsql_free_statement(sock->status, &sock->stmt, DSQL_drop);
 fb_disconnect(sock);
 for (i=0; i<sock->row_fcount;i++) free(sock->row[i]);
 free(sock->row);free(sock->row_sizes);
 free(sock->sqlda_out); free(sock->tpb); free(sock->dpb);
 if (sock->lasterror) free(sock->lasterror);
 memset(sock,0,sizeof(rlm_sql_firebird_sock));
}

int fb_free_result(rlm_sql_firebird_sock *sock) {
 isc_commit_transaction(sock->status,&sock->trh);
 isc_dsql_free_statement(sock->status, &sock->stmt, DSQL_close);
 fb_free_sqlda(sock->sqlda_out);
 sock->statement_type=0;
 return 0;
}
