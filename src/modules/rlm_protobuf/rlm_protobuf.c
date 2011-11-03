/**
 * RLM_PROTOBUF
 *     interact with http service via protocol buffer.
 *
 * Copyright 2011 Ruslan Shevchenko <ruslan@shevchenko.kiev.ua> Kiev, Ukraine.
 **/
 

#include <pthread.h>

#include <freeradius-devel/radius.h>
#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/libradius.h>
#include <freeradius-devel/modules.h>

#include <curl/curl.h>

#include "vsa.pb-c.h"

#define AUTHORIZE  1
#define AUTHENTICATE 2
#define PREACCOUNT  3
#define ACCOUNT    4
#define CHECKSIM    5
#define POSTAUTH    6


typedef struct rlm_protobuf_t {
  char*  uri;
  char*  method;
  int    verbose;
  int    authenticate;
  int    authorize;
  int    preaccount;
  int    account;
  int    checksim;
  int    postauth;
  int    input_buffer_size;
  int    timeout;
} rlm_protobuf_t;

static const CONF_PARSER module_config[] = {
  { "url" , PW_TYPE_STRING_PTR, offsetof(rlm_protobuf_t,uri), NULL, NULL },
  { "method" , PW_TYPE_STRING_PTR, offsetof(rlm_protobuf_t,method), NULL, NULL },
  { "verbose", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,verbose), NULL, "no" },
  { "authenticate", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,authenticate), NULL, "yes" },
  { "authorize", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,authorize), NULL, "yes" },
  { "preaccount", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,preaccount), NULL, "yes" },
  { "account", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,account), NULL, "yes" },
  { "checksim", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,checksim), NULL, "yes" },
  { "postauth", PW_TYPE_BOOLEAN, offsetof(rlm_protobuf_t,postauth), NULL, "no" },
  { "input_buffer_size", PW_TYPE_INTEGER, offsetof(rlm_protobuf_t,input_buffer_size), NULL, "1024" },
  { "timeout", PW_TYPE_INTEGER, offsetof(rlm_protobuf_t,timeout), NULL, "30" },
  { NULL, -1, 0, NULL, NULL }
};


static pthread_key_t curl_key;
static pthread_once_t curl_once = PTHREAD_ONCE_INIT;

static void rlm_curl_make_key(void);
static CURL* rlm_curl_create_curlhandle(rlm_protobuf_t* instance);
static void rlm_curl_destroy_curlhandle(CURL*);


static void rlm_curl_make_key(void)
{
  pthread_key_create(&curl_key, rlm_curl_destroy_curlhandle);
}

static CURL* get_threadspecific_curl_handle(rlm_protobuf_t* instance)
{
  CURL* retval = (CURL*)pthread_getspecific(curl_key);
  if (retval==NULL) {
     retval=rlm_curl_create_curlhandle(instance);
     pthread_setspecific(curl_key,retval);
  }
  return retval;
}

static CURL* rlm_curl_create_curlhandle(rlm_protobuf_t* instance)
{
  CURL* retval = curl_easy_init();
  curl_easy_setopt(retval,CURLOPT_URL,instance->uri);
  if (instance->verbose) {
       curl_easy_setopt(retval,CURLOPT_VERBOSE,1);
 }
  return retval;
}

static void rlm_curl_destroy_curlhandle(CURL* handle)
{
 if (handle!=NULL) {
    curl_easy_cleanup(handle);
 }
}

static int rlm_protobuf_instantiate(CONF_SECTION* conf, void ** instance)
{
 rlm_protobuf_t* data;
 data = rad_malloc(sizeof(*data));
 if (!data) {
    return -1;
 }
 memset(data,0,sizeof(*data));

 if (cf_section_parse(conf, data, module_config) < 0) {
      free(data);
      return -1;
 }

 CURLcode rcode = curl_global_init(CURL_GLOBAL_ALL);
 if (rcode!=0) {
     radlog(L_ERR, "can't init curl %d",rcode);
     free(data);
     return -1;
 }

 *instance=data;

 pthread_once(&curl_once, rlm_curl_make_key);
 
 return 0;
}

static int rlm_protobuf_detach(void* instance)
{
 curl_global_cleanup();
 free(instance);
 return 0;
}


static void fill_protobuf_vp(Org__Freeradius__ValuePair* cvp, 
                             VALUE_PAIR* pair,
                             ProtobufCAllocator* allocator)
{
  cvp->attribute = pair->attribute;
  if (pair->vendor != 0) {
      cvp->has_vendor = 1;
      cvp->vendor = pair->vendor;
  }
  uint8_t* tmpptr=NULL;
  uint32_t tmpuint32=0;
  switch(pair->type) {
        case PW_TYPE_STRING:
               cvp->string_value = allocator->alloc(allocator->allocator_data,pair->length+1);
               strncpy(cvp->string_value,pair->vp_strvalue,pair->length+1);
               break;
         case PW_TYPE_INTEGER:
               cvp->has_int_value = 1;
               cvp->int_value = pair->vp_integer;
               break;
         case PW_TYPE_IPADDR:
               cvp->has_ipv4addr_value = 1;
               cvp->ipv4addr_value = htonl(pair->vp_ipaddr);
               break;
         case PW_TYPE_DATE:
               cvp->has_date_value = 1;
               cvp->date_value = pair->vp_date;
               break;
         case PW_TYPE_ABINARY:
         case PW_TYPE_OCTETS:
               cvp->has_octets_value = 1;
               cvp->octets_value.len = pair->length;
               cvp->octets_value.data = allocator->alloc(allocator->allocator_data,pair->length);
               memcpy(cvp->octets_value.data, pair->vp_strvalue, pair->length);
               break;
         case PW_TYPE_IFID:
               cvp->has_ifid_value = 1;
               cvp->ifid_value = (
                      (((((((
                      ((((((((uint64_t)(pair->vp_ifid[0])<<8)+pair->vp_ifid[1])<<8)+
                                        pair->vp_ifid[2])<<8)+pair->vp_ifid[3])<<8)+
                                        pair->vp_ifid[4])<<8)+pair->vp_ifid[5])<<8)+
                                        pair->vp_ifid[6])<<8)+pair->vp_ifid[7])
                     );
               break;
         case PW_TYPE_IPV6ADDR:
               cvp->ipv6addr_value = allocator->alloc(allocator->allocator_data,sizeof(Org__Freeradius__IpV6Addr));
               memset(cvp->ipv6addr_value,0,sizeof(Org__Freeradius__IpV6Addr));
               cvp->ipv6addr_value->base.descriptor = &org__freeradius__ip_v6_addr__descriptor;
               tmpptr=(uint8_t*)(&pair->vp_ipv6addr);
               cvp->ipv6addr_value->addr1 = (
                      (((((((
                      ((((((((uint64_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                        tmpptr[2])<<8)+tmpptr[3])<<8)+
                                        tmpptr[4])<<8)+tmpptr[5])<<8)+
                                        tmpptr[6])<<8)+tmpptr[7])
                     );
	       tmpptr+=8;
               cvp->ipv6addr_value->addr2 = (
                      (((((((
                      ((((((((uint64_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                        tmpptr[2])<<8)+tmpptr[3])<<8)+
                                        tmpptr[4])<<8)+tmpptr[5])<<8)+
                                        tmpptr[6])<<8)+tmpptr[7])
                     );
               break;
         case PW_TYPE_IPV6PREFIX:
               cvp->ipv6prefix_value = allocator->alloc(allocator->allocator_data,sizeof(Org__Freeradius__IpV6Prefix));
               memset(cvp->ipv6prefix_value,0,sizeof(Org__Freeradius__IpV6Prefix));
               cvp->ipv6prefix_value->base.descriptor = &org__freeradius__ip_v6_prefix__descriptor;
                /* see rfc4818 */
               tmpptr=(uint8_t*)pair->vp_ipv6prefix;
               tmpuint32=tmpptr[1]; // length.
               cvp->ipv6prefix_value->description = (
                      (((((((uint32_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                        tmpptr[2])<<8)+tmpptr[3])
                                      );
               if (tmpuint32 > 4) {
                 tmpptr+=4;
                 cvp->ipv6prefix_value->has_prefix1 = 1;
                 cvp->ipv6prefix_value->prefix1 = (
                      (((((((uint32_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                       tmpptr[2])<<8)+tmpptr[3])
                 );
               }
               if (tmpuint32 > 8) {
                 tmpptr+=4;
                 cvp->ipv6prefix_value->has_prefix2 = 1;
                 cvp->ipv6prefix_value->prefix2 = (
                      (((((((uint32_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                       tmpptr[2])<<8)+tmpptr[3])
                 );
               }
               if (tmpuint32 > 12) {
                 tmpptr+=4;
                 cvp->ipv6prefix_value->has_prefix3 = 1;
                 cvp->ipv6prefix_value->prefix3 = (
                      (((((((uint32_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                       tmpptr[2])<<8)+tmpptr[3])
                 );
               }
               if (tmpuint32 > 16) {
                 tmpptr+=4;
                 cvp->ipv6prefix_value->has_prefix4 = 1;
                 cvp->ipv6prefix_value->prefix4 = (
                      (((((((uint32_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                       tmpptr[2])<<8)+tmpptr[3])
                 );
               }
               break;
         case PW_TYPE_BYTE:
               cvp->has_byte_value = 1;
               cvp->byte_value = pair->vp_integer;
               break;
         case PW_TYPE_SHORT:
               cvp->has_short_value = 1;
               cvp->short_value = pair->vp_integer;
               break;
         case PW_TYPE_ETHERNET:
               cvp->has_macaddr_value = 1;
               tmpptr=(uint8_t*)pair->vp_ether;
               cvp->macaddr_value = (
                          (((
                      ((((((((uint64_t)(tmpptr[0])<<8)+tmpptr[1])<<8)+
                                        tmpptr[2])<<8)+tmpptr[3])<<8)+
                                        tmpptr[4])<<8)+tmpptr[5])
                                    );
               break;
         case PW_TYPE_SIGNED:
               cvp->has_signed_value = 1;
               cvp->signed_value = pair->vp_signed;
               break;
         case PW_TYPE_COMBO_IP:
               cvp->has_comboip_value = 1;
               cvp->comboip_value.len = pair->length;
               cvp->comboip_value.data = allocator->alloc(allocator->allocator_data,pair->length);
               memcpy(cvp->comboip_value.data,pair->vp_octets,pair->length);
               break;
         case PW_TYPE_TLV:
               cvp->has_tlv_value = 1;
               cvp->tlv_value.len = pair->length;
               cvp->tlv_value.data = allocator->alloc(allocator->allocator_data,pair->length);
               memcpy(cvp->tlv_value.data,pair->vp_tlv,pair->length);
               break;
         case PW_TYPE_EXTENDED:
               cvp->has_extended_value = 1;
               cvp->extended_value.len = pair->length;
               cvp->extended_value.data = allocator->alloc(allocator->allocator_data,pair->length);
               memcpy(cvp->extended_value.data,pair->vp_octets,pair->length);
               break;
         case PW_TYPE_EXTENDED_FLAGS:
               cvp->has_extended_flags_value = 1;
               cvp->extended_flags_value.len = pair->length;
               cvp->extended_flags_value.data = allocator->alloc(allocator->allocator_data,pair->length);
               memcpy(cvp->extended_flags_value.data,pair->vp_octets,pair->length);
               break;
         case PW_TYPE_INTEGER64:
               cvp->has_int64_value = 1;
               cvp->int64_value = pair->vp_integer64;
               break;
         default:
               radlog(L_ERR,"unimplemented radius VSA type %d, skip",pair->type);
               break;
  }
}
                             

static Org__Freeradius__RequestData* 
                        code_protobuf_request( int method, 
                                      REQUEST* request,
                                      ProtobufCAllocator* allocator)
{
 RADIUS_PACKET* packet = request->packet;
 VALUE_PAIR* pair;
 Org__Freeradius__RequestData* request_data = 
                   allocator->alloc(allocator->allocator_data,
                                   sizeof(Org__Freeradius__RequestData));
 Org__Freeradius__RequestData tmp = ORG__FREERADIUS__REQUEST_DATA__INIT ;
 *request_data = tmp;
 request_data->state = method;
 request_data->n_vps = 0;
 if (packet!=NULL) {
   int n_pairs = 0;
   for(pair = packet->vps; pair != NULL; pair = pair->next) {
       ++n_pairs;
   }
   if (n_pairs > 0) {
      request_data->n_vps = n_pairs;
      request_data->vps = allocator->alloc(allocator->allocator_data,sizeof(Org__Freeradius__ValuePair*)*n_pairs);
   }
   int i=0;
   for(pair = packet->vps; pair != NULL; pair = pair->next) {
      Org__Freeradius__ValuePair* cvp = allocator->alloc(allocator->allocator_data,sizeof(Org__Freeradius__ValuePair));
      Org__Freeradius__ValuePair tmp1 = ORG__FREERADIUS__VALUE_PAIR__INIT;
      *cvp = tmp1;
      request_data->vps[i++]=cvp;
      fill_protobuf_vp(cvp,pair,allocator);
   }
 }
 return request_data;
}

static void copy_byte_buffer(VALUE_PAIR* vp, ProtobufCBinaryData* ppbuff, int* errflg, char* attrname)
{
 if(ppbuff->len > sizeof(vp->vp_octets)) {
    radlog(L_ERR,"rlm_protobuf: too long byte sequence for attribute %s, truncate", attrname);
    memcpy( &(vp->vp_octets), ppbuff->data, sizeof(vp->vp_octets));
    vp->length = sizeof(vp->vp_octets);
    *errflg=2;
 } else {
    memcpy(vp->vp_octets, ppbuff->data, ppbuff->len);
    vp->length = ppbuff->len;
 }
}

static VALUE_PAIR* create_radius_vp(Org__Freeradius__ValuePair* cvp,
                                    int* errflg)
{
  DICT_ATTR* attr = dict_attrbyvalue(cvp->attribute,
                                     (cvp->has_vendor ? cvp->vendor : 0));
  VALUE_PAIR* vp;
  if (attr==NULL) {
     radlog(L_ERR,"skipping unknown attribute %d, %d",cvp->attribute,
                                     (cvp->has_vendor ? cvp->vendor : 0));
     return NULL;
  }
  vp = pairalloc(attr);
  *errflg=0;
  switch (attr->type) {
     case PW_TYPE_STRING:
          if (cvp->string_value!=NULL) {
            int maxLen = sizeof(vp->vp_strvalue);
            int sLen = strlen(cvp->string_value);
            if (sLen >= maxLen) {
               radlog(L_ERR,"too long string for attribute %s, truncate", attr->name);
               strncpy(vp->vp_strvalue,cvp->string_value,maxLen);
               vp->vp_strvalue[maxLen-1]='\0';
               vp->length=maxLen;
               *errflg=2;
            } else {
               strncpy(vp->vp_strvalue,cvp->string_value,maxLen);
               vp->length=sLen;
            }
          } else {
               radlog(L_ERR,"attribute %s must be string, have %d", attr->name, attr->type);
               *errflg=1;
          }
          break;
     case PW_TYPE_INTEGER:
          if (cvp->has_int_value) {
              vp->vp_integer=cvp->int_value;
              vp->length=sizeof(vp->vp_integer);
          } else {
             radlog(L_ERR,"attribute %s must be integer, have %d", attr->name, attr->type);
             *errflg=1;
          }
          break;
     case PW_TYPE_IPADDR:
          if (cvp->has_ipv4addr_value) {
            vp->vp_ipaddr = ntohl(cvp->ipv4addr_value); 
            vp->length=sizeof(vp->vp_ipaddr);
          } else if (cvp->string_value!=NULL) {
            int rc = inet_pton(AF_INET, cvp->string_value, &(vp->vp_ipaddr));
            if (rc < 0) {
              char message[255];
              strerror_r(errno,message,255);
              radlog(L_ERR,"error during parsing ip_addr %s (%s)", attr->name,
                            message);
              *errflg=1;
            } else if (rc==0) {
              radlog(L_ERR,"invalid ip for %s (%s)", attr->name,cvp->string_value);
              *errflg=1;
            }
          } else {
             radlog(L_ERR,"attribute %s must be ipaddr", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_DATE:
          if (cvp->has_date_value) {
            vp->vp_date = cvp->date_value; 
            vp->length=sizeof(vp->vp_date);
          } else {
             radlog(L_ERR,"attribute %s must be ipaddr", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_ABINARY:
     case PW_TYPE_OCTETS:
          if (cvp->has_octets_value) {
             copy_byte_buffer(vp, &(cvp->octets_value), errflg, attr->name);
          } else {
             radlog(L_ERR,"attribute %s must be bytes", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_IFID:
          if (cvp->has_ifid_value) {
            uint64_t v = cvp->ifid_value;
            vp->vp_ifid[7]=(v & 0xFF); v>>=8;
            vp->vp_ifid[6]=(v & 0xFF); v>>=8;
            vp->vp_ifid[5]=(v & 0xFF); v>>=8;
            vp->vp_ifid[4]=(v & 0xFF); v>>=8;
            vp->vp_ifid[3]=(v & 0xFF); v>>=8;
            vp->vp_ifid[2]=(v & 0xFF); v>>=8;
            vp->vp_ifid[1]=(v & 0xFF); v>>=8;
            vp->vp_ifid[0]=(v & 0xFF);
            vp->length=sizeof(vp->vp_ifid);
          } else {
             radlog(L_ERR,"attribute %s must be ifid", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_IPV6ADDR:
          if (cvp->ipv6addr_value!=NULL) {
            uint64_t v = cvp->ipv6addr_value->addr1;
            uint8_t* p = (uint8_t*)&(vp->vp_ipv6addr); 
            p[7]=(v&0xFF); v>>=8;
            p[6]=(v&0xFF); v>>=8;
            p[5]=(v&0xFF); v>>=8;
            p[4]=(v&0xFF); v>>=8;
            p[3]=(v&0xFF); v>>=8;
            p[2]=(v&0xFF); v>>=8;
            p[1]=(v&0xFF); v>>=8;
            p[0]=(v&0xFF); 
            v=cvp->ipv6addr_value->addr2;
            p+=8;
            p[7]=(v&0xFF); v>>=8;
            p[6]=(v&0xFF); v>>=8;
            p[5]=(v&0xFF); v>>=8;
            p[4]=(v&0xFF); v>>=8;
            p[3]=(v&0xFF); v>>=8;
            p[2]=(v&0xFF); v>>=8;
            p[1]=(v&0xFF); v>>=8;
            p[0]=(v&0xFF); 
            vp->length=sizeof(vp->vp_ipv6addr);
          } else if (cvp->string_value!=NULL) {
            int rc = inet_pton(AF_INET6, cvp->string_value, &(vp->vp_ipv6addr));
            vp->length=sizeof(vp->vp_ipv6addr);
            if (rc < 0) {
              char message[255];
              strerror_r(errno,message,255);
              radlog(L_ERR,"error during parsing ip_addr %s (%s)", attr->name,
                            message);
              *errflg=1;
            } else if (rc==0) {
              radlog(L_ERR,"invalid ip for %s (%s)", attr->name, cvp->string_value);
              *errflg=1;
            } 
          } else {
              radlog(L_ERR,"rlm_protobuf: reply: invalid type for ip6 address in %s", attr->name);
              *errflg=1;
          }
          break;
     case PW_TYPE_IPV6PREFIX:
          if (cvp->ipv6prefix_value!=NULL) {
             uint16_t descr = cvp->ipv6prefix_value->description;
             int len = descr & 0xFF;
             memset(&vp->vp_ipv6prefix,0,sizeof(vp->vp_ipv6prefix));
             vp->vp_ipv6prefix[1]=(descr>>8);
             vp->vp_ipv6prefix[0]=len;
             uint32_t v = cvp->ipv6prefix_value->prefix1;
             if (cvp->ipv6prefix_value->has_prefix1) {
                vp->vp_ipv6prefix[5]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[4]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[3]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[2]=(v&0xff); 
             } 
             if (cvp->ipv6prefix_value->has_prefix2) {
                v = cvp->ipv6prefix_value->prefix2;
                vp->vp_ipv6prefix[9]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[8]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[7]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[6]=(v&0xff); 
             }
             if (cvp->ipv6prefix_value->has_prefix3) {
                v = cvp->ipv6prefix_value->prefix3;
                vp->vp_ipv6prefix[13]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[12]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[11]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[10]=(v&0xff); 
             }
             if (cvp->ipv6prefix_value->has_prefix4) {
                v = cvp->ipv6prefix_value->prefix4;
                vp->vp_ipv6prefix[17]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[16]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[15]=(v&0xff); v>>=8;
                vp->vp_ipv6prefix[14]=(v&0xff); 
             }
             vp->length=sizeof(vp->vp_ipv6prefix);
          } else {
             radlog(L_ERR,"rlm_protobuf: reply: invalid type for ip6 prefix in %s", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_BYTE:
          if (cvp->has_byte_value) {
            vp->vp_integer = cvp->byte_value;
            vp->length=sizeof(vp->vp_integer);
          } else {
            radlog(L_ERR,"rlm_protobuf: reply: invalid type for byte in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_SHORT:
          if (cvp->has_short_value) {
            vp->vp_integer = cvp->short_value;
            vp->length=sizeof(vp->vp_integer);
          } else {
            radlog(L_ERR,"rlm_protobuf: reply: invalid type for short in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_ETHERNET:
          if (cvp->has_macaddr_value) {
            uint64_t v = cvp->macaddr_value;
            vp->vp_ether[5] = (v & 0xFF); v >>= 8; 
            vp->vp_ether[4] = (v & 0xFF); v >>= 8; 
            vp->vp_ether[3] = (v & 0xFF); v >>= 8; 
            vp->vp_ether[2] = (v & 0xFF); v >>= 8; 
            vp->vp_ether[1] = (v & 0xFF); v >>= 8; 
            vp->vp_ether[1] = (v & 0xFF);  
            vp->length=sizeof(vp->vp_ether);
          } else {
            radlog(L_ERR,"rlm_protobuf: reply: invalid type for ether address in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_SIGNED:
          if (cvp->has_signed_value) {
            vp->vp_signed = cvp->signed_value;
            vp->length=sizeof(vp->vp_signed);
          } else {
            radlog(L_ERR,"rlm_protobuf: reply: invalid type for signed attr in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_COMBO_IP:
          if (cvp->has_comboip_value) {
             memcpy(&vp->vp_octets,cvp->comboip_value.data,cvp->comboip_value.len);
             vp->length=cvp->comboip_value.len;
          } else {
            radlog(L_ERR,"rlm_protobuf: reply: invalid type for comboip attr in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_TLV:
          if (cvp->has_tlv_value) {
             vp->vp_tlv = malloc(cvp->tlv_value.len);
             memcpy(vp->vp_tlv,cvp->tlv_value.data,cvp->tlv_value.len);
             vp->length=cvp->tlv_value.len;
          } else {
             radlog(L_ERR,"rlm_protobuf: reply: invalid type for tlv attr in %s", attr->name);
             *errflg=1;
          }
          break;
     case PW_TYPE_EXTENDED:
          if (cvp->has_extended_value) {
            copy_byte_buffer(vp, &(cvp->extended_value), errflg, attr->name);
          } else {
            radlog(L_ERR,"rlm_protobuf: reply: invalid type for extended attr in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_EXTENDED_FLAGS:
          if (cvp->has_extended_flags_value) {
            copy_byte_buffer(vp, &(cvp->extended_flags_value), errflg, attr->name);
          } else {
            radlog(L_ERR,"rlm_protobuf: reply: invalid type for extended flags attr in %s", attr->name);
            *errflg=1;
          }
          break;
     case PW_TYPE_INTEGER64:
          if (cvp->has_int64_value) {
            vp->vp_integer64 = cvp->int64_value;
            vp->length=sizeof(vp->vp_integer64);
          } else {
            radlog(L_ERR,"reply: invalid type for integer64 attr in %s", attr->name);
            *errflg=1;
          }
          break;
     default:
         radlog(L_ERR,"reply: uninmplemented VSA type for %s", attr->name);
         *errflg=1;
  }
  
  return vp;
}

static int adapt_protobuf_reply(int method,
                                Org__Freeradius__RequestDataReply* rdr, 
                                REQUEST* request
                               )
{
  int retval = rdr->has_allow ? 
                  (rdr->allow ? RLM_MODULE_OK : RLM_MODULE_REJECT) 
                  : RLM_MODULE_OK ;
  unsigned int i=0;
  if  (rdr->error_message!=NULL) {
     radlog(L_ERR,"rlm_protobuf: error from protoserver: %s",rdr->error_message);
     return RLM_MODULE_INVALID;
  }
  
  for(i=0; i < rdr->n_actions; ++i) {
     int errflg=0;
     Org__Freeradius__ValuePairAction* action = rdr->actions[i]; 
     Org__Freeradius__ValuePair* cvp = action->vp; 
     if (action->op == ORG__FREERADIUS__VALUE_PAIR_OP__REMOVE) {
         pairdelete(&(request->reply->vps),cvp->attribute,
                                           cvp->has_vendor ? cvp->vendor : 0 );
     } else {
       VALUE_PAIR* vp = create_radius_vp(cvp,&errflg);
       if (vp!=NULL) {
         if (errflg==0 || errflg==2) {
           /* some attributes must be inserted to request->config-items, 
            * not reply
            */
           if (method==AUTHORIZE
              &&(  vp->attribute==PW_AUTH_TYPE
                 ||vp->attribute==PW_CLEARTEXT_PASSWORD
                )
              ) {
             if (action->op == ORG__FREERADIUS__VALUE_PAIR_OP__REPLACE) {
                pairreplace(&(request->config_items), vp);
             } else {
                pairadd(&(request->config_items), vp);
             }
           } else {
             if (action->op == ORG__FREERADIUS__VALUE_PAIR_OP__REPLACE) {
                pairreplace(&(request->reply->vps),vp);
             } else {
                pairadd(&(request->reply->vps),vp);
             }
           }
         } else {
           /* removed incorrect. */
           pairfree(&vp);
         }
       } else {
         /* incorrect attribute: just skip. */
       }
     }
  }

  return retval; 
}

struct BufferWithAllocator
{
 ProtobufCBufferSimple buffer;
 int                   idx;
 ProtobufCAllocator* allocator;
};
typedef struct BufferWithAllocator  BufferWithAllocator;

static size_t rlm_protobuf_read_function( void *ptr, 
                                          size_t size, 
                                          size_t nmemb, 
                                          void *userdata)
{
 BufferWithAllocator* pba = (BufferWithAllocator*)userdata;
 size_t bytesRequired = size*nmemb;
 size_t bytesLeft = (size_t)(pba->buffer.len - pba->idx);
 size_t bytesToTransfer = (bytesLeft > bytesRequired ? bytesRequired 
                                                     : bytesLeft);
 memcpy(ptr,pba->buffer.data+pba->idx,bytesToTransfer);
 pba->idx += bytesToTransfer;
 return bytesToTransfer;
}

static size_t rlm_protobuf_write_function( char *ptr, 
                                    size_t size, 
                                    size_t nmemb, 
                                    void *userdata)
{
 BufferWithAllocator* pba = (BufferWithAllocator*)userdata;
 size_t nBytes = size*nmemb;
 pba->buffer.base.append(&pba->buffer.base,nBytes,(void*)ptr);
 return nBytes;
}


static int do_protobuf_curl_call(rlm_protobuf_t* instance, int method, REQUEST* request)
{
 CURL* handle = get_threadspecific_curl_handle(instance);
 CURLcode rc;
 int retval;
 struct BufferWithAllocator rba = {
    /*PROTOBUF_C_BUFFER_SIMPLE_INIT({}),*/
     { 
       { protobuf_c_buffer_simple_append }, 
      0, 0, NULL , 0 
      },
    0,
    &protobuf_c_default_allocator
 };
 struct BufferWithAllocator wba = {
    /*PROTOBUF_C_BUFFER_SIMPLE_INIT({}),*/
     {
       { protobuf_c_buffer_simple_append }, 
       0, 0, NULL , 0 
      },
    0,
    &protobuf_c_default_allocator
 };
 char errbuff[CURL_ERROR_SIZE];
 Org__Freeradius__RequestData* proto_request = 
         code_protobuf_request(method,request, &protobuf_c_default_allocator);
                                                         
 rba.buffer.alloced = org__freeradius__request_data__get_packed_size(proto_request);
 rba.buffer.data = rba.allocator->alloc(rba.allocator->allocator_data,rba.buffer.alloced);
 rba.buffer.must_free_data=1;
 org__freeradius__request_data__pack_to_buffer(proto_request, 
                                              & rba.buffer.base);

 wba.buffer.alloced = 1024;
 wba.buffer.data = wba.allocator->alloc(wba.allocator->allocator_data,wba.buffer.alloced);
 wba.buffer.must_free_data=1;

 curl_easy_setopt(handle, CURLOPT_UPLOAD, 1);
 curl_easy_setopt(handle, CURLOPT_INFILESIZE, rba.buffer.len);
 curl_easy_setopt(handle, CURLOPT_READFUNCTION, rlm_protobuf_read_function);
 curl_easy_setopt(handle, CURLOPT_READDATA, &rba);
 curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, rlm_protobuf_write_function);
 curl_easy_setopt(handle, CURLOPT_WRITEDATA, &wba);

 curl_easy_setopt(handle,CURLOPT_ERRORBUFFER,errbuff);
 rc=curl_easy_perform(handle);
 if (rc!=0) {
   radlog(L_ERR,"%s",errbuff);
   curl_easy_cleanup(handle);
   pthread_setspecific(curl_key,NULL);
   retval = RLM_MODULE_INVALID;
 }else {
   retval=RLM_MODULE_NOOP;
 }
 if (instance->verbose) {
   radlog(L_DBG,"received:%d bytes",(int)wba.buffer.len);
 }
 org__freeradius__request_data__free_unpacked(proto_request,rba.allocator);
 rba.allocator->free(rba.allocator->allocator_data,rba.buffer.data);
 if (rc==0) {
    // i. e. whe have no errors in curl
    //
    Org__Freeradius__RequestDataReply* proto_reply = 
       org__freeradius__request_data_reply__unpack(wba.allocator,
                                                   wba.buffer.len,
                                                   wba.buffer.data);

    retval = adapt_protobuf_reply(method, proto_reply, request); 
    org__freeradius__request_data_reply__free_unpacked(
                                                proto_reply,wba.allocator);
    wba.allocator->free(wba.allocator->allocator_data, wba.buffer.data);
 } else {
    if (wba.buffer.data!=NULL) {
       wba.allocator->free(wba.allocator->allocator_data, wba.buffer.data);
    }
 }
 return retval;
}

static int rlm_protobuf_authenticate(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_autheinticate");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->authenticate) {
   return do_protobuf_curl_call(tinstance, AUTHENTICATE, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

static int rlm_protobuf_authorize(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_authorize");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 int retval = RLM_MODULE_NOOP;
 int set_auth_type = FALSE ;
 if (tinstance->authorize) {
   retval = do_protobuf_curl_call(tinstance, AUTHORIZE, request);
   if (retval == RLM_MODULE_OK && tinstance->authenticate) {
      set_auth_type = TRUE;
   }
 } else {
   set_auth_type = tinstance->authenticate;
 }
 if (set_auth_type) {
     pairadd(&request->config_items,
             pairmake("Auth-Type", "PROTOBUF", T_OP_EQ));
     retval = RLM_MODULE_OK;
 }
 return retval;
}

static int rlm_protobuf_preaccount(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_preaccount");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->preaccount) {
   return do_protobuf_curl_call(tinstance, PREACCOUNT, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}


static int rlm_protobuf_account(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_account");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->account) {
   return do_protobuf_curl_call(tinstance, ACCOUNT, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

static int rlm_protobuf_checksim(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_checksim");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->checksim) {
   return do_protobuf_curl_call(tinstance, CHECKSIM, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

static int rlm_protobuf_postauth(void* instance, REQUEST* request)
{
 radlog(L_DBG, "rlm_protobuf_postauth");
 rlm_protobuf_t* tinstance = (rlm_protobuf_t*)instance; 
 if (tinstance->postauth) {
   return do_protobuf_curl_call(tinstance, POSTAUTH, request);
 } else {
   return RLM_MODULE_NOOP;
 }
}

module_t rlm_protobuf = {
 RLM_MODULE_INIT,
 "protobuf",
 RLM_TYPE_THREAD_SAFE,
 rlm_protobuf_instantiate,
 rlm_protobuf_detach,
 {
   rlm_protobuf_authenticate,
   rlm_protobuf_authorize,
   rlm_protobuf_preaccount,
   rlm_protobuf_account,
   rlm_protobuf_checksim,  /* checksim */
   NULL,  /* pre-proxy */
   NULL, /* post-proxy */
   rlm_protobuf_postauth  /* post-auth */
 }
};


