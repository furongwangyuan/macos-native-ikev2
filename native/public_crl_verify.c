/* Public DER only. No filenames, credentials, database or signing API.
 * Statically linked OpenSSL 3.5.9; no config/provider loading. */
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_CA 16384
#define MAX_CRL 262144
#define MAX_REVOKED 4096
#define DAY 86400LL

typedef struct { BIGNUM *serial; int reason; int64_t when; } ENTRY;
static const char *reason_names[] = {"unspecified", "keyCompromise", "CACompromise",
    "affiliationChanged", "superseded", "cessationOfOperation", NULL, NULL,
    NULL, "privilegeWithdrawn", "AACompromise"};

static void fail(const char *code) {
    fprintf(stderr, "public_crl_rejected:%s\n", code);
    exit(2);
}
static void need(int condition, const char *code) { if (!condition) fail(code); }
static void read_exact(unsigned char *p, size_t n) {
    need(fread(p,1,n,stdin)==n,"input_truncated");
}
static uint32_t u32(const unsigned char *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static uint64_t u64(const unsigned char *p) {
    uint64_t n=0; for(int i=0;i<8;i++) n=(n<<8)|p[i]; return n;
}
static void hex(const unsigned char *p, size_t n) {
    for(size_t i=0;i<n;i++) printf("%02x",p[i]);
}
static BIGNUM *positive(const ASN1_INTEGER *n, const char *code) {
    BIGNUM *v=n?ASN1_INTEGER_to_BN(n,NULL):NULL;
    need(v && !BN_is_negative(v) && !BN_is_zero(v) && BN_num_bits(v)<=159,code);
    return v;
}
static int64_t stamp(const ASN1_TIME *s) {
    struct tm t={0}; const unsigned char *raw; int len, type;
    need(s!=NULL,"time_missing");
    type=ASN1_STRING_type(s);len=ASN1_STRING_length(s);raw=ASN1_STRING_get0_data(s);
    need((type==V_ASN1_UTCTIME&&len==13)||(type==V_ASN1_GENERALIZEDTIME&&len==15),"time_encoding");
    for(int i=0;i<len-1;i++) need(raw[i]>='0'&&raw[i]<='9',"time_encoding");
    need(raw[len-1]=='Z' && ASN1_TIME_to_tm(s,&t)==1,"time_invalid");
    need(t.tm_year>=70 && t.tm_year<=8099,"time_bound");
    need((t.tm_year<150)==(type==V_ASN1_UTCTIME),"time_not_rfc5280_canonical");
    time_t out=timegm(&t);need(out>=0,"time_bound");return (int64_t)out;
}
static void algorithm(const X509_ALGOR *alg) {
    const ASN1_OBJECT *obj=NULL;int ptype=0;const void *value=NULL;
    need(alg!=NULL,"signature_algorithm_missing");
    X509_ALGOR_get0(&obj,&ptype,&value,alg);
    need(OBJ_obj2nid(obj)==NID_sha256WithRSAEncryption&&ptype==V_ASN1_NULL,"signature_algorithm_scope");
}
static int same_name(const X509_NAME *a,const X509_NAME *b) {
    unsigned char *x=NULL,*y=NULL;
    int nx=i2d_X509_NAME(a,&x),ny=i2d_X509_NAME(b,&y);
    int same=nx>0&&nx==ny&&!memcmp(x,y,(size_t)nx);
    OPENSSL_free(x);OPENSSL_free(y);return same;
}
static void cert_extensions(X509 *ca) {
    int seen[4]={0};
    need(X509_get_ext_count(ca)==4,"ca_extension_count");
    for(int i=0;i<4;i++) {
        X509_EXTENSION *e=X509_get_ext(ca,i);
        int nid=OBJ_obj2nid(X509_EXTENSION_get_object(e)),j=-1,critical=0;
        if(nid==NID_basic_constraints){j=0;critical=1;}
        if(nid==NID_key_usage){j=1;critical=1;}
        if(nid==NID_subject_key_identifier)j=2;
        if(nid==NID_authority_key_identifier)j=3;
        need(j>=0&&!seen[j]++&&X509_EXTENSION_get_critical(e)==critical,"ca_extension_scope");
    }
}
static void crl_extensions(X509_CRL *crl) {
    int seen[2]={0};need(X509_CRL_get_ext_count(crl)==2,"crl_extension_count");
    for(int i=0;i<2;i++) {
        X509_EXTENSION *e=X509_CRL_get_ext(crl,i);
        int nid=OBJ_obj2nid(X509_EXTENSION_get_object(e));
        int j=nid==NID_authority_key_identifier?0:nid==NID_crl_number?1:-1;
        need(j>=0&&!seen[j]++&&!X509_EXTENSION_get_critical(e),"crl_extension_scope");
    }
}
static void aki_matches(AUTHORITY_KEYID *a,const ASN1_OCTET_STRING *ski) {
    need(a&&a->keyid&&!a->issuer&&!a->serial,"aki_shape");
    need(ASN1_STRING_length(a->keyid)==20&&ASN1_STRING_length(ski)==20&&
         !memcmp(ASN1_STRING_get0_data(a->keyid),ASN1_STRING_get0_data(ski),20),"aki_key_binding");
}
static int compare_entry(const void *a,const void *b) {
    return BN_cmp(((const ENTRY*)a)->serial,((const ENTRY*)b)->serial);
}
/* Check DER lengths/primitives independently of OpenSSL's cached TBS bytes.
 * Extension OCTET STRING contents are separately decoded/re-encoded below. */
static size_t der_one(const unsigned char *p,size_t available,int depth) {
    need(depth<=24&&available>=2,"der_bound");
    unsigned tag=p[0];size_t off=2,len=p[1];
    need((tag&31)!=31,"der_high_tag_out_of_scope");
    if(len&128) {
        unsigned count=(unsigned)(len&127);len=0;
        need(count>0&&count<=4&&available>=2+count&&p[2]!=0,"der_length");
        for(unsigned i=0;i<count;i++)len=(len<<8)|p[2+i];
        need(len>=128,"der_nonminimal_length");off+=count;
    }
    need(len<=available-off,"der_truncated");const unsigned char *v=p+off;
    if(tag&32) {
        need((tag&192)!=0||tag==0x30||tag==0x31,"der_constructed");
        size_t done=0,previous=0;const unsigned char *old=NULL;
        while(done<len) {
            size_t used=der_one(v+done,len-done,depth+1);
            if(tag==0x31&&old) {
                size_t common=previous<used?previous:used;int c=memcmp(old,v+done,common);
                need(c<0||(c==0&&previous<=used),"der_set_order");
            }
            old=v+done;previous=used;done+=used;
        }
    } else if((tag&192)==0) {
        if(tag==1)need(len==1&&(v[0]==0||v[0]==255),"der_boolean");
        else if(tag==2||tag==10)need(len>0&&(len==1||
            !((v[0]==0&&!(v[1]&128))||(v[0]==255&&(v[1]&128)))),"der_integer");
        else if(tag==3)need(len>=1&&v[0]<=7&&(len>1||v[0]==0)&&
            (len==1||!((v[len-1])&((1U<<v[0])-1))),"der_bit_string");
        else if(tag==5)need(len==0,"der_null");
        else if(tag==6) {
            need(len>0&&!(v[len-1]&128),"der_oid");
            for(size_t i=0;i<len;i++)need(v[i]!=128||(i>0&&(v[i-1]&128)),"der_oid_minimal");
        }
        else need(tag==4||tag==12||tag==18||tag==19||tag==20||tag==22||
                  tag==23||tag==24||tag==26||tag==28||tag==30,"der_primitive_scope");
    }
    return off+len;
}
static void ext_canonical(X509_EXTENSION *e,void *decoded) {
    need(e&&decoded,"extension_decode");
    ASN1_OCTET_STRING *raw=X509_EXTENSION_get_data(e);
    int length=ASN1_STRING_length(raw);
    need(length>0&&der_one(ASN1_STRING_get0_data(raw),(size_t)length,0)==(size_t)length,
         "extension_der_structure");
    X509_EXTENSION *again=X509V3_EXT_i2d(OBJ_obj2nid(X509_EXTENSION_get_object(e)),
                                        X509_EXTENSION_get_critical(e),decoded);
    need(again&&ASN1_OCTET_STRING_cmp(X509_EXTENSION_get_data(e),
                                    X509_EXTENSION_get_data(again))==0,"extension_der");
    X509_EXTENSION_free(again);
}
#define CA_CANON(nid,decoded) ext_canonical(X509_get_ext(ca,X509_get_ext_by_NID(ca,nid,-1)),decoded)
#define CRL_CANON(nid,decoded) ext_canonical(X509_CRL_get_ext(crl,X509_CRL_get_ext_by_NID(crl,nid,-1)),decoded)

int main(int argc,char **argv) {
    (void)argv;need(argc==1,"no_arguments_supported");
    need(!strcmp(OPENSSL_VERSION_STR,"3.5.9") &&
         OpenSSL_version_num()==OPENSSL_VERSION_NUMBER,"openssl_version");
    need(OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG,NULL)==1,"openssl_init");
    unsigned char header[25];read_exact(header,sizeof(header));
    need(!memcmp(header,"FVPNCRL1",8),"input_magic");
    uint32_t nca=u32(header+8),ncrl=u32(header+12);
    uint64_t raw_now=u64(header+16);int historical=header[24];
    need(nca>0&&nca<=MAX_CA&&ncrl>0&&ncrl<=MAX_CRL&&raw_now<=253402300799ULL&&historical<=1,"input_bounds");
    int64_t now=(int64_t)raw_now;
    unsigned char *ca_der=OPENSSL_malloc(nca),*crl_der=OPENSSL_malloc(ncrl),*encoded=NULL;
    need(ca_der&&crl_der,"allocation");read_exact(ca_der,nca);read_exact(crl_der,ncrl);
    need(fgetc(stdin)==EOF&&!ferror(stdin),"input_trailing");
    need(der_one(ca_der,nca,0)==nca&&der_one(crl_der,ncrl,0)==ncrl,"der_trailing");
    const unsigned char *p=ca_der;
    X509 *ca=d2i_X509(NULL,&p,nca);
    need(ca&&p==ca_der+nca,"ca_der_parse");
    need(i2d_re_X509_tbs(ca,&encoded)>0,"ca_der_reencode");OPENSSL_free(encoded);encoded=NULL;
    int n=i2d_X509(ca,&encoded);
    need(n==(int)nca&&!memcmp(encoded,ca_der,nca),"ca_der_roundtrip");OPENSSL_free(encoded);encoded=NULL;
    p=crl_der;X509_CRL *crl=d2i_X509_CRL(NULL,&p,ncrl);
    need(crl&&p==crl_der+ncrl,"crl_der_parse");
    need(i2d_re_X509_CRL_tbs(crl,&encoded)>0,"crl_der_reencode");OPENSSL_free(encoded);encoded=NULL;
    n=i2d_X509_CRL(crl,&encoded);
    need(n==(int)ncrl&&!memcmp(encoded,crl_der,ncrl),"crl_der_roundtrip");OPENSSL_free(encoded);
    need(X509_get_version(ca)==2&&X509_CRL_get_version(crl)==1,"version_scope");
    const ASN1_BIT_STRING *issuer_uid=NULL,*subject_uid=NULL;
    X509_get0_uids(ca,&issuer_uid,&subject_uid);
    need(!issuer_uid&&!subject_uid&&X509_NAME_entry_count(X509_get_subject_name(ca))>0,
         "ca_identity_scope");
    BIGNUM *ca_serial=positive(X509_get0_serialNumber(ca),"ca_serial");BN_free(ca_serial);
    need(same_name(X509_get_subject_name(ca),X509_get_issuer_name(ca)),"ca_not_self_issued");
    need(same_name(X509_get_subject_name(ca),X509_CRL_get_issuer(crl)),"crl_issuer_binding");
    const ASN1_BIT_STRING *signature=NULL;const X509_ALGOR *sigalg=NULL;
    X509_get0_signature(&signature,&sigalg,ca);algorithm(sigalg);algorithm(X509_get0_tbs_sigalg(ca));
    need(X509_ALGOR_cmp(sigalg,X509_get0_tbs_sigalg(ca))==0,"ca_signature_algorithm_mismatch");
    X509_CRL_get0_signature(crl,&signature,&sigalg);algorithm(sigalg);
    EVP_PKEY *key=X509_get_pubkey(ca);BIGNUM *exponent=NULL;
    need(key&&EVP_PKEY_is_a(key,"RSA")&&EVP_PKEY_get_bits(key)==4096,"ca_key_scope");
    need(EVP_PKEY_get_bn_param(key,OSSL_PKEY_PARAM_RSA_E,&exponent)==1&&BN_is_word(exponent,65537),"ca_exponent");
    BN_free(exponent);
    cert_extensions(ca);crl_extensions(crl);
    BASIC_CONSTRAINTS *bc=X509_get_ext_d2i(ca,NID_basic_constraints,NULL,NULL);
    CA_CANON(NID_basic_constraints,bc);
    need(bc&&bc->ca&&bc->pathlen&&ASN1_INTEGER_get(bc->pathlen)==0,"ca_basic_constraints");
    BASIC_CONSTRAINTS_free(bc);
    ASN1_BIT_STRING *ku=X509_get_ext_d2i(ca,NID_key_usage,NULL,NULL);
    CA_CANON(NID_key_usage,ku);
    const unsigned char expected_ku[]={0x03,0x02,0x01,0x06};
    ASN1_OCTET_STRING *raw_ku=X509_EXTENSION_get_data(X509_get_ext(ca,X509_get_ext_by_NID(ca,NID_key_usage,-1)));
    need(ASN1_STRING_length(raw_ku)==4&&!memcmp(ASN1_STRING_get0_data(raw_ku),expected_ku,4),"ca_key_usage_named_bits");
    need(ku&&ASN1_STRING_length(ku)<=2,"ca_key_usage");
    for(int i=0;i<16;i++)need(ASN1_BIT_STRING_get_bit(ku,i)==(i==5||i==6),"ca_key_usage");
    ASN1_BIT_STRING_free(ku);
    ASN1_OCTET_STRING *ski=X509_get_ext_d2i(ca,NID_subject_key_identifier,NULL,NULL);
    CA_CANON(NID_subject_key_identifier,ski);
    need(ski&&ASN1_STRING_length(ski)==20,"ca_ski");
    unsigned char keyhash[SHA_DIGEST_LENGTH];const ASN1_BIT_STRING *pkbits=X509_get0_pubkey_bitstr(ca);
    need(pkbits&&SHA1(ASN1_STRING_get0_data(pkbits),(size_t)ASN1_STRING_length(pkbits),keyhash),"ca_key_hash");
    need(!memcmp(keyhash,ASN1_STRING_get0_data(ski),20),"ca_ski_key_binding");
    AUTHORITY_KEYID *ca_aki=X509_get_ext_d2i(ca,NID_authority_key_identifier,NULL,NULL);
    AUTHORITY_KEYID *crl_aki=X509_CRL_get_ext_d2i(crl,NID_authority_key_identifier,NULL,NULL);
    CA_CANON(NID_authority_key_identifier,ca_aki);CRL_CANON(NID_authority_key_identifier,crl_aki);
    aki_matches(ca_aki,ski);aki_matches(crl_aki,ski);
    AUTHORITY_KEYID_free(ca_aki);AUTHORITY_KEYID_free(crl_aki);ASN1_OCTET_STRING_free(ski);
    int64_t ca_from=stamp(X509_get0_notBefore(ca)),ca_to=stamp(X509_get0_notAfter(ca));
    int64_t last=stamp(X509_CRL_get0_lastUpdate(crl)),next=stamp(X509_CRL_get0_nextUpdate(crl));
    need(ca_from<ca_to&&ca_from<=last&&last<ca_to,"ca_not_valid_at_crl_issue");
    need(last<=now&&next>last&&next-last>=29*DAY&&next-last<=31*DAY,"crl_time_scope");
    if(!historical)need(ca_from<=now&&now<ca_to&&now<next,"current_validity");
    need(X509_verify(ca,key)==1,"ca_self_signature");
    need(X509_CRL_verify(crl,key)==1,"crl_signature");
    EVP_PKEY_free(key);
    ASN1_INTEGER *number=X509_CRL_get_ext_d2i(crl,NID_crl_number,NULL,NULL);
    CRL_CANON(NID_crl_number,number);
    BIGNUM *crlnum=positive(number,"crl_number");ASN1_INTEGER_free(number);
    STACK_OF(X509_REVOKED) *revoked=X509_CRL_get_REVOKED(crl);
    int count=revoked?sk_X509_REVOKED_num(revoked):0;
    need(count>=0&&count<=MAX_REVOKED,"revocation_count");
    ENTRY *entries=calloc((size_t)count+1,sizeof(*entries));need(entries!=NULL,"allocation");
    for(int i=0;i<count;i++) {
        X509_REVOKED *r=sk_X509_REVOKED_value(revoked,i);
        entries[i].serial=positive(X509_REVOKED_get0_serialNumber(r),"revoked_serial");
        entries[i].when=stamp(X509_REVOKED_get0_revocationDate(r));
        need(entries[i].when<=last,"revocation_after_issue");
        int ext=X509_REVOKED_get_ext_count(r);need(ext==0||ext==1,"revoked_extension_count");
        entries[i].reason=0;
        if(ext) {
            X509_EXTENSION *e=X509_REVOKED_get_ext(r,0);
            need(OBJ_obj2nid(X509_EXTENSION_get_object(e))==NID_crl_reason&&
                 !X509_EXTENSION_get_critical(e),"revoked_extension_scope");
            ASN1_ENUMERATED *reason=X509_REVOKED_get_ext_d2i(r,NID_crl_reason,NULL,NULL);
            ext_canonical(e,reason);
            int64_t value=-1;need(reason&&ASN1_ENUMERATED_get_int64(&value,reason)==1,"revoked_reason");
            need(value>=0&&value<=10&&reason_names[value]!=NULL,"revoked_reason_scope");
            entries[i].reason=(int)value;ASN1_ENUMERATED_free(reason);
        }
    }
    qsort(entries,(size_t)count,sizeof(*entries),compare_entry);
    for(int i=1;i<count;i++)need(BN_cmp(entries[i-1].serial,entries[i].serial)!=0,"duplicate_revoked_serial");
    unsigned char ca_hash[SHA256_DIGEST_LENGTH],crl_hash[SHA256_DIGEST_LENGTH];
    need(SHA256(ca_der,nca,ca_hash)&&SHA256(crl_der,ncrl,crl_hash),"digest");
    char *decimal=BN_bn2dec(crlnum);need(decimal!=NULL,"allocation");
    printf("{\"version\":1,\"openssl\":\"3.5.9\",\"ca_sha256\":\"");hex(ca_hash,32);
    printf("\",\"der_sha256\":\"");hex(crl_hash,32);
    printf("\",\"number\":%s,\"this_update\":%lld,\"next_update\":%lld,\"ca_not_before\":%lld,\"ca_not_after\":%lld,\"historical\":%s,\"revocations\":[",
        decimal,(long long)last,(long long)next,(long long)ca_from,(long long)ca_to,
        historical?"true":"false");OPENSSL_free(decimal);BN_free(crlnum);
    for(int i=0;i<count;i++) {
        decimal=BN_bn2dec(entries[i].serial);need(decimal!=NULL,"allocation");
        printf("%s{\"serial\":%s,\"reason\":\"%s\",\"revoked_at\":%lld}",i?",":"",decimal,
            reason_names[entries[i].reason],(long long)entries[i].when);
        OPENSSL_free(decimal);BN_free(entries[i].serial);
    }
    puts("]}");need(!ferror(stdout),"output_write");
    free(entries);X509_free(ca);X509_CRL_free(crl);OPENSSL_free(ca_der);OPENSSL_free(crl_der);
    return 0;
}
