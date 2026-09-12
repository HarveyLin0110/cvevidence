#include <openssl/ssl.h>
#include <openssl/err.h>
#include <zlib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>

static int backup_roundtrip(void) {
  const unsigned char settings[] = "hostname=fresh-device\ntelemetry=enabled\n";
  unsigned char compressed[512], restored[512];
  unsigned long clen=sizeof(compressed), rlen=sizeof(restored);
  if(compress2(compressed,&clen,settings,sizeof(settings),Z_BEST_SPEED)!=Z_OK)return 1;
  if(uncompress(restored,&rlen,compressed,clen)!=Z_OK)return 2;
  if(rlen!=sizeof(settings)||memcmp(restored,settings,rlen))return 3;
  printf("backup_restore=ok input_bytes=%lu compressed_bytes=%lu zlib=%s\n",(unsigned long)sizeof(settings),clen,zlibVersion());return 0;
}
/* Product TLS entry: socket input reaches SSL_read through the selected TLS method. */
static int serve_once(int socket_fd,const char *cert,const char *key) {
  SSL_CTX *context=SSL_CTX_new(TLSv1_2_server_method());
  if(!context)return 10;
  if(SSL_CTX_use_certificate_file(context,cert,SSL_FILETYPE_PEM)!=1 || SSL_CTX_use_PrivateKey_file(context,key,SSL_FILETYPE_PEM)!=1)return 11;
  SSL *connection=SSL_new(context);char message[128];
  SSL_set_fd(connection,socket_fd);
  if(SSL_accept(connection)!=1){ERR_print_errors_fp(stderr);return 12;}
  int count=SSL_read(connection,message,sizeof(message));
  if(count<=0)return 13;
  int sent=SSL_write(connection,message,count);
  SSL_free(connection);SSL_CTX_free(context);return sent==count?0:14;
}
static int tls_roundtrip(const char *cert,const char *key) {
  int pair[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,pair))return 20;
  pid_t child=fork();if(child<0)return 21;
  if(child==0){close(pair[0]);int r=serve_once(pair[1],cert,key);close(pair[1]);_exit(r);}
  close(pair[1]);SSL_CTX *context=SSL_CTX_new(TLSv1_2_client_method());
  SSL_CTX_set_verify(context,SSL_VERIFY_NONE,NULL);SSL *connection=SSL_new(context);SSL_set_fd(connection,pair[0]);
  if(SSL_connect(connection)!=1){ERR_print_errors_fp(stderr);return 22;}
  const char payload[]="fetch-settings";char received[64];
  if(SSL_write(connection,payload,sizeof(payload))!=(int)sizeof(payload))return 23;
  int count=SSL_read(connection,received,sizeof(received));
  int ok=count==(int)sizeof(payload)&&memcmp(payload,received,sizeof(payload))==0;
  SSL_free(connection);SSL_CTX_free(context);close(pair[0]);int status=0;waitpid(child,&status,0);
  if(!ok||!WIFEXITED(status)||WEXITSTATUS(status))return 24;
  printf("tls_roundtrip=ok protocol=TLSv1.2 transport=local_socketpair openssl=%s\n",SSLeay_version(SSLEAY_VERSION));return 0;
}
static int listen_once(int port,const char *cert,const char *key) {
  int server=socket(AF_INET,SOCK_STREAM,0);if(server<0)return 30;
  struct sockaddr_in address={0};address.sin_family=AF_INET;
  address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
  if(bind(server,(struct sockaddr*)&address,sizeof(address))||listen(server,1))return 31;
  socklen_t size=sizeof(address);if(getsockname(server,(struct sockaddr*)&address,&size))return 32;
  printf("listening_port=%d transport=TCP bind=127.0.0.1 SSL_read_address=%p\n",ntohs(address.sin_port),(void*)SSL_read);
  FILE *maps=fopen("/proc/self/maps","r");char line[1024];
  if(maps){while(fgets(line,sizeof(line),maps))if(strstr(line,"libssl.so")||strstr(line,"device-management"))printf("load_map=%s",line);fclose(maps);}
  fflush(stdout);int client=accept(server,NULL,NULL);if(client<0)return 33;
  int result=serve_once(client,cert,key);close(client);close(server);
  printf("tls_server_receive=%s\n",result==0?"ok":"failed");return result;
}
static int connect_once(int port) {
  int client=socket(AF_INET,SOCK_STREAM,0);if(client<0)return 40;
  struct sockaddr_in address={0};address.sin_family=AF_INET;
  address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
  if(connect(client,(struct sockaddr*)&address,sizeof(address)))return 41;
  SSL_CTX *context=SSL_CTX_new(TLSv1_2_client_method());if(!context)return 42;
  SSL_CTX_set_verify(context,SSL_VERIFY_NONE,NULL);SSL *connection=SSL_new(context);SSL_set_fd(connection,client);
  if(SSL_connect(connection)!=1){ERR_print_errors_fp(stderr);return 43;}
  const char request[]="read-device-settings";char reply[128];
  if(SSL_write(connection,request,sizeof(request))!=(int)sizeof(request))return 44;
  int count=SSL_read(connection,reply,sizeof(reply));
  int result=(count==(int)sizeof(request)&&memcmp(request,reply,sizeof(request))==0)?0:45;
  printf("tls_client_roundtrip=%s protocol=%s openssl=%s\n",result==0?"ok":"failed",SSL_get_version(connection),SSLeay_version(SSLEAY_VERSION));
  SSL_free(connection);SSL_CTX_free(context);close(client);return result;
}
int main(int argc,char **argv) {
  SSL_library_init();SSL_load_error_strings();
  if(argc==5&&strcmp(argv[1],"--serve")==0)return listen_once(atoi(argv[2]),argv[3],argv[4]);
  if(argc==3&&strcmp(argv[1],"--client")==0)return connect_once(atoi(argv[2]));
  if(argc!=3){fprintf(stderr,"usage: device-management certificate.pem key.pem\n");return 64;}
  SSL_library_init();SSL_load_error_strings();int r=backup_roundtrip();if(r)return r;
  return tls_roundtrip(argv[1],argv[2]);
}
