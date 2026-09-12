#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc,char **argv) {
  if(argc!=2){fprintf(stderr,"usage: update-reader update.gz\n");return 64;}
  FILE *input=fopen(argv[1],"rb");if(!input){perror("open");return 66;}
  z_stream stream={0};gz_header header={0};
  unsigned char extra[32], chunk[8], output[256];
  header.extra=extra;header.extra_max=sizeof(extra);
  if(inflateInit2(&stream,31)!=Z_OK)return 70;
  if(inflateGetHeader(&stream,&header)!=Z_OK)return 71;
  int result=Z_OK;unsigned long produced=0;
  while(result!=Z_STREAM_END) {
    if(stream.avail_in==0) {
      stream.avail_in=fread(chunk,1,sizeof(chunk),input);stream.next_in=chunk;
      if(stream.avail_in==0){fprintf(stderr,"update input incomplete: gzip stream ended before trailer\n");inflateEnd(&stream);fclose(input);return 2;}
    }
    stream.avail_out=sizeof(output);stream.next_out=output;
    result=inflate(&stream,Z_NO_FLUSH);produced+=sizeof(output)-stream.avail_out;
    if(result!=Z_OK&&result!=Z_STREAM_END){fprintf(stderr,"gzip error: %s\n",stream.msg?stream.msg:"unknown");inflateEnd(&stream);fclose(input);return 3;}
  }
  printf("update_read=ok zlib=%s extra_len=%u extra_capacity=%u chunk_bytes=%lu output_bytes=%lu\n",zlibVersion(),header.extra_len,header.extra_max,(unsigned long)sizeof(chunk),produced);
  inflateEnd(&stream);fclose(input);return 0;
}
