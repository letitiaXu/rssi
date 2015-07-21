
#include <stdio.h>
#include <stdlib.h>
#include "sniffer.h"
#include "radiotap-parser.h"


static void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static int get_rssi(const u_char *packet, int len, int8_t *rssi);

static int capture_packet_counter=0;

//----------------------------------

pcap_t * SnifferInit(char *dev){    
    char errbuf[PCAP_ERRBUF_SIZE*10];    
    int header_type;    
    int status=0;
    pcap_t *handle=0;
    
    handle=pcap_create(dev,errbuf); //为抓取器打开一个句柄
    if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return 0;
    }
    else{
        printf("Opened device %s\n",dev);
    }
    
    if(pcap_can_set_rfmon(handle)){     //查看是否能设置为监控模式
        printf("Device %s can be opened in monitor mode\n",dev);
    }
    else{
        printf("Device %s can't be opened in monitor mode!!!\n",dev);
    }
    
    pcap_set_rfmon(handle,0);   //设置为监控模式
    if(pcap_set_rfmon(handle,1)!=0){ 
        fprintf(stderr, "Device %s couldn't be opened in monitor mode\n", dev);
        return 0;
    }
    else{
        printf("Device %s has been opened in monitor mode\n", dev);
    }
    pcap_set_promisc(handle,0);   //不设置混杂模式
    pcap_set_snaplen(handle,BUFSIZ);   //设置最大捕获包的长度
    
    status=pcap_activate(handle);   //激活
    if(status!=0){
        pcap_perror(handle,(char*)"pcap error: ");
        return 0;
    }
    
    header_type=pcap_datalink(handle);  //返回链路层的类型
    if(header_type!=DLT_IEEE802_11_RADIO){
        printf("Error: incorrect header type - %d",header_type);
        return 0;            
    }
    
    return handle;
}

//----------------------------------

int SnifferStart(pcap_t * handle){
    pcap_loop(handle,20,packet_process,NULL);   
    return 0;
}

//----------------------------------

int SnifferStop(pcap_t * handle){
    return 0;
}

//----------------------------------

int SnifferClose(pcap_t * handle){
     /* Сlose the session */      
    pcap_close(handle);
    pcap_set_rfmon(handle,0);
    return 0;
}

//----------------------------------

void packet_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    int status=0;
    int8_t rssi=0;
    ++capture_packet_counter;  //计数君
    printf("Packet %d:\n",capture_packet_counter);
    if(header!=0 && packet!=0){        
        
        status=get_rssi(packet,header->len,&rssi);

        if(status!=0){
            if(status==-1){
                printf("\tNo RSSI\n\n");   //没有获取到rssi
                return;
            }
            else{
                printf("Error %d\n",status);
            }
        }
        printf("\tlen=%d \n\tcaplen=%d \n\tRSSI=%i\n",header->len,header->caplen,rssi);        
    }
    else{
        if(!header){            
            printf("Error: no header\n");            
        }
        if(!packet){            
            printf("Error: no packet\n");            
        }
    }
    
}

/* 成功获取rssi返回0
 * 否则返回－1
 */
static int get_rssi(const u_char *packet, int len, int8_t*rssi){
    int status=0, next_arg_index=0;
    struct ieee80211_radiotap_header *header=(struct ieee80211_radiotap_header *)packet;
    struct ieee80211_radiotap_iterator iterator;
    //解析
    if(ieee80211_radiotap_iterator_init(&iterator,header,len)){
        return status;
    }
    //获取rssi
    status=-1;
    do{
        next_arg_index=ieee80211_radiotap_iterator_next(&iterator);        
        if(iterator.this_arg_index==IEEE80211_RADIOTAP_DBM_ANTSIGNAL){
            *rssi=*iterator.this_arg;                        
            status=0;
            break;           
        }

    }while(next_arg_index>=0);
    
    
    return status;
}



int main(int argc, char** argv) {
    char *dev;
    char *default_dev=(char *)"en0";  /*default interface*/   
    pcap_t *handle;
    
    dev=default_dev;    //直接设置为无线网卡
    
    handle=SnifferInit(dev);
    if(handle==0){
        printf("Error, while opening device %s\n",dev);
        return 1;
    }
     
    SnifferStart(handle);       
        
    SnifferClose(handle);    
    
    return(0);
}
