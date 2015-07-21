/* 
 * File:   sniffer.h
 * Author: root
 *
 * Created on 26 Октябрь 2014 г., 23:13
 */

#ifndef SNIFFER_H
#define	SNIFFER_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <pcap/pcap.h>
    
    pcap_t * SnifferInit(char *dev);
    int SnifferClose(pcap_t *handle);
    int SnifferStart(pcap_t *handle);
    int SnifferStop(pcap_t * handle);

#ifdef	__cplusplus
}
#endif

#endif	/* SNIFFER_H */

