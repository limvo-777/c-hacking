#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <time.h>

#include "myheader.h"

unsigned short in_cksum (unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader* ip);

/******************************************************************
  Spoof an ICMP echo request using an arbitrary source IP Address
*******************************************************************/
int main() {
   clock_t start, end, pstart, pend;
   float runtime, createtime;
   char buffer[1500];

   memset(buffer, 0, 1500);
   pstart=clock();

   /*********************************************************
      Step 1: Fill in the ICMP header.
    ********************************************************/
   struct icmpheader *icmp = (struct icmpheader *)
                             (buffer + sizeof(struct ipheader));
   icmp->icmp_type = 8; //ICMP Type: 8 is request, 0 is reply.

   // Calculate the checksum for integrity
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

   /*********************************************************
      Step 2: Fill in the IP header.
    ********************************************************/
   struct ipheader *ip = (struct ipheader *) buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
   ip->iph_destip.s_addr = inet_addr("10.0.2.6");
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct icmpheader));

   pend=clock();
   createtime = (float)(pend-pstart)/CLOCKS_PER_SEC;
   printf("c creating packet time (100) : %.6f \n", createtime);
   /*********************************************************
      Step 3: Finally, send the spoofed packet
    ********************************************************/
   start =clock();
   for (int i=0; i<100; i++)
   {
      send_raw_ip_packet (ip);
   }
   end=clock();
   runtime = (float)(end-start)/CLOCKS_PER_SEC;
   printf("c icmp spoofing time (100) : %.6f \n", runtime);
   return 0;
}

