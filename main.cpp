#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <iostream>
#include <set>
#include <ctime>

using namespace std;
set <string> malicious_sites;
int block = 0;

typedef struct libnet_ipv4_hdr
{
    uint8_t ip_v;       /* version */
    uint8_t ip_tos;       /* type of service */
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    uint32_t shost_Addr;
    uint32_t dhost_Addr;
}*ip_hdr;

typedef struct libnet_tcp_hdr
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */
    uint8_t th_off;        /* data offset */
    uint8_t  th_flags;       /* control flags */
    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
}*tcp_hdr;


void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}


/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	char site[1000];
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;
	unsigned char *packet_end;
	block = 0;
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0){
		if((((ip_hdr)data)->ip_v >> 4) == 4){
			if(((ip_hdr)data)->ip_p == 6){
				packet_end = (uint8_t *)data + ret;
				data = (uint8_t *)data + ((((ip_hdr)data)->ip_v & 0x0F) << 2);
				data = (uint8_t *)data + (((((tcp_hdr)data)->th_off) >> 4) << 2);
				if(strncasecmp((const char*)data,"GET",3)==0||strncasecmp((const char*)data,"POST",4)==0){
					for(int i=0;(uint8_t *)data+i<packet_end;i++){
						if(!strncmp((const char *)(data + i), "Host: ",6)){
							data = (uint8_t *)data + i + 6;
							break;
						}
					}
					
					printf("\nsite = ");
					for(int j=0;(uint8_t *)data+j<=packet_end;j++){
						if(data[j] == '\n'){
							site[j-1] = '\0';
							break;
						}
						site[j] = data[j];
						printf("%c",site[j]);
					}
					printf("\n");
					if(malicious_sites.count(string(site))){
						printf("blocked\n");
						block = 1;
					}
					else{
						for(int i=0;i<strlen(site);i++){
							if(site[i]=='.'){
								if(malicious_sites.count(string(site+1+i))){
									printf("blocked\n");
									block = 1;
									break;
								}
							}
						}
					}
									
				}
			}
		}
	}
	fputc('\n', stdout);
	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(block){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else{
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}
}

void usage(void) {
	printf("syntax : 1m-block <site list file>\n");
	printf("sample : 1m-block top-1m.txt\n");
}

int main(int argc, char **argv)
{
	if(argc != 2){
		usage();
		exit(1);
	}

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	long start_t, end_t;
	
	start_t = clock();
	FILE *fp = fopen(argv[1], "r");
	char line[1000];
	while(fgets(line, sizeof(line), fp))
	{	
		int i;
		line[strlen(line)-1] = '\0';
		for(i=0; i<strlen(line); i++)
		{
			if(line[i] != ',') continue;
			i++;
			break;
		}
		string mal_site(&line[i]);
		malicious_sites.insert(mal_site);
	}
	fclose(fp);
	end_t = clock();
	printf("CLOCKS PER SEC: %ld\n", CLOCKS_PER_SEC);
	printf("%ldclocks elapsed to load list\n", end_t - start_t);
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			start_t = clock();
			nfq_handle_packet(h, buf, rv);
			end_t = clock();
			printf("%ldclocks elapsed\n\n", end_t - start_t);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
