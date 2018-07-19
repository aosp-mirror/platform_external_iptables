#ifndef _NFT_ARP_H_
#define _NFT_ARP_H_

extern char *opcodes[];
#define NUMOPCODES 9

void nft_rule_to_arptables_command_state(const struct nftnl_rule *r,
					 struct iptables_command_state *cs);

#endif
