#ifndef _NFT_CACHE_H_
#define _NFT_CACHE_H_

struct nft_handle;

void nft_fake_cache(struct nft_handle *h);
void nft_build_cache(struct nft_handle *h, struct nftnl_chain *c);
void nft_rebuild_cache(struct nft_handle *h);
void nft_release_cache(struct nft_handle *h);
void flush_chain_cache(struct nft_handle *h, const char *tablename);
int flush_rule_cache(struct nft_handle *h, const char *table,
		     struct nftnl_chain *c);

struct nftnl_chain_list *
nft_chain_list_get(struct nft_handle *h, const char *table, const char *chain);
struct nftnl_set_list *
nft_set_list_get(struct nft_handle *h, const char *table, const char *set);
struct nftnl_table_list *nftnl_table_list_get(struct nft_handle *h);

#endif /* _NFT_CACHE_H_ */
