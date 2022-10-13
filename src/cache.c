#include <stdlib.h>

#include "cache.h"

int cache_init(Cache *cache, int init_size,
		CacheItem *(*alloc)(void *opaque), void *opaque,
		void (*free)(CacheItem *item))
{
	cache->free_list = NULL;
	cache->alloc = alloc;
	cache->opaque = opaque;
	cache->free = free;

	int i;
	for (i = 0; i < init_size; i++) {
		CacheItem *item = alloc(opaque);
		if (item == NULL) {
			cache_deinit(cache);
			return -1;
		}
		cache_put(cache, item);	
	}

	return 0;
}

CacheItem *cache_get(Cache *cache)
{
	CacheItem *item = cache->free_list;

	if (item) {
		cache->free_list = item->next;	
	} else {
		item = cache->alloc(cache->opaque);	
	}

	return item;
}

void cache_put(Cache *cache, CacheItem *item)
{
	item->next = cache->free_list;
	cache->free_list = item;
}

void cache_deinit(Cache *cache)
{
	while (cache->free_list) {
		CacheItem *item = cache->free_list;
		cache->free_list = item->next;
		cache->free(item);
	}
}
