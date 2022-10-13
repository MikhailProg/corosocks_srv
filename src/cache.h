#ifndef CACHE_H
#define CACHE_H

typedef struct Cache Cache;
typedef struct CacheItem CacheItem;

struct CacheItem {
	CacheItem	*next;
};

struct Cache {
	CacheItem 	*free_list;
	CacheItem	*(*alloc)(void *opaque);
	void		*opaque;
	void		(*free)(CacheItem *item);
};

int cache_init(Cache *cache, int init_size,
		CacheItem *(*alloc)(void *opaque), void *opaque,
		void (*free)(CacheItem *item));

CacheItem *cache_get(Cache *cache);

void cache_put(Cache *cache, CacheItem *item);

void cache_deinit(Cache *cache);

#endif
