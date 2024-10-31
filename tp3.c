#include "tp3.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_ALPHA 0.6
#define SEED 0

uint32_t
murmurhash (const char *key, uint32_t len, uint32_t seed) {
  uint32_t c1 = 0xcc9e2d51;
  uint32_t c2 = 0x1b873593;
  uint32_t r1 = 15;
  uint32_t r2 = 13;
  uint32_t m = 5;
  uint32_t n = 0xe6546b64;
  uint32_t h = 0;
  uint32_t k = 0;
  uint8_t *d = (uint8_t *) key; // 32 bit extract from `key'
  const uint32_t *chunks = NULL;
  const uint8_t *tail = NULL; // tail - last 8 bytes
  int i = 0;
  int l = len / 4; // chunk length

  h = seed;

  chunks = (const uint32_t *) (d + l * 4); // body
  tail = (const uint8_t *) (d + l * 4); // last 8 byte chunk of `key'

  // for each 4 byte chunk of `key'
  for (i = -l; i != 0; ++i) {
    // next 4 byte chunk of `key'
    k = chunks[i];

    // encode next 4 byte chunk of `key'
    k *= c1;
    k = (k << r1) | (k >> (32 - r1));
    k *= c2;

    // append to hash
    h ^= k;
    h = (h << r2) | (h >> (32 - r2));
    h = h * m + n;
  }

  k = 0;

  // remainder
  switch (len & 3) { // `len % 4'
    case 3: k ^= (tail[2] << 16);
    case 2: k ^= (tail[1] << 8);

    case 1:
      k ^= tail[0];
      k *= c1;
      k = (k << r1) | (k >> (32 - r1));
      k *= c2;
      h ^= k;
  }

  h ^= len;

  h ^= (h >> 16);
  h *= 0x85ebca6b;
  h ^= (h >> 13);
  h *= 0xc2b2ae35;
  h ^= (h >> 16);

  return h;
}

typedef uint32_t hash_t;
hash_t hash(const char* key, size_t m){
  return murmurhash(key, (hash_t)strlen(key), SEED) % (hash_t)m;
}
//Hashing cerrado con probing lineal
typedef struct elem_t{
  char* key;
  void* value;
  bool borrado;
}elem_t;


struct dictionary {
  size_t cantidad;
  size_t m;
  elem_t* elems;
  destroy_f destroy;
  size_t borrados;
};

dictionary_t *dictionary_create(destroy_f destroy) {
  dictionary_t* dic = malloc(sizeof(dictionary_t));
  if(dic == NULL){
    return NULL;
  }
  dic->cantidad = 0;
  dic->m = 100;
  dic->elems = malloc(sizeof(elem_t)*dic->m);
  if(dic->elems == NULL){
    free(dic);
    return NULL;
  }
  dic->destroy = destroy;
  dic->borrados = 0;

  for(size_t i = 0; i < dic->m; i++){
    dic->elems[i].key = NULL;
    dic->elems[i].value = NULL;
    dic->elems[i].borrado = false;
  }
  return dic;
};

bool dictionary_put(dictionary_t *dictionary, const char *key, void *value) {
  if (!dictionary || !key) return false;
  
  size_t borrados = dictionary->borrados;
  size_t cantidad = dictionary->cantidad;
  size_t m = dictionary->m;
  size_t index = hash(key, m);
  float alpha = (float)(cantidad + borrados) / (float)m;

  if (alpha < MAX_ALPHA) {
    for (size_t i = 0; i < m; i++) {
      if(!dictionary->elems[index].key || strcmp(dictionary->elems[index].key,key)==0){
        dictionary->elems[index].key = malloc(strlen(key)+1);
        if(!dictionary->elems[index].key) return false;
        strcpy(dictionary->elems[index].key,key);
        dictionary->elems[index].value = value;
        dictionary->cantidad++;
        return true;
      }else{
      index = (index + 1) % m;
      }
    }
  } else {
    dictionary_t *new_dic = dictionary_create(dictionary->destroy);
    if (!new_dic) return false;
    
    new_dic->m = m * 2;
    new_dic->elems = malloc(sizeof(elem_t) * new_dic->m);
    if (!new_dic->elems) {
      free(new_dic);
      return false;
    }
    
    for (size_t i = 0; i < new_dic->m; i++) {
      new_dic->elems[i].key = NULL;
      new_dic->elems[i].value = NULL;
      new_dic->elems[i].borrado = false;
    }

    for (size_t i = 0; i < m; i++) {
      if (dictionary->elems[i].key) {
        dictionary_put(new_dic, dictionary->elems[i].key, dictionary->elems[i].value);
        dictionary->destroy(dictionary->elems[i].value);
      }
    }

    free(dictionary->elems);
    *dictionary = *new_dic;
    free(new_dic);
    return dictionary_put(dictionary, key, value);
  }

  return false;
}


void *dictionary_get(dictionary_t *dictionary, const char *key, bool *err) {
  return NULL;
};

bool dictionary_delete(dictionary_t *dictionary, const char *key) {
  return true;
};

void *dictionary_pop(dictionary_t *dictionary, const char *key, bool *err) {
  return NULL;
};

bool dictionary_contains(dictionary_t *dictionary, const char *key) {
  size_t index = hash(key,dictionary->m);

  for (size_t i = 0; i < dictionary->m; i++) {
    if(!dictionary->elems[index].key && dictionary->elems[index].borrado == false) return false;
    if(strcmp(dictionary->elems[index].key, key) == 0) return true;
    index = (index + 1) % dictionary->m;
  }
  return false;
};

size_t dictionary_size(dictionary_t *dictionary) { return dictionary->cantidad; };

void dictionary_destroy(dictionary_t *dictionary){
  for(size_t i = 0; i < dictionary->m; i++){
    if(dictionary->elems[i].key){
      free(dictionary->elems[i].key);
      dictionary->destroy(dictionary->elems[i].value);
    }
  }
  free(dictionary->elems);
  free(dictionary);
};
