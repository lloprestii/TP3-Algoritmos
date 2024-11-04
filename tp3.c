#include "tp3.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define MAX_ALPHA 0.8
#define SEED 0
#define INITIAL_SIZE 100

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
  uint8_t *d = (uint8_t *) key; // 32 bit extract from key'
  const uint32_t *chunks = NULL;
  const uint8_t *tail = NULL; // tail - last 8 bytes
  int i = 0;
  int l = len / 4; // chunk length

  h = seed;

  chunks = (const uint32_t *) (d + l * 4); // body
  tail = (const uint8_t *) (d + l * 4); // last 8 byte chunk of key'

  // for each 4 byte chunk of key'
  for (i = -l; i != 0; ++i) {
    // next 4 byte chunk of key'
    k = chunks[i];

    // encode next 4 byte chunk of key'
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
  switch (len & 3) { // len % 4'
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
  dictionary_t *dictionary = malloc(sizeof(dictionary_t));
  if (!dictionary) return NULL;
  dictionary->elems = calloc(INITIAL_SIZE, sizeof(elem_t));
  if (!dictionary->elems) {
      free(dictionary);
      return NULL;
  }
  dictionary->m = INITIAL_SIZE;
  dictionary->cantidad = 0;
  dictionary->borrados = 0;
  dictionary->destroy = destroy;
  return dictionary;
};


void rehash(dictionary_t *dictionary) {
    size_t new_size = dictionary->m * 2;
    elem_t *new_elems = calloc(new_size, sizeof(elem_t));
    for (size_t i = 0; i < dictionary->m; i++) {
        if (dictionary->elems[i].key && !dictionary->elems[i].borrado) {
            size_t new_index = hash(dictionary->elems[i].key, new_size);
            while (new_elems[new_index].key != NULL) new_index = (new_index + 1) % new_size;
            new_elems[new_index] = dictionary->elems[i];
        }
    }
    free(dictionary->elems);
    dictionary->elems = new_elems;
    dictionary->m = new_size;
    dictionary->borrados = 0;
};

bool dictionary_put(dictionary_t *dictionary, const char *key, void *value) {
    if (!key) return false;
    float alpha = (float)(dictionary->cantidad + dictionary->borrados) / (float)dictionary->m;
    if (alpha > MAX_ALPHA) rehash(dictionary);
    size_t index = hash(key, dictionary->m);
    while (dictionary->elems[index].key) {
        if (!dictionary->elems[index].borrado && strcmp(dictionary->elems[index].key, key) == 0) {
            if (dictionary->destroy) dictionary->destroy(dictionary->elems[index].value);
            dictionary->elems[index].value = value;
            return true;
        }
        index = (index + 1) % dictionary->m;
    }
    dictionary->elems[index].key = malloc(strlen(key) + 1);
    if (!dictionary->elems[index].key) return false;
    strcpy(dictionary->elems[index].key, key);
    dictionary->elems[index].value = value;
    dictionary->elems[index].borrado = false;
    dictionary->cantidad++;
    return true;
};

void *dictionary_get(dictionary_t *dictionary, const char *key, bool *err) {
    if (!key) {
    *err = true;
    return NULL;
  }
  size_t index = hash(key, dictionary->m);
  for (int i = 0; i < dictionary->m; i++) {
    if (dictionary->elems[index].key == NULL && dictionary->elems[index].borrado == false) {
      *err = true;
      return NULL;
    }
    if (dictionary->elems[index].key != NULL && strcmp(dictionary->elems[index].key, key) == 0) {
      *err = false;
      return dictionary->elems[index].value;
    }
    index = (index + 1) % dictionary->m;
  }
  *err = true;
  return NULL;
};

bool dictionary_delete(dictionary_t *dictionary, const char *key) {
  if (!key) return false;
  size_t index = hash(key, dictionary->m);
  for (size_t i = 0; i < dictionary->m; i++) {
      if (dictionary->elems[index].key == NULL && dictionary->elems[index].borrado == false) return false;
      if (dictionary->elems[index].key && strcmp(dictionary->elems[index].key, key) == 0) {
          free(dictionary->elems[index].key);
          if (dictionary->destroy && dictionary->elems[index].value) {
              dictionary->destroy(dictionary->elems[index].value);
          }
          dictionary->elems[index].key = NULL;
          dictionary->elems[index].value = NULL;
          dictionary->elems[index].borrado = true;
          dictionary->cantidad--;
          dictionary->borrados++;
          return true;
      }
      index = (index + 1) % dictionary->m;
  }
  return false;
};

void *dictionary_pop(dictionary_t *dictionary, const char *key, bool *err) {
  if (!key) {
      *err = true;
      return NULL;
  }
  size_t index = hash(key, dictionary->m);
  for (size_t i = 0; i < dictionary->m; i++) {
      if (dictionary->elems[index].key == NULL && dictionary->elems[index].borrado == false) {
          *err = true;
          return NULL;
      }
      if (dictionary->elems[index].key && strcmp(dictionary->elems[index].key, key) == 0) {
          void *value = dictionary->elems[index].value;
          free(dictionary->elems[index].key);
          dictionary->elems[index].key = NULL;
          dictionary->elems[index].value = NULL;
          dictionary->elems[index].borrado = true;
          dictionary->cantidad--;
          dictionary->borrados++;
          *err = false;
          return value;
      }
      index = (index + 1) % dictionary->m;
  }
  *err = true;
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

void dictionary_destroy(dictionary_t *dictionary) {
  for (size_t i = 0; i < dictionary->m; i++) {
      if (!dictionary->elems[i].borrado) {
          free(dictionary->elems[i].key);
          if (dictionary->destroy) dictionary->destroy(dictionary->elems[i].value);
      }
  }
  free(dictionary->elems);
  free(dictionary);
};