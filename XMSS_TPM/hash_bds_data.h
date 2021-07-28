#ifndef HASH_BDS_DATA_H
#define HASH_BDS_DATA_H

#include "params.h"

enum bds_structure{data_layer, NEXT_layer, WOTS_sigs, RESERVED};

void set_corrupted_layers(unsigned int *layers, unsigned int nr_of_hmaced_bds_layers, int layer);

int is_layer_corrupt(xmss_params *params,
                    unsigned int *corrupted_layers,
                    int bds_structure, unsigned int current_layer);

void hmac_all_bds_data(const xmss_params *params, unsigned char *sk, unsigned char *sk_seed,
                        unsigned char *hmac_out, int update_bds_hmac, int update_wots_hmac);

#endif