#if !defined( XMSS_RESERVE_H_ )
#define XMSS_RESERVE_H_
#include <stdio.h>
#include "params.h"

/*
 * This is the internal include file for the reservation functions for this
 * subsystem. It should not be used by applications
 */

void xmss_set_reserve_count(xmss_params *params, uint64_t count);

int xmss_set_autoreserve(xmss_params *params, unsigned sigs_to_autoreserve);

int xmss_advance_count(xmss_params *params, uint64_t idx_leaf);

int xmss_reserve_signature(xmss_params *params, unsigned sigs_to_reserve,
                            uint64_t idx_leaf, unsigned char *sk);

#endif /* XMSS_RESERVE_H_ */
