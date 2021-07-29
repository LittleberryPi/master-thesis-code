#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_core.h"
#include "xmss_reserve.h"
#include "hash_bds_data.h"

typedef struct{
    unsigned char h;
    unsigned long next_idx;
    unsigned char stackusage;
    unsigned char completed;
    unsigned char *node;
} treehash_inst;

typedef struct {
    unsigned char *stack;
    unsigned int stackoffset;
    unsigned char *stacklevels;
    unsigned char *auth;
    unsigned char *keep;
    treehash_inst *treehash;
    unsigned char *retain;
    unsigned int next_leaf;
} bds_state;

/* These serialization functions provide a transition between the current
   way of storing the state in an exposed struct, and storing it as part of the
   byte array that is the secret key.
   They will probably be refactored in a non-backwards-compatible way, soon. */

static void xmssmt_serialize_state(const xmss_params *params,
                                   unsigned char *sk, bds_state *states,
                                   unsigned int nr_states)
{
    unsigned int i, j;

    /* Skip past the 'regular' sk */
    // sk += params->index_bytes + 4*params->n; // already done in callee

    for (i = 0; i < nr_states; i++) {
        // printf("state addr for state=%d is %p\n", i, sk);
        sk += (params->tree_height + 1) * params->n; /* stack */

        ull_to_bytes(sk, 4, states[i].stackoffset);
        sk += 4;

        sk += params->tree_height + 1; /* stacklevels */
        sk += params->tree_height * params->n; /* auth */
        sk += (params->tree_height >> 1) * params->n; /* keep */

        for (j = 0; j < params->tree_height - params->bds_k; j++) {
            ull_to_bytes(sk, 1, states[i].treehash[j].h);
            sk += 1;

            ull_to_bytes(sk, 4, states[i].treehash[j].next_idx);
            sk += 4;

            ull_to_bytes(sk, 1, states[i].treehash[j].stackusage);
            sk += 1;

            ull_to_bytes(sk, 1, states[i].treehash[j].completed);
            sk += 1;

            sk += params->n; /* node */
        }

        /* retain */
        sk += ((1 << params->bds_k) - params->bds_k - 1) * params->n;

        ull_to_bytes(sk, 4, states[i].next_leaf);
        sk += 4;
    }
}

static void xmssmt_deserialize_state(const xmss_params *params,
                                     bds_state *states,
                                     unsigned char **wots_sigs,
                                     unsigned char *sk,
                                     unsigned int nr_states)
{
    unsigned int i, j;

    // TODO These data sizes follow from the (former) test xmss_core_fast.c
    // TODO They should be reconsidered / motivated more explicitly

    for (i = 0; i < nr_states; i++) {
        states[i].stack = sk;
        sk += (params->tree_height + 1) * params->n;

        states[i].stackoffset = bytes_to_ull(sk, 4);
        sk += 4;

        states[i].stacklevels = sk;
        sk += params->tree_height + 1;

        states[i].auth = sk;
        sk += params->tree_height * params->n;

        states[i].keep = sk;
        sk += (params->tree_height >> 1) * params->n;

        for (j = 0; j < params->tree_height - params->bds_k; j++) {
            states[i].treehash[j].h = bytes_to_ull(sk, 1);
            sk += 1;

            states[i].treehash[j].next_idx = bytes_to_ull(sk, 4);
            sk += 4;

            states[i].treehash[j].stackusage = bytes_to_ull(sk, 1);
            sk += 1;

            states[i].treehash[j].completed = bytes_to_ull(sk, 1);
            sk += 1;

            states[i].treehash[j].node = sk;
            sk += params->n;
        }

        states[i].retain = sk;
        sk += ((1 << params->bds_k) - params->bds_k - 1) * params->n;

        states[i].next_leaf = bytes_to_ull(sk, 4);
        sk += 4;
    }

    if (nr_states > 1) {
        *wots_sigs = sk;
    }
}

static void xmss_serialize_state(const xmss_params *params,
                                 unsigned char *sk, bds_state *state,
                                 unsigned int nr_states)
{
    xmssmt_serialize_state(params, sk, state, nr_states);
}

static void xmss_deserialize_state(const xmss_params *params,
                                   bds_state *state, unsigned char *sk)
{
    xmssmt_deserialize_state(params, state, NULL, sk, 1);
}

static void memswap(void *a, void *b, void *t, unsigned long long len)
{
    memcpy(t, a, len);
    memcpy(a, b, len);
    memcpy(b, t, len);
}

/**
 * Swaps the content of two bds_state objects, swapping actual memory rather
 * than pointers.
 * As we're mapping memory chunks in the secret key to bds state objects,
 * it is now necessary to make swaps 'real swaps'. This could be done in the
 * serialization function as well, but that causes more overhead
 */
// TODO this should not be necessary if we keep better track of the states
static void deep_state_swap(const xmss_params *params,
                            bds_state *a, bds_state *b)
{
    // TODO this is extremely ugly and should be refactored
    // TODO right now, this ensures that both 'stack' and 'retain' fit
    unsigned char t[
        ((params->tree_height + 1) > ((1 << params->bds_k) - params->bds_k - 1)
         ? (params->tree_height + 1)
         : ((1 << params->bds_k) - params->bds_k - 1))
        * params->n];
    unsigned int i;

    memswap(a->stack, b->stack, t, (params->tree_height + 1) * params->n);
    memswap(&a->stackoffset, &b->stackoffset, t, sizeof(a->stackoffset));
    memswap(a->stacklevels, b->stacklevels, t, params->tree_height + 1);
    memswap(a->auth, b->auth, t, params->tree_height * params->n);
    memswap(a->keep, b->keep, t, (params->tree_height >> 1) * params->n);

    for (i = 0; i < params->tree_height - params->bds_k; i++) {
        memswap(&a->treehash[i].h, &b->treehash[i].h, t, sizeof(a->treehash[i].h));
        memswap(&a->treehash[i].next_idx, &b->treehash[i].next_idx, t, sizeof(a->treehash[i].next_idx));
        memswap(&a->treehash[i].stackusage, &b->treehash[i].stackusage, t, sizeof(a->treehash[i].stackusage));
        memswap(&a->treehash[i].completed, &b->treehash[i].completed, t, sizeof(a->treehash[i].completed));
        memswap(a->treehash[i].node, b->treehash[i].node, t, params->n);
    }

    memswap(a->retain, b->retain, t, ((1 << params->bds_k) - params->bds_k - 1) * params->n);
    memswap(&a->next_leaf, &b->next_leaf, t, sizeof(a->next_leaf));
}

static int treehash_minheight_on_stack(const xmss_params *params,
                                       bds_state *state,
                                       const treehash_inst *treehash)
{
    unsigned int r = params->tree_height, i;

    for (i = 0; i < treehash->stackusage; i++) {
        if (state->stacklevels[state->stackoffset - i - 1] < r) {
            r = state->stacklevels[state->stackoffset - i - 1];
        }
    }
    return r;
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 *
 */
static void treehash_init(const xmss_params *params,
                          unsigned char *node, int height, int index,
                          bds_state *state, const unsigned char *sk_seed,
                          const unsigned char *pub_seed, const uint32_t addr[8])
{
    unsigned int idx = index;
    // use three different addresses because at this point we use all three formats in parallel
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    // only copy layer and tree address parts
    copy_subtree_addr(ots_addr, addr);
    set_type(ots_addr, 0); // type = ots
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    uint32_t lastnode, i;
    unsigned char stack[(height+1)*params->n]; // stack of nodes
    unsigned int stacklevels[height+1]; // height for node in stack
    unsigned int stackoffset=0; // stack head in stack array
    unsigned int nodeh; // node height

    lastnode = (1<<height);

    for (i = 0; i < params->tree_height-params->bds_k; i++) {
        state->treehash[i].h = i; // set each treehash_h (treehash[all heights])
        state->treehash[i].completed = 1; // set every treehash instance to completed
        state->treehash[i].stackusage = 0; // there is no stackusage for any treehash instance
    }

    i = 0;
    // Iterate over all leaf nodes
    for (; idx < lastnode; idx++) {
        // Compute the WOTS pk
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        // put leaf node in stack
        gen_leaf_wots(params, stack+stackoffset*params->n, sk_seed, pub_seed, ltree_addr, ots_addr);
        // node in stack is a leaf (h=0)
        stacklevels[stackoffset] = 0;
        // increase stack head
        stackoffset++; 
        // if i==3
        if (params->tree_height - params->bds_k > 0 && i == 3) { 
            // set TREEHASH_0.node which is y_0[3]
            memcpy(state->treehash[0].node, stack+stackoffset*params->n, params->n); 
        }
        // while top two nodes are of the same height
        while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2]) { 
            // height of top two nodes
            nodeh = stacklevels[stackoffset-1]; 
            if (i >> nodeh == 1) {
                // set authpath_h node which is y_h[1]
                memcpy(state->auth + nodeh*params->n, stack+(stackoffset-1)*params->n, params->n); 
            }
            else {
                if (nodeh < params->tree_height - params->bds_k && i >> nodeh == 3) {
                    // set TREEHASH_h.node which is y_h[3]
                    memcpy(state->treehash[nodeh].node, stack+(stackoffset-1)*params->n, params->n); 
                }
                else if (nodeh >= params->tree_height - params->bds_k) {
                    memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((i >> nodeh) - 3) >> 1)) * params->n, stack+(stackoffset-1)*params->n, params->n);
                }
            }
            // set node_addr to current node height
            set_tree_height(node_addr, stacklevels[stackoffset-1]);
            // set node_addr to index of next node (on height h+1?)
            set_tree_index(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
            // compute hash and put on stack
            thash_h(params, stack+(stackoffset-2)*params->n, stack+(stackoffset-2)*params->n, pub_seed, node_addr); 
            // new node on stack is on one level higher
            stacklevels[stackoffset-2]++; 
            // decrease stack head
            stackoffset--; 
        }
        i++;
    }

    for (i = 0; i < params->n; i++) {
        node[i] = stack[i]; // copy stack to the tree root in pk
    }
}

static void treehash_update(const xmss_params *params,
                            treehash_inst *treehash, bds_state *state,
                            const unsigned char *sk_seed,
                            const unsigned char *pub_seed,
                            const uint32_t addr[8])
{
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    // only copy layer and tree address parts
    copy_subtree_addr(ots_addr, addr);
    // type = ots
    set_type(ots_addr, 0);
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    set_ltree_addr(ltree_addr, treehash->next_idx);
    set_ots_addr(ots_addr, treehash->next_idx);

    unsigned char nodebuffer[2 * params->n];
    unsigned int nodeheight = 0;
    gen_leaf_wots(params, nodebuffer, sk_seed, pub_seed, ltree_addr, ots_addr);
    while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset-1] == nodeheight) {
        memcpy(nodebuffer + params->n, nodebuffer, params->n);
        memcpy(nodebuffer, state->stack + (state->stackoffset-1)*params->n, params->n);
        set_tree_height(node_addr, nodeheight);
        set_tree_index(node_addr, (treehash->next_idx >> (nodeheight+1)));
        thash_h(params, nodebuffer, nodebuffer, pub_seed, node_addr);
        nodeheight++;
        treehash->stackusage--;
        state->stackoffset--;
    }
    if (nodeheight == treehash->h) { // this also implies stackusage == 0
        memcpy(treehash->node, nodebuffer, params->n);
        treehash->completed = 1;
    }
    else {
        memcpy(state->stack + state->stackoffset*params->n, nodebuffer, params->n);
        treehash->stackusage++;
        state->stacklevels[state->stackoffset] = nodeheight;
        state->stackoffset++;
        treehash->next_idx++;
    }
}

/**
 * Performs treehash updates on the instance that needs it the most.
 * Returns the updated number of available updates.
 **/
static char bds_treehash_update(const xmss_params *params,
                                bds_state *state, unsigned int updates,
                                const unsigned char *sk_seed,
                                const unsigned char *pub_seed,
                                const uint32_t addr[8])
{
    uint32_t i, j;
    unsigned int level, l_min, low;
    unsigned int used = 0;

    for (j = 0; j < updates; j++) {
        l_min = params->tree_height;
        level = params->tree_height - params->bds_k;
        for (i = 0; i < params->tree_height - params->bds_k; i++) {
            if (state->treehash[i].completed) {
                low = params->tree_height;
            }
            else if (state->treehash[i].stackusage == 0) {
                low = i;
            }
            else {
                low = treehash_minheight_on_stack(params, state, &(state->treehash[i]));
            }
            if (low < l_min) {
                level = i;
                l_min = low;
            }
        }
        if (level == params->tree_height - params->bds_k) {
            break;
        }
        treehash_update(params, &(state->treehash[level]), state, sk_seed, pub_seed, addr);
        used++;
    }
    return updates - used;
}

/**
 * Updates the state (typically NEXT_i) by adding a leaf and updating the stack
 * Returns -1 if all leaf nodes have already been processed
 **/
static char bds_state_update(const xmss_params *params,
                             bds_state *state, const unsigned char *sk_seed,
                             const unsigned char *pub_seed,
                             const uint32_t addr[8])
{
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    uint32_t ots_addr[8] = {0};

    unsigned int nodeh;
    int idx = state->next_leaf;
    if (idx == 1 << params->tree_height) {
        return -1;
    }

    // only copy layer and tree address parts
    copy_subtree_addr(ots_addr, addr);
    // type = ots
    set_type(ots_addr, 0);
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    set_ots_addr(ots_addr, idx);
    set_ltree_addr(ltree_addr, idx);

    gen_leaf_wots(params, state->stack+state->stackoffset*params->n, sk_seed, pub_seed, ltree_addr, ots_addr);

    state->stacklevels[state->stackoffset] = 0;
    state->stackoffset++;
    if (params->tree_height - params->bds_k > 0 && idx == 3) {
        memcpy(state->treehash[0].node, state->stack+state->stackoffset*params->n, params->n);
    }
    while (state->stackoffset>1 && state->stacklevels[state->stackoffset-1] == state->stacklevels[state->stackoffset-2]) {
        nodeh = state->stacklevels[state->stackoffset-1];
        if (idx >> nodeh == 1) {
            memcpy(state->auth + nodeh*params->n, state->stack+(state->stackoffset-1)*params->n, params->n);
        }
        else {
            if (nodeh < params->tree_height - params->bds_k && idx >> nodeh == 3) {
                memcpy(state->treehash[nodeh].node, state->stack+(state->stackoffset-1)*params->n, params->n);
            }
            else if (nodeh >= params->tree_height - params->bds_k) {
                memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((idx >> nodeh) - 3) >> 1)) * params->n, state->stack+(state->stackoffset-1)*params->n, params->n);
            }
        }
        set_tree_height(node_addr, state->stacklevels[state->stackoffset-1]);
        set_tree_index(node_addr, (idx >> (state->stacklevels[state->stackoffset-1]+1)));
        thash_h(params, state->stack+(state->stackoffset-2)*params->n, state->stack+(state->stackoffset-2)*params->n, pub_seed, node_addr);

        state->stacklevels[state->stackoffset-2]++;
        state->stackoffset--;
    }
    state->next_leaf++;
    return 0;
}

/**
 * Returns the auth path for node leaf_idx and computes the auth path for the
 * next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
 * in "Post Quantum Cryptography", Springer 2009.
 * next_bds = -1: we use bds_round as usually
 * next_bds = 0: we compute bds for current leaf in forward computing
 * next_bds = 1: we compute next_bds in forward computing
 */
static void bds_round(const xmss_params *params,
                      bds_state *state, const unsigned long leaf_idx, const unsigned long idx,
                      const unsigned char *sk_seed,
                      const unsigned char *pub_seed, uint32_t addr[8], int next_bds)
{
    unsigned int i;
    unsigned int tau = params->tree_height;
    unsigned int startidx;
    unsigned int offset, rowidx;
    unsigned char buf[2 * params->n];

    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    // only copy layer and tree address parts
    copy_subtree_addr(ots_addr, addr);
    // type = ots
    set_type(ots_addr, 0);
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    /* (1) if leaf_idx is left node, tau = 0, else tau = height of first left node 
    parent of leaf_idx */
    for (i = 0; i < params->tree_height; i++) {
        if (! ((leaf_idx >> i) & 1)) {
            tau = i;
            break;
        }
    }

    if (tau > 0) {
        memcpy(buf, state->auth + (tau-1) * params->n, params->n);
        // we need to do this before refreshing state->keep to prevent overwriting
        memcpy(buf + params->n, state->keep + ((tau-1) >> 1) * params->n, params->n);
    }
    if (!((leaf_idx >> (tau + 1)) & 1) && (tau < params->tree_height - 1)) { // (2)
        memcpy(state->keep + (tau >> 1)*params->n, state->auth + tau*params->n, params->n);
    }
    if (tau == 0) { // (3) leaf_idx is a left node
        set_ltree_addr(ltree_addr, leaf_idx);
        set_ots_addr(ots_addr, leaf_idx);
        gen_leaf_wots(params, state->auth, sk_seed, pub_seed, ltree_addr, ots_addr);
    }
    else { // (4) leaf_idx is a right node
        set_tree_height(node_addr, (tau-1));
        set_tree_index(node_addr, leaf_idx >> tau);
        thash_h(params, state->auth + tau * params->n, buf, pub_seed, node_addr); // (4a)
        for (i = 0; i < tau; i++) { // (4b)
            if (i < params->tree_height - params->bds_k) {
                memcpy(state->auth + i * params->n, state->treehash[i].node, params->n);
            }
            else {
                offset = (1 << (params->tree_height - 1 - i)) + i - params->tree_height;
                rowidx = ((leaf_idx >> i) - 1) >> 1;
                memcpy(state->auth + i * params->n, state->retain + (offset + rowidx) * params->n, params->n);
            }
        }

        for (i = 0; i < ((tau < params->tree_height - params->bds_k) ? tau : (params->tree_height - params->bds_k)); i++) { //(4c)
            startidx = leaf_idx + 1 + 3 * (1 << i);
            unsigned long full_startidx = idx + 1 + 3 * (1 << i);
            // skip if leaf is already computed in next_bds
            if (full_startidx > params->reserve_count && next_bds == 0 && params->autoreserve > 0) {
                continue;
            }
            // we're computing next bds, skip if leaf is going to be computed during normal bds
            else if (full_startidx < params->reserve_count && next_bds == 1) { 
                continue;
            }
            if (startidx < 1U << params->tree_height) {
                state->treehash[i].h = i;
                state->treehash[i].next_idx = startidx;
                state->treehash[i].completed = 0;
                state->treehash[i].stackusage = 0;
            }
        }
    }
}

void sign_tree(const xmss_params *params, unsigned long long idx, bds_state *states, uint32_t ots_addr[8],
                 unsigned char *wots_sigs, const unsigned char *sk_seed, const unsigned char *pub_seed, 
                 unsigned int *updates, int *needswap_upto, uint64_t i) {
    deep_state_swap(params, states+params->d + i, states + i);

    set_layer_addr(ots_addr, (i+1));
    set_tree_addr(ots_addr, ((idx + 1) >> ((i+2) * params->tree_height)));
    set_ots_addr(ots_addr, (((idx >> ((i+1) * params->tree_height)) + 1) & ((1 << params->tree_height)-1)));

    wots_sign(params, wots_sigs + i*params->wots_sig_bytes, states[i].stack, sk_seed, pub_seed, ots_addr);

    states[params->d + i].stackoffset = 0;
    states[params->d + i].next_leaf = 0;

    (*updates)--; // WOTS-signing counts as one update
    *needswap_upto = i;
    for (uint64_t j = 0; j < params->tree_height-params->bds_k; j++) {
        states[i].treehash[j].completed = 1;
    }
}


// Then we do the layers above the bottom layer
void bds_advance_upper_trees(const xmss_params *params, unsigned long long idx,
                            int *needswap_upto, bds_state *states, unsigned int updates, 
                            const unsigned char *sk_seed, const unsigned char *pub_seed, 
                            uint32_t ots_addr[8], unsigned char *wots_sigs) {
    uint32_t addr[8] = {0};
    uint32_t idx_leaf;
    uint64_t idx_tree;

    // We only need to advance upper trees if we have more than 1 layer
    if (params->d == 1) {
        return;
    }

    for (uint64_t i = 0; i < params->d; i++) {
        // check if we're not at the end of a tree (if idx+1 != nr_leafs in tree-1)
        // we skip i == 0, because this has already been done in the callee, but we need to check
        // in case we need to sign tree when i == 0
        if (! (((idx + 1) & ((1ULL << ((i+1)*params->tree_height)) - 1)) == 0)) {
            if (i > 0) {
                idx_leaf = (idx >> (params->tree_height * i)) & ((1 << params->tree_height)-1);
                idx_tree = (idx >> (params->tree_height * (i+1)));
                set_layer_addr(addr, i);
                set_tree_addr(addr, idx_tree);
                if (i == (unsigned int) (*needswap_upto + 1)) {
                    bds_round(params, &states[i], idx_leaf, idx, sk_seed, pub_seed, addr, -1);
                    bds_treehash_update(params, &states[i], (params->tree_height - params->bds_k) >> 1, sk_seed, pub_seed, ots_addr);
                    // printf("BDS ROUND LAYER %ld\n", i);
                }
            }
        }
        // idx+1 == nr_leafs in tree-1 && idx < total nr_leafs
        else if (idx < (1ULL << params->full_height) - 1) {
            sign_tree(params, idx, states, ots_addr, wots_sigs, sk_seed, pub_seed, &updates, needswap_upto, i);
        }
    }
}


/* Update BDS next */
void update_bds_reserved(const xmss_params *params, unsigned long idx, unsigned char *sk,
                        unsigned int start_bds_addr, const unsigned char *sk_seed,
                        unsigned char *pub_seed, int bds_round_mode) {
    // idx = idx + params->autoreserve;
    unsigned int bds_addr = params->index_bytes + 4*params->n;
    unsigned int wots_sigs_addr = bds_addr + (2*params->d - 1)*params->bds_state_bytes;
    unsigned char *wots_sigs = sk + wots_sigs_addr;
    int needswap_upto = -1;
    unsigned int updates = (params->tree_height - params->bds_k) >> 1;

    // Prepare Addresses
    uint32_t ots_addr[8] = {0};
    uint64_t idx_tree = idx >> params->tree_height;
    uint32_t idx_leaf = idx & ((1 << params->tree_height)-1);
    set_type(ots_addr, 0);
    set_layer_addr(ots_addr, 0);
    set_tree_addr(ots_addr, idx_tree);
    set_ots_addr(ots_addr, idx_leaf);

    unsigned int bds_reserved_idx_addr = params->sk_bytes + params->index_bytes;
    unsigned int bds_reserved_data_addr = bds_reserved_idx_addr + params->index_bytes;
    unsigned int bds_NEXT0_addr = params->d*params->bds_state_bytes;

    // If we're at the end of the tree, we need to not compute NEXT_0 further, but bds_reserved = NEXT_0
    if (params->d > 1 && ((idx + 1) & ((1ULL << params->tree_height) - 1)) == 0 && (idx < (1ULL << params->full_height) - 1)) {
        // Update bds_reserved state
        /* Prepare an sk copy (sk_nv) which can be written to NV memory, sk is still
        used to create signatures so do not modify sk */
        unsigned int bds_addr = params->index_bytes + 4*params->n;
        unsigned int bds_size = params->sk_bytes - bds_addr;
        unsigned char sk_nv[bds_size];
        memcpy(sk_nv, sk + bds_addr, bds_size);


        bds_state states[2*params->d - 1];
        treehash_inst treehash[(2*params->d - 1) * (params->tree_height - params->bds_k)];
        for (unsigned int i = 0; i < 2*params->d - 1; i++) {
            states[i].treehash = treehash + i * (params->tree_height - params->bds_k);
        }
        xmssmt_deserialize_state(params, states, &wots_sigs, sk_nv, 2*params->d - 1);

        bds_advance_upper_trees(params, idx, &needswap_upto, states, updates, sk_seed, 
                                pub_seed, ots_addr, wots_sigs);
        
        xmssmt_serialize_state(params, sk_nv, states, 2*params->d - 1);
        // Write bds_reserved to sk
        memcpy(sk + bds_reserved_data_addr, sk_nv, bds_size);
        ull_to_bytes(sk + bds_reserved_idx_addr, params->index_bytes, idx+1); // set idx bds_reserved
        
        // Update BDS NEXT layers into sk
        memcpy(sk + bds_addr + bds_NEXT0_addr, sk_nv + bds_NEXT0_addr, (params->d-1)*params->bds_state_bytes);
    }
    else if (idx < (1ULL << params->full_height) - 1) {
        // Update bds_reserved state
        /* Prepare an sk copy (sk_nv) which can be written to NV memory, sk is still
        used to create signatures so do not modify sk */
        unsigned char sk_nv[params->bds_state_bytes];
        memcpy(sk_nv, sk + start_bds_addr, params->bds_state_bytes);
        bds_state state_nv; // state_nv is a copy of state
        treehash_inst treehash[params->tree_height - params->bds_k];
        state_nv.treehash = treehash;
        xmss_deserialize_state(params, &state_nv, sk_nv);
        // Compute the auth path for leaf_idx+sigs_reserved
        bds_round(params, &state_nv, idx_leaf, idx, sk_seed, pub_seed, ots_addr, bds_round_mode);
        bds_treehash_update(params, &state_nv, (params->tree_height - params->bds_k) >> 1, sk_seed, pub_seed, ots_addr);
        // put back the state in sk_nv
        xmss_serialize_state(params, sk_nv, &state_nv, 1); 
        // Write bds_reserved to sk
        memcpy(sk + bds_reserved_data_addr, sk_nv, params->bds_state_bytes);
        // set idx bds_reserved
        ull_to_bytes(sk + bds_reserved_idx_addr, params->index_bytes, idx+1); 
        if (params->d > 1) {
            // copy whole bds except for bds layer 0, into bds next
            unsigned bds_addr = params->index_bytes + 4*params->n;
            unsigned int bds_layer1_addr = bds_addr + params->bds_state_bytes;
            unsigned int bds_size_wihout_layer0 = params->sk_bytes - bds_layer1_addr;
            memcpy(sk + bds_reserved_data_addr + params->bds_state_bytes, sk + bds_layer1_addr, bds_size_wihout_layer0);
        }
    }
}


/* Fast forward the bds state (bulk compute) autoreserve times for reservation 
function and store this in bds_reserved */
void bulk_bds_reserved(const xmss_params *params, unsigned char *sk, uint64_t start_leaf_idx, 
        uint64_t goal_index, unsigned int start_bds_addr, int bds_round_mode) {
    // Read seeds from sk_nv
    unsigned char sk_seed[params->n];
    memcpy(sk_seed, sk + params->index_bytes, params->n);
    unsigned char pub_seed[params->n];
    memcpy(pub_seed, sk + params->index_bytes + 3*params->n, params->n);

    unsigned int bds_reserved_idx_addr = params->sk_bytes + params->index_bytes;
    unsigned int bds_reserved_data_addr = bds_reserved_idx_addr + params->index_bytes;

    // We do one round separately, because if callee is xmss(mt)_core_keypair,
    // we only need to read bds layer 0 once and then bds_reserved
    update_bds_reserved(params, start_leaf_idx, sk, start_bds_addr, sk_seed, pub_seed, bds_round_mode);
    // Compute the auth path for start_leaf_idx+sigs_reserved+1
    for (uint64_t idx = start_leaf_idx+1; idx < goal_index; idx++) {
        update_bds_reserved(params, idx, sk, bds_reserved_data_addr, sk_seed, pub_seed, bds_round_mode);
    }
}

/* Reserve bds state when xmss_reserve_signature() is called */
void bds_reserve(xmss_params *params, unsigned char *sk) {
    // NOTE: sk didn't skip OID_LEN and thus points to OID_LEN
    sk += XMSS_OID_LEN;

    unsigned int bds_reserved_idx_addr = params->sk_bytes + params->index_bytes;
    unsigned int bds_reserved_data_addr = bds_reserved_idx_addr + params->index_bytes;

    unsigned long bds_reserved_idx = bytes_to_ull(sk + bds_reserved_idx_addr, params->index_bytes);

    if (bds_reserved_idx < params->reserve_count) { 
        // we need to advance (bulk compute) bds_reserved until params->reserve_count
        bulk_bds_reserved(params, sk, bds_reserved_idx, params->reserve_count, bds_reserved_data_addr, 1);
    }
}

void bulk_NEXT0_tree(const xmss_params *params, unsigned char *sk, uint64_t start_index, uint64_t goal_index) {
    uint32_t addr[8] = {0};
    unsigned char sk_seed[params->n];
    unsigned char pub_seed[params->n];
    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint64_t next0_tree_addr;

    memcpy(sk_seed, sk+params->index_bytes, params->n);
    memcpy(pub_seed, sk+params->index_bytes+3*params->n, params->n);

    // initialize state
    bds_state state;
    treehash_inst treehash[params->tree_height - params->bds_k];
    state.treehash = treehash;
    next0_tree_addr = params->index_bytes + 4*params->n + (params->d * params->bds_state_bytes);
    xmss_deserialize_state(params, &state, sk + next0_tree_addr);

    for (uint64_t idx = start_index; idx < goal_index; idx++) { 
        // update for NEXT_0 if NEXT_0 exists
        idx_leaf = (idx & ((1 << params->tree_height)-1));
        idx_tree = idx >> params->tree_height;
        set_tree_addr(addr, (idx_tree + 1));

        if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << params->full_height)) {
            bds_state_update(params, &state, sk_seed, pub_seed, addr);
        }
        else {
            break;
        }
    }

    xmss_serialize_state(params, sk + next0_tree_addr, &state, 1);
}

void bulk_upper_NEXT_trees(const xmss_params *params, unsigned char *sk, uint64_t idx) {
    uint32_t addr[8] = {0};
    unsigned char sk_seed[params->n];
    unsigned char pub_seed[params->n];
    uint64_t idx_tree;
    uint32_t idx_leaf;
    unsigned char *wots_sigs;

    unsigned int bds_addr = params->index_bytes + 4*params->n;
    unsigned int bds_NEXT0_addr = bds_addr + (params->d*params->bds_state_bytes);
    memcpy(sk_seed, sk+params->index_bytes, params->n);
    memcpy(pub_seed, sk+params->index_bytes+3*params->n, params->n);

    // initialize NEXT states
    bds_state states[params->d - 1];
    treehash_inst treehash[(params->d - 1) * (params->tree_height - params->bds_k)];
    for (unsigned int i = 0; i < params->d - 1; i++) {
        states[i].treehash = treehash + i * (params->tree_height - params->bds_k);
    }
    xmssmt_deserialize_state(params, states, &wots_sigs, sk + bds_NEXT0_addr, params->d - 1);

    for (unsigned int i = 1; i < params->d-1; i++) {
        // If we are at the end of the tree
        if ((((idx+1) & ((1ULL << ((i+1)*params->tree_height)) - 1)) == 0)) {
            // If we haven't finished NEXT tree on layer i
            set_layer_addr(addr, i);
            unsigned int start_index = states[i].next_leaf;
            unsigned int goal_index = 1ULL << params->tree_height;
            for (unsigned j = start_index; j < goal_index; j++) { 
                // update for NEXT_i if NEXT_i exists
                idx_leaf = states[i].next_leaf;
                idx_tree = (idx >> (params->tree_height * (i+1)));
                set_tree_addr(addr, (idx_tree + 1));

                if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << params->full_height)) {
                    bds_state_update(params, &states[i], sk_seed, pub_seed, addr);
                }
                else {
                    break;
                }
            }
        }
    }
    
    xmssmt_serialize_state(params, sk + bds_NEXT0_addr, states, params->d - 1);
    
}

/* Reserve bds state when xmss_reserve_signature() is called */
void bds_reserve_mt(xmss_params *params, unsigned char *sk) {
    // NOTE: sk didn't skip OID_LEN and thus points to OID_LEN
    sk += XMSS_OID_LEN;

    unsigned int bds_reserved_idx_addr = params->sk_bytes + params->index_bytes;
    unsigned int bds_reserved_data_addr = bds_reserved_idx_addr + params->index_bytes;
    unsigned long bds_reserved_idx = bytes_to_ull(sk + bds_reserved_idx_addr, params->index_bytes);

    if (bds_reserved_idx < params->reserve_count) { 
        // we need to advance (bulk compute) NEXT_0 tree until params->reserve_count
        bulk_NEXT0_tree(params, sk, bds_reserved_idx, params->reserve_count);
        // in case we haven't advanced NEXT_j enough in the layers j > 0, bulk compute them
        bulk_upper_NEXT_trees(params, sk, params->reserve_count-1);
        // we need to advance (bulk compute) bds_reserved until params->reserve_count
        bulk_bds_reserved(params, sk, bds_reserved_idx, params->reserve_count, bds_reserved_data_addr, 1);
    }
}


/* TODO: update the sk index and bds state in nv memory at once when DEFAULT_STORAGE */
/* Advance the bds state for XMSS^MT, and if needed pre-compute the bds state which 
is going to be stored in NV memory because of the reservation function */
void bds_advance(int sigs_reserved, xmss_params *params, 
                      bds_state *states, unsigned char *sk,
                      const unsigned long long idx, const unsigned char *sk_seed,
                      unsigned char *pub_seed, uint32_t ots_addr[8],
                      unsigned int *updates, unsigned char *wots_sigs, int *needswap_upto) {
    // NOTE: sk skipped OID_LEN and points to index
    uint32_t idx_leaf = idx & ((1 << params->tree_height)-1);
    unsigned int bds_addr = params->index_bytes + 4*params->n;
    unsigned int bds_size = params->sk_bytes - bds_addr;
    unsigned int bds_reserved_idx_addr = params->sk_bytes + params->index_bytes;
    unsigned int bds_reserved_data_addr = bds_reserved_idx_addr + params->index_bytes;
    unsigned int wots_addr = bds_addr + (2*params->d - 1) * params->bds_state_bytes;
    unsigned long bds_idx = bytes_to_ull(sk + params->sk_bytes, params->index_bytes);
    unsigned long bds_reserved_idx = bytes_to_ull(sk + params->sk_bytes + params->index_bytes, params->index_bytes);

    if (sigs_reserved == 0) {
        // Update bds state
        bds_round(params, &states[0], idx_leaf, idx, sk_seed, pub_seed, ots_addr, 0);
        *updates = bds_treehash_update(params, &states[0], *updates, sk_seed, pub_seed, ots_addr);
        
        if (params->autoreserve == 0) {
            ull_to_bytes(sk + params->sk_bytes, params->index_bytes, params->reserve_count); // set bds idx
            // if we have XMSSMT, we also try to advance the upper layers
            bds_advance_upper_trees(params, idx, needswap_upto, states, *updates, sk_seed, 
                            pub_seed, ots_addr, wots_sigs);
        }
        // If we do reserve, and bds index in nv memory == bds next index in nv memory, then we don't have to update bds_reserved
        // But this is only when we have reserved, so when leaf_idx % autoreserve > 0
        else if (params->autoreserve > 0) {
            if (bds_idx < bds_reserved_idx || (idx % (params->autoreserve+1) > 0 && bds_idx == bds_reserved_idx)) {
                xmssmt_serialize_state(params, sk + bds_addr, states, 2*params->d - 1);
                update_bds_reserved(params, idx+params->autoreserve, sk, bds_reserved_data_addr, sk_seed, pub_seed, 1);
                xmssmt_deserialize_state(params, states, &wots_sigs, sk + bds_addr, 2*params->d - 1);
            }
        }
    }
    else if (sigs_reserved == -1) { // we're one index before reserve_count
        xmssmt_serialize_state(params, sk + bds_addr, states, 2*params->d - 1);
        /* bds = bds in nv memory */
        #ifdef DEFAULT_STORAGE
            // read in bds (not NEXT)
            FILE *keypair_file = fopen("keypair", "rb");
            fseek(keypair_file, XMSS_OID_LEN + params->pk_bytes + XMSS_OID_LEN + bds_addr, SEEK_SET);
            fread(sk + bds_addr, 1, params->d * params->bds_state_bytes, keypair_file); 
            // read in wots sigs
            if (params->d > 1) {
                fseek(keypair_file, XMSS_OID_LEN + params->pk_bytes + XMSS_OID_LEN + wots_addr, SEEK_SET);
                fread(sk + wots_addr, 1, (params->d - 1) * params->wots_sig_bytes + params->index_bytes, keypair_file);
            }
            // read in bds idx
            fseek(keypair_file, XMSS_OID_LEN + params->pk_bytes + XMSS_OID_LEN + params->sk_bytes, SEEK_SET);
            fread(sk + params->sk_bytes, 1, params->index_bytes, keypair_file);
            fclose(keypair_file);
        #endif //TPM_STORAGE
        #ifdef TPM_STORAGE
            // read in bds (not NEXT)
            FILE *f_bds = fopen( "bds.data", "rb" );
            fread(sk + bds_addr, 1, params->d * params->bds_state_bytes, f_bds); 
            // read in wots sigs
            if (params->d > 1) {
                fseek(f_bds, wots_addr - bds_addr, SEEK_SET);
                fread(sk + wots_addr, 1, (params->d - 1) * params->wots_sig_bytes + params->index_bytes, f_bds);
            }
            // read in bds idx
            fseek(f_bds, bds_size, SEEK_SET);
            fread(sk + params->sk_bytes, 1, params->index_bytes, f_bds);
            fclose(f_bds);
        #endif //TPM_STORAGE

        update_bds_reserved(params, idx+params->autoreserve, sk, bds_reserved_data_addr, sk_seed, pub_seed, 1);
        xmssmt_deserialize_state(params, states, &wots_sigs, sk + bds_addr, 2*params->d - 1);
    }
    else if (sigs_reserved > 0) {
        bds_round(params, &states[0], idx_leaf, idx, sk_seed, pub_seed, ots_addr, 0);
        *updates = bds_treehash_update(params, &states[0], *updates, sk_seed, pub_seed, ots_addr);

        xmssmt_serialize_state(params, sk + bds_addr, states, 2*params->d - 1);
        update_bds_reserved(params, idx+params->autoreserve, sk, bds_reserved_data_addr, sk_seed, pub_seed, 1);
        xmssmt_deserialize_state(params, states, &wots_sigs, sk + bds_addr, 2*params->d - 1);
    }
}

/**
 * Given a set of parameters, this function returns the size of the secret key.
 * This is implementation specific, as varying choices in tree traversal will
 * result in varying requirements for state storage.
 *
 * This function handles both XMSS and XMSSMT parameter sets.
 */
unsigned long long xmss_xmssmt_core_sk_bytes(const xmss_params *params)
{
    return params->index_bytes + 4 * params->n
        + (2 * params->d - 1) * (
            (params->tree_height + 1) * params->n
            + 4
            + params->tree_height + 1
            + params->tree_height * params->n
            + (params->tree_height >> 1) * params->n
            + (params->tree_height - params->bds_k) * (7 + params->n)
            + ((1 << params->bds_k) - params->bds_k - 1) * params->n
            + 4
         )
        + (params->d - 1) * params->wots_sig_bytes;
}

/**
 * Given a set of parameters, this function returns the the bds NEXT size of the 
 * bottom layer
 */
unsigned long long xmss_xmssmt_core_bds_state_bytes(const xmss_params *params)
{
    return (params->tree_height + 1) * params->n
        + 4
        + params->tree_height + 1
        + params->tree_height * params->n
        + (params->tree_height >> 1) * params->n
        + (params->tree_height - params->bds_k) * (7 + params->n)
        + ((1 << params->bds_k) - params->bds_k - 1) * params->n
        + 4;
}

void match_auth_node(const xmss_params *params, uint32_t idx, bds_state *state, 
                        unsigned int nodeh, uint32_t *auth_indices,
                        unsigned char *stack, unsigned int stackoffset) {
    /* If the top node has the same index as we look for, it works because the top node is
    the parent of idx at height nodeh */
    if ((idx >> nodeh) == auth_indices[nodeh]) {
        // set auth_h node
        memcpy(state->auth + nodeh*params->n, stack+(stackoffset-1)*params->n, params->n);
    }
    // The left sibling could also match
    else if ((idx >> nodeh)-1 == auth_indices[nodeh]) {
        // set auth_h node
        memcpy(state->auth + nodeh*params->n, stack+(stackoffset-2)*params->n, params->n);
    }
}

void match_keep_node(const xmss_params *params, uint32_t idx, bds_state *state, 
                        unsigned int nodeh, uint32_t *keep_indices,
                        unsigned char *stack, unsigned int stackoffset) {
    /* If the top node has the same index as we look for, it works because the top node is
    the parent of idx at height nodeh */
    if ((idx >> nodeh) == keep_indices[nodeh]) {
        // set keep_h node
        memcpy(state->keep + (nodeh >> 1)*params->n, stack+(stackoffset-1)*params->n, params->n);
    }
    // The left sibling could also match
    else if ((idx >> nodeh)-1 == keep_indices[nodeh]) {
        // set keep_h node
        memcpy(state->keep + (nodeh >> 1)*params->n, stack+(stackoffset-2)*params->n, params->n);
    }
}

void match_treehashinit_node(const xmss_params *params, uint32_t idx, bds_state *state, 
                        unsigned int nodeh, uint32_t *treehashnode_indices,
                        unsigned char *stack, unsigned int stackoffset) {
    /* Skip if treehash does not have a node at this height */
    if (state->treehash[nodeh].completed) {
        return;
    }

    /* If the top node has the same index as we look for, it works because the top node is
    the parent of idx at height nodeh */
    if ((idx >> nodeh) == treehashnode_indices[nodeh]) {
        // set treehash_h node
        memcpy(state->treehash[nodeh].node, stack+(stackoffset-1)*params->n, params->n);
        state->treehash[nodeh].completed = 1;
    }
    // The left sibling could also match
    else if ((idx >> nodeh)-1 == treehashnode_indices[nodeh]) {
        // set treehash_h node
        memcpy(state->treehash[nodeh].node, stack+(stackoffset-2)*params->n, params->n);
        state->treehash[nodeh].completed = 1;
    }
}

void recover_bds_state(const xmss_params *params, unsigned char *root_node, uint32_t idx_leaf,
                          bds_state *state, const unsigned char *sk_seed,
                          const unsigned char *pub_seed, const uint32_t addr[8])
{
    // use three different addresses because at this point we use all three formats in parallel
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};
    // only copy layer and tree address parts
    copy_subtree_addr(ots_addr, addr);
    set_type(ots_addr, 0); // type = ots
    copy_subtree_addr(ltree_addr, addr);
    set_type(ltree_addr, 1);
    copy_subtree_addr(node_addr, addr);
    set_type(node_addr, 2);

    uint32_t lastnode, i;
    unsigned char stack[(params->tree_height+1)*params->n]; // stack of nodes
    unsigned int stacklevels[params->tree_height+1]; // height for node in stack
    unsigned int stackoffset=0; // stack head in stack array
    unsigned int nodeh; // node height

    lastnode = (1<<params->tree_height);

    for (i = 0; i < params->tree_height-params->bds_k; i++) {
        state->treehash[i].h = i; // set each treehash_h (treehash[all heights])
        state->treehash[i].completed = 0; // set every treehash instance to completed
        state->treehash[i].stackusage = 0; // there is no stackusage for any treehash instance
    }

    /* Begin with computing all authentication node position in tree */
    uint32_t *auth_indices = calloc(params->tree_height, sizeof(uint32_t));
    for (i = 0; i < params->tree_height; i++) {
        uint32_t parenth_index = idx_leaf >> i;
        if (parenth_index % 2 == 0) { // if parent node is a left node
            parenth_index++;
        }
        else { // if parent node is a right node
            parenth_index--;
        }
        auth_indices[i] = parenth_index;
    }

    /* Then compute KEEP node positions in the tree */
    uint32_t *keep_indices = calloc(params->tree_height-params->bds_k, sizeof(uint32_t));
    for (i = 0; i < params->tree_height-params->bds_k; i++) {
        uint32_t keep_interval = (1 << i) * 4; // 2^i * 4
        uint32_t first_keep_idx = 1 << i; // 2^i
        uint32_t diff_keep_idx = idx_leaf % keep_interval;

        if (diff_keep_idx >= first_keep_idx && diff_keep_idx < 2*first_keep_idx) {
            // The position of the keep index at height i
            keep_indices[i] = (idx_leaf - (diff_keep_idx - first_keep_idx)) >> i;
        }
    }
    for (i = 0; i < params->tree_height-params->bds_k; i++) {
        // If keep_indices[i] remained unintialized, we do not compute it and therefore
        // set it to an uncomputable value, namely max leaf idx
        if (keep_indices[i] == 0)
            keep_indices[i] = 1 << params->tree_height;
    }

    /* Then compute TREEHASH node positions in the tree */
    uint32_t *treehashnode_indices = calloc(params->tree_height-params->bds_k, sizeof(uint32_t));
    for (i = 0; i < params->tree_height-params->bds_k; i++) {
        uint32_t treehashinit_interval = 1 << (i+1);
        uint32_t diff_treehashinit_idx = idx_leaf % treehashinit_interval;
        uint32_t leaf_idx = idx_leaf - diff_treehashinit_idx;
        uint32_t start_treehashinit_idx = leaf_idx + 3 * (1 << i);
        // start_treehashinit_idx is within the tree
        if (start_treehashinit_idx < 1U << params->tree_height) {
            treehashnode_indices[i] = start_treehashinit_idx >> i;
            state->treehash[i].next_idx = start_treehashinit_idx;
        }
        // This treehash node is not needed (we're almost at the end of the tree)
        else {
            treehashnode_indices[i] = 0;
            state->treehash[i].completed = 1;
        }
    }

    // Iterate over all leaf nodes
    for (unsigned int idx = 0; idx < lastnode; idx++) {
        // Compute the WOTS pk
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        // put leaf node in stack
        gen_leaf_wots(params, stack+stackoffset*params->n, sk_seed, pub_seed, ltree_addr, ots_addr);
        // node in stack is a leaf (h=0)
        stacklevels[stackoffset] = 0;
        // increase stack head
        stackoffset++; 

        // while top two nodes are of the same height
        while (stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2]) { 
            // height of top two nodes
            nodeh = stacklevels[stackoffset-1]; 
            /* If the top node has the same index as we look for, it works because the top node is
            the parent of idx at height nodeh */
            // We look for auth nodes
            match_auth_node(params, idx, state, nodeh, auth_indices, stack, stackoffset);
            // We look for retain nodes
            if (nodeh >= params->tree_height - params->bds_k) {
                memcpy(state->retain + ((1 << (params->tree_height - 1 - nodeh)) + nodeh - params->tree_height + (((idx >> nodeh) - 3) >> 1)) * params->n, stack+(stackoffset-1)*params->n, params->n);
            }
            else {
                // We look for keep nodes
                match_keep_node(params, idx, state, nodeh, keep_indices, stack, stackoffset);
                // We look for treehashinit nodes
                match_treehashinit_node(params, idx, state, nodeh, treehashnode_indices, stack, stackoffset);
            }
            // set node_addr to (current?) node height
            set_tree_height(node_addr, stacklevels[stackoffset-1]);
            // set node_addr to index of next node (on height h+1?)
            set_tree_index(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
            // compute hash and put on stack
            thash_h(params, stack+(stackoffset-2)*params->n, stack+(stackoffset-2)*params->n, pub_seed, node_addr); 
            // new node on stack is on one level higher
            stacklevels[stackoffset-2]++; 
            // decrease stack head
            stackoffset--; 
        }
    }

    for (i = 0; i < params->n; i++) {
        root_node[i] = stack[i]; // copy stack to the tree root in pk
    }

    free(auth_indices);
    free(keep_indices);
    free(treehashnode_indices);
}

int core_recover_bds_data(xmss_params *params, unsigned char *sk, unsigned int *corrupted_layers,
                            unsigned int nr_of_hmaced_bds_layers) {
    uint32_t addr[8] = {0};
    uint32_t ots_addr[8] = {0};
    unsigned long long idx = 0;
    unsigned int i;
    unsigned char *wots_sigs;
    unsigned char sk_seed[params->n];
    unsigned char pub_seed[params->n];
    uint64_t idx_tree;
    uint32_t idx_leaf;
    int is_corrupt = 0;

    // Extract SK
    for (i = 0; i < params->index_bytes; i++) {
        idx |= ((unsigned long long)sk[i]) << 8*(params->index_bytes - 1 - i);
    }

    // Initialize BDS states
    bds_state states[2*params->d - 1];
    treehash_inst treehash[(2*params->d - 1) * (params->tree_height - params->bds_k)];
    for (i = 0; i < 2*params->d - 1; i++) {
        states[i].treehash = treehash + i * (params->tree_height - params->bds_k);
    }

    for (i = 0; i < 2*params->d - 1; i++) {
        states[i].stackoffset = 0;
        states[i].next_leaf = 0;
    }
    
    xmssmt_deserialize_state(params, states, &wots_sigs, sk + params->index_bytes + 4*params->n, 2*params->d - 1);

    memcpy(sk_seed, sk+params->index_bytes, params->n);
    memcpy(pub_seed, sk+params->index_bytes+3*params->n, params->n);

    /* Recover the BDS state for all trees */
    idx_tree = idx >> (params->tree_height);
    idx_leaf = idx & ((1 << params->tree_height)-1);
    set_layer_addr(addr, 0);
    set_tree_addr(addr, idx_tree);
    unsigned char root_node[params->pk_bytes];
    for (i = 0; i < params->d; i++) {
        is_corrupt = is_layer_corrupt(params, corrupted_layers, data_layer, i);
        int wots_is_corrupt = is_layer_corrupt(params, corrupted_layers, WOTS_sigs, i);
        if (is_corrupt || wots_is_corrupt) {
            recover_bds_state(params, root_node, idx_leaf, states+i, sk_seed, pub_seed, addr);
        }
        idx_tree = idx >> (params->tree_height * (i+2));
        idx_leaf = (idx >> (params->tree_height * (i+1))) & ((1 << params->tree_height)-1);
        set_layer_addr(addr, (i+1));
        set_tree_addr(addr, idx_tree);

        if (params->d > 1 && i < params->d-1 && wots_is_corrupt) {
            // Only sign when we use XMSS^MT, and in XMSS^MT do not sign the top layer
            set_layer_addr(ots_addr, (i+1));
            set_tree_addr(ots_addr, idx_tree);
            set_ots_addr(ots_addr, idx_leaf);
            wots_sign(params, wots_sigs + i*params->wots_sig_bytes, root_node, sk_seed, pub_seed, ots_addr);
        }
    }

    xmssmt_serialize_state(params, sk + params->index_bytes + 4*params->n, states, 2*params->d - 1);

    /* Recover BDS NEXT layers */
    is_corrupt = is_layer_corrupt(params, corrupted_layers, NEXT_layer, 0);
    if (is_corrupt) {
        unsigned long long diff_start_of_tree = idx % (1<<params->tree_height);
        unsigned long long start_of_tree = idx - diff_start_of_tree;
        bulk_NEXT0_tree(params, sk, start_of_tree, idx+params->autoreserve+1);
        bulk_upper_NEXT_trees(params, sk, idx+(params->autoreserve+1)-1);
    }

    /* Also recover BDS RESERVED */
    if (params->autoreserve > 0) {
        is_corrupt = is_layer_corrupt(params, corrupted_layers, RESERVED, 0);
        if (is_corrupt) {
            bulk_bds_reserved(params, sk, idx, idx+params->autoreserve+1, params->index_bytes + 4*params->n, 1);
        }
    }

    return 0;
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_core_keypair(xmss_params *params,
                      unsigned char *pk, unsigned char *sk)
{
    uint32_t addr[8] = {0};

    // TODO refactor BDS state not to need separate treehash instances
    bds_state state;
    treehash_inst treehash[params->tree_height - params->bds_k];
    state.treehash = treehash;

    xmss_deserialize_state(params, &state, sk + params->index_bytes + 4*params->n);

    state.stackoffset = 0;
    state.next_leaf = 0;

    // Set idx = 0
    sk[0] = 0;
    sk[1] = 0;
    sk[2] = 0;
    sk[3] = 0;
    // Init SK_SEED (n byte) and SK_PRF (n byte)
    randombytes(sk + params->index_bytes, 2*params->n);

    // Init PUB_SEED (n byte)
    randombytes(sk + params->index_bytes + 3*params->n, params->n);

    // Copy PUB_SEED to public key
    memcpy(pk + params->n, sk + params->index_bytes + 3*params->n, params->n);

    // Compute root
    treehash_init(params, pk, params->tree_height, 0, &state, sk + params->index_bytes, sk + params->index_bytes + 3*params->n, addr);
    // copy root to sk
    memcpy(sk + params->index_bytes + 2*params->n, pk, params->n);

    /* Write the BDS state into sk. */
    xmss_serialize_state(params, sk + params->index_bytes + 4*params->n, &state, 1);

    /* Set the BDS state index to 0 */
    ull_to_bytes(sk + params->sk_bytes, params->index_bytes, 0);

    if (params->autoreserve > 0) {
        // /* Fast forward the bds state autoreserve times for reservation function and
        // store this in bds_reserved */
        bulk_bds_reserved(params, sk, 0, params->autoreserve+1, params->index_bytes + 4*params->n, 1);
    }
    
    return 0;
}

/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmss_core_sign(xmss_params *params,
                   unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen)
{
    const unsigned char *pub_root = sk + params->index_bytes + 2*params->n;

    uint16_t i = 0;
    int sigs_reserved;

    // TODO refactor BDS state not to need separate treehash instances
    bds_state state;
    treehash_inst treehash[params->tree_height - params->bds_k];
    state.treehash = treehash;

    /* Load the BDS state from sk. */
    xmss_deserialize_state(params, &state, sk + params->index_bytes + 4*params->n);

    // Extract SK
    unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
    // printf("idx=%ld\n", idx);
    // printf("autoreserve=%d\n", params->autoreserve);
    
    /* Check if we can still sign with this sk.
     * If not, return -2
     * 
     * If this is the last possible signature (because the max index value 
     * is reached), production implementations should delete the secret key 
     * to prevent accidental further use.
     * 
     * For the case of total tree height of 64 we do not use the last signature 
     * to be on the safe side (there is no index value left to indicate that the 
     * key is finished, hence external handling would be necessary)
     */ 
    if (idx >= ((1ULL << params->full_height) - 1)) {
        // Delete secret key here. We only do this in memory, production code
        // has to make sure that this happens on disk.
        if (idx > ((1ULL << params->full_height) - 1))
            return -2; // We already used all one-time keys
        if ((params->full_height == 64) && (idx == ((1ULL << params->full_height) - 1))) 
                return -2; // We already used all one-time keys
    }
    
    unsigned char sk_seed[params->n];
    memcpy(sk_seed, sk + params->index_bytes, params->n);
    unsigned char sk_prf[params->n];
    memcpy(sk_prf, sk + params->index_bytes + params->n, params->n);
    unsigned char pub_seed[params->n];
    memcpy(pub_seed, sk + params->index_bytes + 3*params->n, params->n);

    // index as 32 bytes string
    unsigned char idx_bytes_32[32];
    ull_to_bytes(idx_bytes_32, 32, idx);

    // Update SK
    sigs_reserved = xmss_advance_count(params, idx);
    sk[0] = ((idx + 1) >> 24) & 255;
    sk[1] = ((idx + 1) >> 16) & 255;
    sk[2] = ((idx + 1) >> 8) & 255;
    sk[3] = (idx + 1) & 255;
    // Secret key for this non-forward-secure version is now updated.
    // A production implementation should consider using a file handle instead,
    //  and write the updated secret key at this point!

    // Init working params
    unsigned char R[params->n]; // output holder for PRF
    unsigned char msg_h[params->n]; // message digest
    uint32_t ots_addr[8] = {0};

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    prf(params, R, idx_bytes_32, sk_prf);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    memcpy(sm + params->sig_bytes, m, mlen);

    /* Compute the message hash. */
    hash_message(params, msg_h, R, pub_root, idx,
                 sm + params->sig_bytes - params->padding_len - 3*params->n,
                 mlen);

    // Start collecting signature
    *smlen = 0;

    // Copy index to signature
    sm[0] = (idx >> 24) & 255;
    sm[1] = (idx >> 16) & 255;
    sm[2] = (idx >> 8) & 255;
    sm[3] = idx & 255;

    sm += 4;
    *smlen += 4;

    // Copy R to signature
    for (i = 0; i < params->n; i++) {
        sm[i] = R[i];
    }

    sm += params->n;
    *smlen += params->n;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Prepare Address
    set_type(ots_addr, 0);
    set_ots_addr(ots_addr, idx);

    // Compute WOTS signature
    wots_sign(params, sm, msg_h, sk_seed, pub_seed, ots_addr);

    sm += params->wots_sig_bytes;
    *smlen += params->wots_sig_bytes;

    // the auth path was already computed during the previous round
    memcpy(sm, state.auth, params->tree_height*params->n);

    // advance the bds state in NV memory if needed
    unsigned int updates = (params->tree_height - params->bds_k) >> 1;
    bds_advance(sigs_reserved, params, &state, sk, idx, sk_seed, pub_seed, ots_addr, &updates, NULL, NULL);

    // sk is updated for next signature generation
    xmss_serialize_state(params, sk + params->index_bytes + 4*params->n, &state, 1); 

    sm += params->tree_height*params->n;
    *smlen += params->tree_height*params->n;

    memcpy(sm, m, mlen);
    *smlen += mlen;

    return sigs_reserved;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_core_keypair(xmss_params *params,
                        unsigned char *pk, unsigned char *sk)
{
    uint32_t addr[8] = {0};
    unsigned int i;
    unsigned char *wots_sigs;

    // TODO refactor BDS state not to need separate treehash instances
    bds_state states[2*params->d - 1];
    treehash_inst treehash[(2*params->d - 1) * (params->tree_height - params->bds_k)];
    for (i = 0; i < 2*params->d - 1; i++) {
        states[i].treehash = treehash + i * (params->tree_height - params->bds_k);
    }

    xmssmt_deserialize_state(params, states, &wots_sigs, sk + params->index_bytes + 4*params->n, 2*params->d - 1);

    for (i = 0; i < 2 * params->d - 1; i++) {
        states[i].stackoffset = 0;
        states[i].next_leaf = 0;
    }

    // Set idx = 0
    for (i = 0; i < params->index_bytes; i++) {
        sk[i] = 0;
    }
    // Init SK_SEED (params->n byte) and SK_PRF (params->n byte)
    randombytes(sk+params->index_bytes, 2*params->n);

    // Init PUB_SEED (params->n byte)
    randombytes(sk+params->index_bytes + 3*params->n, params->n);

    // Copy PUB_SEED to public key
    memcpy(pk+params->n, sk+params->index_bytes+3*params->n, params->n);

    // Start with the bottom-most layer
    set_layer_addr(addr, 0);
    // Set up state and compute wots signatures for all but topmost tree root
    for (i = 0; i < params->d - 1; i++) {
        // Compute seed for OTS key pair
        treehash_init(params, pk, params->tree_height, 0, states + i, sk+params->index_bytes, pk+params->n, addr);
        set_layer_addr(addr, (i+1));
        wots_sign(params, wots_sigs + i*params->wots_sig_bytes, pk, sk + params->index_bytes, pk+params->n, addr);
    }
    // Address now points to the single tree on layer d-1
    treehash_init(params, pk, params->tree_height, 0, states + i, sk+params->index_bytes, pk+params->n, addr);
    memcpy(sk + params->index_bytes + 2*params->n, pk, params->n);

    xmssmt_serialize_state(params, sk + params->index_bytes + 4*params->n, states, 2*params->d - 1);

    /* Set the BDS state index to 0 */
    ull_to_bytes(sk + params->sk_bytes, params->index_bytes, 0);

    if (params->autoreserve > 0) {
        bulk_bds_reserved(params, sk, 0, params->autoreserve+1, params->index_bytes + 4*params->n, 1);
        bulk_NEXT0_tree(params, sk, 0, params->autoreserve+1);
    }

    return 0;
}


/**
 * Signs a message.
 * Returns
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 *
 */
int xmssmt_core_sign(xmss_params *params,
                     unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen)
{  
    const unsigned char *pub_root = sk + params->index_bytes + 2*params->n;

    uint64_t idx_tree;
    uint32_t idx_leaf;
    uint64_t i;
    int needswap_upto = -1;
    unsigned int updates;

    unsigned char sk_seed[params->n];
    unsigned char sk_prf[params->n];
    unsigned char pub_seed[params->n];
    // Init working params
    unsigned char R[params->n];
    unsigned char msg_h[params->n];
    uint32_t addr[8] = {0};
    uint32_t ots_addr[8] = {0};
    unsigned char idx_bytes_32[32];

    unsigned char *wots_sigs;

    // TODO refactor BDS state not to need separate treehash instances
    bds_state states[2*params->d - 1];
    treehash_inst treehash[(2*params->d - 1) * (params->tree_height - params->bds_k)];
    for (i = 0; i < 2*params->d - 1; i++) {
        states[i].treehash = treehash + i * (params->tree_height - params->bds_k);
    }

    xmssmt_deserialize_state(params, states, &wots_sigs, sk + params->index_bytes + 4*params->n, 2*params->d - 1);

    // Extract SK
    unsigned long long idx = 0;
    for (i = 0; i < params->index_bytes; i++) {
        idx |= ((unsigned long long)sk[i]) << 8*(params->index_bytes - 1 - i);
    }

    /* Check if we can still sign with this sk.
     * If not, return -2
     * 
     * If this is the last possible signature (because the max index value 
     * is reached), production implementations should delete the secret key 
     * to prevent accidental further use.
     * 
     * For the case of total tree height of 64 we do not use the last signature 
     * to be on the safe side (there is no index value left to indicate that the 
     * key is finished, hence external handling would be necessary)
     */ 
    if (idx >= ((1ULL << params->full_height) - 1)) {
        // Delete secret key here. We only do this in memory, production code
        // has to make sure that this happens on disk.
        if (idx > ((1ULL << params->full_height) - 1))
            return -2; // We already used all one-time keys
        if ((params->full_height == 64) && (idx == ((1ULL << params->full_height) - 1))) 
                return -2; // We already used all one-time keys
    }
    
    memcpy(sk_seed, sk+params->index_bytes, params->n);
    memcpy(sk_prf, sk+params->index_bytes+params->n, params->n);
    memcpy(pub_seed, sk+params->index_bytes+3*params->n, params->n);

    // Update SK
    int sigs_reserved = xmss_advance_count(params, idx);
    for (i = 0; i < params->index_bytes; i++) {
        sk[i] = ((idx + 1) >> 8*(params->index_bytes - 1 - i)) & 255;
    }
    // Secret key for this non-forward-secure version is now updated.
    // A production implementation should consider using a file handle instead,
    //  and write the updated secret key at this point!

    // ---------------------------------
    // Message Hashing
    // ---------------------------------

    // Message Hash:
    // First compute pseudorandom value
    ull_to_bytes(idx_bytes_32, 32, idx);
    prf(params, R, idx_bytes_32, sk_prf);

    /* Already put the message in the right place, to make it easier to prepend
     * things when computing the hash over the message. */
    memcpy(sm + params->sig_bytes, m, mlen);

    /* Compute the message hash. */
    hash_message(params, msg_h, R, pub_root, idx,
                 sm + params->sig_bytes - params->padding_len - 3*params->n,
                 mlen);

    // Start collecting signature
    *smlen = 0;

    // Copy index to signature
    for (i = 0; i < params->index_bytes; i++) {
        sm[i] = (idx >> 8*(params->index_bytes - 1 - i)) & 255;
    }

    sm += params->index_bytes;
    *smlen += params->index_bytes;

    // Copy R to signature
    for (i = 0; i < params->n; i++) {
        sm[i] = R[i];
    }

    sm += params->n;
    *smlen += params->n;

    // ----------------------------------
    // Now we start to "really sign"
    // ----------------------------------

    // Handle lowest layer separately as it is slightly different...

    // Prepare Address
    set_type(ots_addr, 0);
    idx_tree = idx >> params->tree_height;
    idx_leaf = (idx & ((1 << params->tree_height)-1));
    set_layer_addr(ots_addr, 0);
    set_tree_addr(ots_addr, idx_tree);
    set_ots_addr(ots_addr, idx_leaf);

    // Compute WOTS signature
    wots_sign(params, sm, msg_h, sk_seed, pub_seed, ots_addr);

    sm += params->wots_sig_bytes;
    *smlen += params->wots_sig_bytes;

    memcpy(sm, states[0].auth, params->tree_height*params->n);
    sm += params->tree_height*params->n;
    *smlen += params->tree_height*params->n;

    // prepare signature of remaining layers
    for (i = 1; i < params->d; i++) {
        // put WOTS signature in place
        memcpy(sm, wots_sigs + (i-1)*params->wots_sig_bytes, params->wots_sig_bytes);

        sm += params->wots_sig_bytes;
        *smlen += params->wots_sig_bytes;

        // put AUTH nodes in place
        memcpy(sm, states[i].auth, params->tree_height*params->n);
        sm += params->tree_height*params->n;
        *smlen += params->tree_height*params->n;
    }

    updates = (params->tree_height - params->bds_k) >> 1;

    // idx_tree is the tree where NEXT_0 is currently at
    idx_tree = (idx+params->autoreserve) >> params->tree_height;
    set_tree_addr(addr, (idx_tree + 1));
    // mandatory update for NEXT_0 (does not count towards h-k/2) if NEXT_0 exists
    if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << params->full_height)) {
        // always update NEXT_0 if autoreserve = 0
        if (params->autoreserve == 0) {
            bds_state_update(params, &states[params->d], sk_seed, pub_seed, addr);
        }
        else {
            unsigned long bds_idx = bytes_to_ull(sk + params->sk_bytes, params->index_bytes);
            unsigned long bds_reserved_idx = bytes_to_ull(sk + params->sk_bytes + params->index_bytes, params->index_bytes);
            // update NEXT_0 if we haven't just reserved yet
            if (bds_idx < bds_reserved_idx || (idx % (params->autoreserve+1) > 0 && bds_idx == bds_reserved_idx)) {
                bds_state_update(params, &states[params->d], sk_seed, pub_seed, addr);
            }
        }
    }

    // Advance the bottom layer's BDS state
    bds_advance(sigs_reserved, params, &states[0], sk, idx, sk_seed, pub_seed, ots_addr, 
                    &updates, wots_sigs, &needswap_upto);

    // Update the treehash instances and NEXT trees
    for (uint64_t i = 1; i < params->d; i++) {
        set_layer_addr(addr, i);
        // check if we're not at the end of a tree (if idx+1 != nr_leafs in tree-1)
        if (! (((idx + 1) & ((1ULL << ((i+1)*params->tree_height)) - 1)) == 0)) {
            idx_leaf = (idx >> (params->tree_height * i)) & ((1 << params->tree_height)-1);
            idx_tree = (idx >> (params->tree_height * (i+1)));
            set_tree_addr(addr, idx_tree);
            updates = bds_treehash_update(params, &states[i], updates, sk_seed, pub_seed, addr);
        }
            
        // if a NEXT-tree exists for this level;
        idx_leaf = ((idx+params->autoreserve) >> (params->tree_height * i)) & ((1 << params->tree_height)-1);
        idx_tree = ((idx+params->autoreserve) >> (params->tree_height * (i+1)));
        set_tree_addr(addr, (idx_tree + 1));
        // if we haven't just signed and switched trees for this layer
        if (! (((idx+params->autoreserve + 1) & ((1ULL << ((i+1)*params->tree_height)) - 1)) == 0)) {
            // if we haven't reached the end of leaves at this layer (computed using bottom leaves)
            if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << (params->full_height - params->tree_height * i))) {
                // if we have updates left and we haven't reached the end of the full tree
                if (updates > 0 && states[params->d + i].next_leaf < (1ULL << params->full_height)) {
                    // available leaves left is including current leaf
                    unsigned long long NEXT_leafs_to_be_computed = (1ULL << params->tree_height) - states[params->d + i].next_leaf;
                    unsigned long long available_leaves_left = (1ULL << (params->tree_height * (i+1)))*(idx_tree+1) - (idx+params->autoreserve) - 1;
                    // update only once if we don't need to bulk compute
                    unsigned long long bds_state_update_per_round = NEXT_leafs_to_be_computed / available_leaves_left;
                    if (bds_state_update_per_round == 0) {
                        bds_state_update_per_round = 1;
                    }
                    while (bds_state_update_per_round > 0) {
                        // if we haven't reached the end of leafs at this layer
                        if ((1 + idx_tree) * (1 << params->tree_height) + idx_leaf < (1ULL << (params->full_height - params->tree_height * i))) { 
                            // if we have updates left and we haven't reached the end of the full tree
                            if (updates > 0 && states[params->d + i].next_leaf < (1ULL << params->full_height)) {
                                bds_state_update(params, &states[params->d + i], sk_seed, pub_seed, addr);
                                updates--;
                            }
                            bds_state_update_per_round--;
                        }
                    }
                }
            }
        }
    }

    memcpy(sm, m, mlen);
    *smlen += mlen;

    xmssmt_serialize_state(params, sk + params->index_bytes + 4*params->n, states, 2*params->d - 1);

    return sigs_reserved;
}
