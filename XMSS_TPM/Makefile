CC = /usr/bin/gcc
CFLAGS = -Wall -O3 -Wextra -Wpedantic
LDLIBS = -lcrypto

# TPM
CFLAGS += -DTPM_POSIX -DTPM_TPM20
INCLUDES += -I/<directory to IBM TSS library, for example: /home/user/ibmtss1.6.0/utils>
# link - common flags flags TSS library and applications
LDFLAGS += -L<directory to IBM TSS library, for example: /home/user/ibmtss1.6.0/utils>
# hardening flags for linking executables
LDAFLAGS += -pie -Wl,-z,now -Wl,-rpath,<directory to IBM TSS library, for example: /home/user/ibmtss1.6.0/utils>
LDALIBS +=  -libmtssutils -libmtss

SOURCES = params.c hash.c fips202.c hash_address.c randombytes.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c xmss_reserve.c tpm_functions.c zeroize.c hash_bds_data.c
HEADERS = params.h hash.h fips202.h hash_address.h randombytes.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h xmss_reserve.h tpm_functions.h zeroize.h hash_bds_data.h

SOURCES_FAST_CORE = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES)) 
SOURCES_FAST = $(subst xmss_reserve.c,xmss_reserve_fast.c,$(SOURCES_FAST_CORE))
HEADERS_FAST_CORE = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS)) 
HEADERS_FAST = $(subst xmss_reserve.c,xmss_reserve_fast.c,$(HEADERS_FAST_CORE))

UI = ui/xmss_keypair_default \
	 ui/xmss_sign_default \
	 ui/xmss_open_default \
	 ui/xmssmt_keypair_default \
	 ui/xmssmt_sign_default \
	 ui/xmssmt_open_default \
	 ui/xmss_keypair_fast_default \
	 ui/xmss_sign_fast_default \
	 ui/xmss_open_fast_default \
	 ui/xmssmt_keypair_fast_default \
	 ui/xmssmt_sign_fast_default \
	 ui/xmssmt_open_fast_default \
	 ui/xmss_keypair_tpm \
	 ui/xmss_sign_tpm \
	 ui/xmss_open_tpm \
	 ui/xmssmt_keypair_tpm \
	 ui/xmssmt_sign_tpm \
	 ui/xmssmt_open_tpm \
	 ui/xmss_keypair_fast_tpm \
	 ui/xmss_sign_fast_tpm \
	 ui/xmss_open_fast_tpm \
	 ui/xmssmt_keypair_fast_tpm \
	 ui/xmssmt_sign_fast_tpm \
	 ui/xmssmt_open_fast_tpm \

all: ui

ui: $(UI)

# DEFAULT_STORAGE
ui/xmss_%_fast_default: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DDEFAULT_STORAGE $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES_FAST) $< $(LDALIBS) $(LDLIBS)

ui/xmssmt_%_fast_default: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DDEFAULT_STORAGE -DXMSSMT $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES_FAST) $< $(LDALIBS) $(LDLIBS)

ui/xmss_%_default: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DDEFAULT_STORAGE $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES) $< $(LDALIBS) $(LDLIBS)

ui/xmssmt_%_default: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DDEFAULT_STORAGE -DXMSSMT $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES) $< $(LDALIBS) $(LDLIBS)

# TPM_STORAGE
ui/xmss_%_fast_tpm: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DTPM_STORAGE $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES_FAST) $< $(LDALIBS) $(LDLIBS)

ui/xmssmt_%_fast_tpm: ui/%.c $(SOURCES_FAST) $(OBJS) $(HEADERS_FAST)
	$(CC) -DTPM_STORAGE -DXMSSMT $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES_FAST) $< $(LDALIBS) $(LDLIBS)

ui/xmss_%_tpm: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DTPM_STORAGE $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES) $< $(LDALIBS) $(LDLIBS)

ui/xmssmt_%_tpm: ui/%.c $(SOURCES) $(OBJS) $(HEADERS)
	$(CC) -DTPM_STORAGE -DXMSSMT $(CFLAGS) $(LDFLAGS) $(LDAFLAGS) $(INCLUDES) -o $@ $(SOURCES) $< $(LDALIBS) $(LDLIBS)

clean:
	-$(RM) $(UI)
