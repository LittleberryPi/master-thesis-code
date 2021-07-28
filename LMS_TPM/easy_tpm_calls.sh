#!/bin/bash

PREFIX=/home/gialinh/Documents/Git\ Repositories/master-thesis-code/TPM/ibmtss1.6.0/utils/

export LD_LIBRARY_PATH=$PREFIX
# "${PREFIX}startup"

"${PREFIX}nvundefinespace" -hi o -ha 01000000
"${PREFIX}nvundefinespace" -hi o -ha 01000001
"${PREFIX}nvundefinespace" -hi o -ha 01000002

# "${PREFIX}dictionaryattacklockreset"

echo "hmac_session ended"
