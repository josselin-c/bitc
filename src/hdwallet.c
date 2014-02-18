#include <arpa/inet.h>

#include "util.h"
#include "hash.h"
#include "crypt.h"

enum key_type {
	XPUB_MAINNET  = 0x0488B21E,
	XPRIV_MAINNET = 0x0488ADE4,
	XPUB_TESTNET  = 0x04358394,
	XPRIV_TESTNET = 0x043587CF,
};

struct ext_prv_key {
	uint256 kpar;
	uint256 cpar;
};

struct ext_pub_key {
	uint256 Kpar;
	uint256 cpar;
};

bool
private_child_key_derivation(struct ext_prv_key *parent, uint32 i,
		struct ext_prv_key *child)
{
	uint512 I;
	uint8 data[37];
	uint256 IL;
	uint32 i_be = htonl(i);

	if (i & 0x80000000) {
		data[0] = 0;
		memcpy(data + 1, parent->kpar.data, sizeof parent->kpar.data);
		memcpy(data + 33, &i_be, 4);
		crypt_hmac_sha512(data, 37, parent->cpar.data,
				sizeof parent->cpar.data, &I);
	} else {

	}
	memcpy(IL.data, I.data, sizeof IL.data);
	memcpy(child->cpar.data, I.data + 32, sizeof child->cpar);
	return 1;
}
