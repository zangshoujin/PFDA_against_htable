#ifndef __repeat_attack__
#define __repeat_attack__

#include "encrypt.h"

int repeat_attack(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,int* appear_4_but_not_match,int* no_chain_num,int* more_chain_num,int* one_chain_num,
    int all_encrypt_num[Experment_num],int later_encrypt_num[attack_round][Experment_num],byte w[176],int e,int* success_num,int* fail_num,int* timeout_num,
    int* other_fail_num,int* success_num_in_timeout,int* fail_num_in_timeout,int* timeout_in_timeout,byte *plain_verify,int i);

#endif