#ifndef __recovery_h__
#define __recovery_h__
#include "verify.h"
#include "recovery.h"
#include <stdio.h>
#include "difftribute_table.h"
#include "aes.h"
#include <stdio.h>
typedef unsigned char byte;

struct Different_Cipher{
	byte diff_cipher[2][16];
	int diff_local[4];
};

int recovery_main_key(byte key_10round[16],byte main_key[16]);

int recovery_10round_key(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],struct Different_Cipher dc[4],byte guess_key_10round[16][16],
	byte key_10round[16],byte w[176],int diff_delta_count[4],int* success_num,int* first_fail_num,byte cipher_verify[16]
	,byte in[16],int n,int nt,int base,byte reall_main_key[16],int *first_out_time_num,int *other_fail_num,int *overtime_success_num,
	int *overtime_fail_num,int *overtime_timeout_num);


#endif

