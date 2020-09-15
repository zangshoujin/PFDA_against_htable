#ifndef __verify_h__
#define __verify_h__
typedef int bool;
#define true 1
#define false 0
typedef unsigned char byte;
#include "filter.h"
#include "difftribute_table.h"
#include "aes_rp.h"
#include "recovery.h"
#include "aes_htable.h"
#include "aes_share.h"
#include <stdio.h>

#define OverTime_Num 4194304
/*
	2的30次方1073741824
	2的20次方1048576
	2的22次方4194304
	2的23次方8388608
	2的25次方33554432 理论上这个的超时时间应该是1800秒
*/

int verify_online_key(byte guess_key_10round[16][16],byte key_10round[16],byte w[176],int candidiate_key_count[16],
	int* first_success_num,int* first_fail_num,byte cipher_verify[16],byte in[16],int n,int nt,int base,byte reall_main_key[16],
	int *first_out_time_num,int *other_fail_num);


int verify_offline_key(byte guess_key_10round[16][16],byte key_10round[16],byte w[176],int candidiate_key_count[16],
	int* first_success_num,int* first_fail_num,byte cipher_verify[16],byte in[16],int n,int nt,int base,byte reall_main_key[16],
	int *first_out_time_num,int *other_fail_num);


#endif