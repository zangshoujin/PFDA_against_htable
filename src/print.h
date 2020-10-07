#ifndef __print_h__
#define __print_h__
typedef unsigned char byte;

#include "encrypt.h"

void print_4_by_4(byte temp[16]);
void print_4_by_4_int(int temp[16]);
int Is_equal(byte a[16],byte b[16]);
int print_count(int first_success_num,int first_fail_num,int first_out_time_num,int success_num_in_fail[],int fail_num_in_fail[],
	int out_time_num_in_fail[],int success_num_in_out_time[],int fail_num_in_out_time[],
	int out_time_num_in_out_time[],int other_fail_num,int no_chain_num,int more_chain_num,int one_chain_num,int invalid_error_num,
	int success_num_in_timeout,int fail_num_in_timeout,int timeout_num_in_timeout);

int print_encrypt_num(int first_encrypt_num[],int all_encrypt_num[],int later_fail_encrypt_num[][Experment_num],
	int later_out_time_encrypt_num[][Experment_num]);

int print_round_key(byte in[16],byte out[16],byte key[16],byte outex[16],int nt,int base,byte w[176]);

#endif