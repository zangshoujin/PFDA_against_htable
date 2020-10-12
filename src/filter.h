#ifndef __filter_h__
#define __filter_h__
#include "difftribute_table.h"
#include <stdio.h>
typedef int bool;
#define true 1
#define false 0
typedef unsigned char byte;

int first_filter_difference_chain(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],int diff_delta_count[4],int* appear_4_but_not_match,int* no_chain,
	int* more_chain,int* one_chain);

int later_filter_difference_chain(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
    int relationship_delta_difference_cipher[4][4],int diff_delta_count[4]);

#endif