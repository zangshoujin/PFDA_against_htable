#include <stdio.h>
#include "print.h"
#include "aes_rp.h"
#include "encrypt.h"
typedef unsigned char byte;

void print_4_by_4(byte temp[16]){
	FILE *fpWrite = fopen("experiment.txt", "a+");
	for(int j=0;j<16;j++){
		printf("0x%02x,",temp[j]);
		fprintf(fpWrite,"0x%02x,",temp[j]);
		if((j+1)%4==0){
			printf("\n");
			fprintf(fpWrite,"\n");
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
}

void print_4_by_4_int(int temp[16]){
	FILE *fpWrite = fopen("experiment.txt", "a+");
	for(int j=0;j<16;j++){
		printf("%d ",temp[j]);
		fprintf(fpWrite,"%d ",temp[j]);
		if((j+1)%4==0){
			printf("\n");
			fprintf(fpWrite,"\n");
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
}

int print_count(int first_success_num,int first_fail_num,int first_out_time_num,int second_success_num_in_fail,int second_fail_num_in_fail,
	int second_out_time_num_in_fail,int second_success_num_in_out_time,int second_fail_num_in_out_time,
	int second_out_time_num_in_out_time,int other_fail_num,int no_chain_num,int more_chain_num,int match_four_num,int invalid_error_num,int overtime_success_num){
	
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("first_success_num:%d\n",first_success_num);
	fprintf(fpWrite,"first_success_num:%d\n",first_success_num);
	printf("first_fail_num:%d\n",first_fail_num);
	fprintf(fpWrite,"first_fail_num:%d\n",first_fail_num);
	printf("first_out_time_num:%d\n",first_out_time_num);
	fprintf(fpWrite,"first_out_time_num:%d\n",first_out_time_num);

	printf("second_success_num_in_fail:%d\n",second_success_num_in_fail);
	fprintf(fpWrite,"second_success_num_in_fail:%d\n",second_success_num_in_fail);
	printf("second_fail_num_in_fail:%d\n",second_fail_num_in_fail);
	fprintf(fpWrite,"second_fail_num_in_fail:%d\n",second_fail_num_in_fail);
	printf("second_out_time_num_in_fail:%d\n",second_out_time_num_in_fail);
	fprintf(fpWrite,"second_out_time_num_in_fail:%d\n",second_out_time_num_in_fail);

	printf("second_success_num_in_out_time:%d\n",second_success_num_in_out_time);
	fprintf(fpWrite,"second_success_num_in_out_time:%d\n",second_success_num_in_out_time);
	printf("second_fail_num_in_out_time:%d\n",second_fail_num_in_out_time);
	fprintf(fpWrite,"second_fail_num_in_out_time:%d\n",second_fail_num_in_out_time);
	printf("second_out_time_num_in_out_time:%d\n",second_out_time_num_in_out_time);
	fprintf(fpWrite,"second_out_time_num_in_out_time:%d\n",second_out_time_num_in_out_time);

	printf("other_fail_num:%d\n",other_fail_num);
	fprintf(fpWrite,"other_fail_num:%d\n",other_fail_num);
	printf("no_chain_num:%d\n",no_chain_num);
	fprintf(fpWrite,"no_chain_num:%d\n",no_chain_num);
	printf("more_chain_num:%d\n",more_chain_num);
	fprintf(fpWrite,"more_chain_num:%d\n",more_chain_num);
	printf("match_four_num:%d\n",match_four_num);
	fprintf(fpWrite,"match_four_num:%d\n",match_four_num);
	printf("invalid_error_num:%d\n",invalid_error_num);
	fprintf(fpWrite,"invalid_error_num:%d\n",invalid_error_num);

	printf("overtime_success_num:%d\n",overtime_success_num);
	fprintf(fpWrite,"overtime_success_num:%d\n",overtime_success_num);
	fclose(fpWrite);
	return 0;
}


int print_encrypt_num(int first_encrypt_num[],int all_encrypt_num[],int second_fail_encrypt_num[],int second_out_time_encrypt_num[]){
	FILE *fpWrite = fopen("encrypt_times.txt", "a+");
	fprintf(fpWrite,"first_encrypt_num:\n");
	for(int i=0;i<Experment_num;i++){
		fprintf(fpWrite,"%d\t",first_encrypt_num[i]);
		if((i+1)%10==0)fprintf(fpWrite,"\n");
	}
	fprintf(fpWrite,"\n");
	fprintf(fpWrite,"all_encrypt_num:\n");
	for(int i=0;i<Experment_num;i++){
		fprintf(fpWrite,"%d\t",all_encrypt_num[i]);
		if((i+1)%10==0)fprintf(fpWrite,"\n");
	}
	fprintf(fpWrite,"\n");
	fprintf(fpWrite,"seconde_fail_encrypt_num:\n");
	for(int i=0;i<Experment_num;i++){
		fprintf(fpWrite,"%d\t",second_fail_encrypt_num[i]);
		if((i+1)%10==0)fprintf(fpWrite,"\n");
	}
	fprintf(fpWrite,"\n");
	fprintf(fpWrite,"second_out_time_encrypt_num:\n");
	for(int i=0;i<Experment_num;i++){
		fprintf(fpWrite,"%d\t",second_out_time_encrypt_num[i]);
		if((i+1)%10==0)fprintf(fpWrite,"\n");
	}
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
	return 0;
}

int print_round_key(byte in[16],byte out[16],byte key[16],byte outex[16],int nt,int base,byte w[176]){
	printf("*******子密钥开始线********\n");
	FILE *fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"**********子密钥开始线***********\n");
	fclose(fpWrite);
	run_aes(&aes_rp,in,out,key,outex,nt,base,w);
	printf("------子密钥结束线------\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"------子密钥结束线-------\n");
	fclose(fpWrite);
	return 0;
}
