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

int print_count(int first_success_num,int first_fail_num,int first_out_time_num,int success_num_in_fail[attack_round],int fail_num_in_fail[attack_round],
	int out_time_num_in_fail[attack_round],int success_num_in_out_time[attack_round],int fail_num_in_out_time[attack_round],
	int out_time_num_in_out_time[attack_round],int other_fail_num,int no_chain_num,int more_chain_num,int one_chain_num,int invalid_error_num,
	int success_num_in_timeout,int fail_num_in_timeout,int timeout_num_in_timeout){
	
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("first_success_num:%d\n",first_success_num);
	fprintf(fpWrite,"first_success_num:%d\n",first_success_num);
	printf("first_fail_num:%d\n",first_fail_num);
	fprintf(fpWrite,"first_fail_num:%d\n",first_fail_num);
	printf("first_out_time_num:%d\n",first_out_time_num);
	fprintf(fpWrite,"first_out_time_num:%d\n",first_out_time_num);

	int success_all_num = first_success_num;
	for(int i=1;i<attack_round;i++){
		success_all_num += success_num_in_fail[i];
		printf("%d_success_num_in_fail:%d\n",i+1,success_num_in_fail[i]);
		fprintf(fpWrite,"%d_success_num_in_fail:%d\n",i+1,success_num_in_fail[i]);
		printf("%d_fail_num_in_fail:%d\n",i+1,fail_num_in_fail[i]);
		fprintf(fpWrite, "%ds_fail_num_in_fail:%d\n",i+1,fail_num_in_fail[i]);
		printf("%d_out_time_num_in_fail:%d\n",i+1,out_time_num_in_fail[i]);
		fprintf(fpWrite,"%d_out_time_num_in_fail:%d\n",i+1,out_time_num_in_fail[i]);
		success_all_num += success_num_in_out_time[i];
		printf("%d_success_num_in_out_time:%d\n",i+1,success_num_in_out_time[i]);
		fprintf(fpWrite,"%d_success_num_in_out_time:%d\n",i+1,success_num_in_out_time[i]);
		printf("%d_fail_num_in_out_time:%d\n",i+1,fail_num_in_out_time[i]);
		fprintf(fpWrite,"%d_fail_num_in_out_time:%d\n",i+1,fail_num_in_out_time[i]);
		printf("%d_out_time_num_in_out_time:%d\n",i+1,out_time_num_in_out_time[i]);
		fprintf(fpWrite,"%d_out_time_num_in_out_time:%d\n",i+1,out_time_num_in_out_time[i]);
	}
	
	printf("other_fail_num:%d\n",other_fail_num);
	fprintf(fpWrite,"other_fail_num:%d\n",other_fail_num);
	printf("no_chain_num:%d\n",no_chain_num);
	fprintf(fpWrite,"no_chain_num:%d\n",no_chain_num);
	printf("more_chain_num:%d\n",more_chain_num);
	fprintf(fpWrite,"more_chain_num:%d\n",more_chain_num);
	printf("one_chain_num:%d\n",one_chain_num);
	fprintf(fpWrite,"one_chain_num:%d\n",one_chain_num);
	printf("invalid_error_num:%d\n",invalid_error_num);
	fprintf(fpWrite,"invalid_error_num:%d\n",invalid_error_num);

	printf("success_num_in_timeout:%d\n",success_num_in_timeout);
	fprintf(fpWrite,"success_num_in_timeout:%d\n",success_num_in_timeout);
	printf("fail_num_in_timeout:%d\n",fail_num_in_timeout);
	fprintf(fpWrite,"fail_num_in_timeout:%d\n",fail_num_in_timeout);
	printf("timeout_num_in_timeout:%d\n",timeout_num_in_timeout);
	fprintf(fpWrite,"timeout_num_in_timeout:%d\n",timeout_num_in_timeout);

	printf("success_all_num:%d\n",success_all_num);
	fprintf(fpWrite,"success_all_num:%d\n",success_all_num);
	fclose(fpWrite);
	return 0;
}

int print_encrypt_num(int first_encrypt_num[],int all_encrypt_num[],int later_fail_encrypt_num[][Experment_num],
	int later_out_time_encrypt_num[][Experment_num]){
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
	fprintf(fpWrite,"\n");\

	fprintf(fpWrite,"later_fail_encrypt_num:\n");
	for(int j=1;j<attack_round;j++){
		for(int i=0;i<Experment_num;i++){
			fprintf(fpWrite,"%d\t",later_fail_encrypt_num[j][i]);
			if((i+1)%10==0)fprintf(fpWrite,"\n");
		}
		fprintf(fpWrite,"\n");
	}

	fprintf(fpWrite,"later_out_time_encrypt_num:\n");
	for(int j=1;j<attack_round;j++){
		for(int i=0;i<Experment_num;i++){
			fprintf(fpWrite,"%d\t",later_out_time_encrypt_num[j][i]);
			if((i+1)%10==0)fprintf(fpWrite,"\n");
		}
		fprintf(fpWrite,"\n");
	}
	
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
