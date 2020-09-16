#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include "aes.h"
#include "aes_rp.h"
#include "aes_rp_prg.h"
#include "share.h"
#include "aes_share.h"
#include "aes_htable.h"
#include "common.h"
#include "prg.h"
#include "cvector.h"
#include "time.h"
#include "difftribute_table.h"
#include "filter.h"
#include "verify.h"
#include "recovery.h"
#include "print.h"
#include "encrypt.h"


int random_key(byte in[16],byte out[16],byte key[16],byte outex[16],int nt,byte w[176]){
	//随机注入错误
	srand((unsigned)time(NULL) + rand());
	byte loc = 0 + rand() % (256 - 0); 
	byte value = 1 + rand() % (256 - 1); 
	byte rel_value = get_sbox_value(loc);
	set_sbox_value(loc, value);
	printf("注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,sbox_no_error[loc]);
	FILE *fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,sbox_no_error[loc]);
	fclose(fpWrite);
	if(value == rel_value){
		return -1;
	}
	//模拟每次攻击使用随机主密钥
	for (int i = 0; i < 16; i++) {
		key[i] = 0 + rand() % (256 - 0);
	}
	printf("\n随机密钥是：\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"\n随机密钥是：\n");
	fclose(fpWrite);
	print_4_by_4(key);
	printf("\n子密钥是：\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"\n子密钥是：\n");
	fclose(fpWrite);
	print_round_key(in,out,key,outex,nt,1,w);
	printf("\n子密钥结束\n\n");
	fpWrite = fopen("experiment.txt", "a+");
	fprintf(fpWrite,"\n子密钥结束\n\n");
	fclose(fpWrite);
	return 0;
}

int main(){
	clock_t start,middle1,middle2,finish;
   	double duration;
	start = clock();
  	int n=Share_num;//share的个数
	int base = 1;
  	int nt = 10;
	diff_table();
	int all_encrypt_num[Experment_num] = {0,0,0,0,0,0,0,0,0,0};
	int first_encrypt_num[Experment_num] = {0,0,0,0,0,0,0,0,0,0};
	int second_fail_encrypt_num[Experment_num] = {0,0,0,0,0,0,0,0,0,0};
	int second_out_time_encrypt_num[Experment_num] = {0,0,0,0,0,0,0,0,0,0};
	double excute_time[Experment_num];//每次实验的执行时间，先不统计，因为现在还涉及读写文件，会消耗大量时间
	int first_success_num = 0;//成功的次数
	int second_success_num_in_fail = 0;
	int second_success_num_in_out_time = 0;
	int first_fail_num = 0;//失败的次数
	int second_fail_num_in_fail = 0;
	int second_fail_num_in_out_time = 0;
	int other_fail_num = 0;//其他未知的失败次数
	int appear_4_but_not_match = 0;//
	int no_chain_num = 0;//找不到链的情况（继续找的情况）
	int more_chain_num = 0;//匹配多条链的情况
	int match_four_num = 0;//刚好匹配四条链的情况
	int invalid_error_num = 0;//注入无效错误的情况
	int first_out_time_num = 0;//超时的次数
	int second_out_time_num_in_fail = 0;
	int second_out_time_num_in_out_time = 0;
	int overtime_success_num = 0;//超过设定的复杂度，但是攻击成功了
	int overtime_fail_num = 0;//超过设定的复杂度，但是攻击失败
	int overtime_overtime_num = 0;//超过设定的复杂度，真的超时了
	for(int e=0;e<Experment_num;e++){
		middle1 = clock();
		FILE *fpWrite ;
		if(Is_print){
			fpWrite= fopen("encrypt_state.txt", "a+");
			fprintf(fpWrite,"第%d次实验：\n",e);
			fclose(fpWrite);
		}
		printf("\n********************************\n第%d次实验\n",e);
		fpWrite = fopen("experiment.txt", "a+");
		fprintf(fpWrite,"\n********************************\n第%d次实验\n",e);
		fclose(fpWrite);
		byte outex[16]={0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};//预测输出,已经被注释掉了，没用了
		byte in[16]={0xd7,0x82,0x0c,0x13,0x95,0x97,0x87,0x61,0xfc,0x3f,0x52,0xb2,0xcc,0xd7,0x94,0xe8};
		byte key[16]={0xd7,0x82,0x0c,0x13,0x95,0x97,0x87,0x61,0xfc,0x3f,0x52,0xb2,0xcc,0xd7,0x94,0xe8};
		byte out[16];
		byte w[176];//扩展密钥
		int invalid_error = 0;//判断是否注入了一个无效的错误
		if(Is_random == 0){//如果不随机产生密钥和错误  控制是否密钥和错误,调试用 1:表示随机 0:表示固定
			byte loc = 0xd9; //注入错误的位置
			byte value = 0x25; //注入错误的值
			byte rel_value = get_sbox_value(loc);
			set_sbox_value(loc, value);
			fpWrite = fopen("experiment.txt", "a+");
			printf("注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,sbox_no_error[loc]);
			fprintf(fpWrite,"注入错误的位置是%02x,错误值是%02x,原值是%02x\n",loc,value,sbox_no_error[loc]);
			printf("\n密钥是：\n");
			fprintf(fpWrite,"密钥是：\n");
			for(int i=0;i<16;i++){
				printf("%02x,",key[i]);
				fprintf(fpWrite,"%02x,",key[i]);
				if((i+1)%4==0){
					printf("\n");
					fprintf(fpWrite,"\n");
				}
			}
			fclose(fpWrite);
			print_round_key(in,out,key,outex,nt,base,w); //输出扩展密钥用
		}
		else if(Is_random == 1){//如果随机密钥和错误
			invalid_error = random_key(in,out,key,outex,nt,w);
		}
		if(invalid_error == -1){//如果注入了一个无效错误
			all_encrypt_num[e] = 0;
			invalid_error_num++;
			middle2 = clock();
			excute_time[e] = (double)(middle2 - middle1)/ CLOCKS_PER_SEC;
			continue;
		}
		byte delta = 0;
		byte differential_cipher_4_error[4][4]={0};
		struct Different_Cipher dc[4];
		int relationship_delta_difference_cipher[4][4] = {{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1}};//记录一组差分值对应第几组delta
		int diff_delta_count[4]={0,0,0,0};//记录一组差分值能够匹配几组delta
		byte plain_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
		byte cipher_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
		all_encrypt_num[e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
			relationship_delta_difference_cipher,diff_delta_count,&appear_4_but_not_match,&no_chain_num,&more_chain_num,
			&match_four_num,cipher_verify,plain_verify);	
		byte guess_key_10round[16][16]={{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
										{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
										{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
										{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
		byte key_10round[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的第十轮子密钥
		byte main_key[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的初始密钥
		byte delta2 = mult(2 , delta);
		byte delta3 = mult(3 , delta);
		byte arr_delta[4][4] = {{delta2,delta3,delta,delta},{delta,delta2,delta3,delta},
			{delta,delta,delta2,delta3},{delta3,delta,delta,delta2}};
		int re = recovery_10round_key(delta,differential_cipher_4_error,arr_delta,relationship_delta_difference_cipher,dc,
			guess_key_10round,key_10round,w,diff_delta_count,&first_success_num,&first_fail_num,cipher_verify,plain_verify,n,nt,base,key,
			&first_out_time_num,&other_fail_num,&overtime_success_num,&overtime_fail_num,&overtime_overtime_num);
		if(re == -1){
			byte delta = 0;
			byte differential_cipher_4_error[4][4]={0};
			struct Different_Cipher dc[4];
			int relationship_delta_difference_cipher[4][4] = {{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1}};//记录一组差分值对应第几组delta
			int diff_delta_count[4]={0,0,0,0};//记录一组差分值能够匹配几组delta
			byte plain_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
			byte cipher_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
			second_fail_encrypt_num[e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
				relationship_delta_difference_cipher,diff_delta_count,&appear_4_but_not_match,&no_chain_num,&more_chain_num,
				&match_four_num,cipher_verify,plain_verify);
			all_encrypt_num[e] += second_fail_encrypt_num[e];		
			byte guess_key_10round[16][16]={{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
											{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
											{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
											{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
			byte key_10round[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的第十轮子密钥
			byte main_key[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的初始密钥
			byte delta2 = mult(2 , delta);
			byte delta3 = mult(3 , delta);
			byte arr_delta[4][4] = {{delta2,delta3,delta,delta},{delta,delta2,delta3,delta},
				{delta,delta,delta2,delta3},{delta3,delta,delta,delta2}};
			recovery_10round_key(delta,differential_cipher_4_error,arr_delta,relationship_delta_difference_cipher,dc,
				guess_key_10round,key_10round,w,diff_delta_count,&second_success_num_in_fail,&second_fail_num_in_fail,cipher_verify,plain_verify,n,nt,base,key,
				&second_out_time_num_in_fail,&other_fail_num,&overtime_success_num,&overtime_fail_num,&overtime_overtime_num);
		}
		else if(re == -3){
			byte delta = 0;
			byte differential_cipher_4_error[4][4]={0};
			struct Different_Cipher dc[4];
			int relationship_delta_difference_cipher[4][4] = {{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1}};//记录一组差分值对应第几组delta
			int diff_delta_count[4]={0,0,0,0};//记录一组差分值能够匹配几组delta
			byte plain_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
			byte cipher_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
			second_out_time_encrypt_num[e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
				relationship_delta_difference_cipher,diff_delta_count,&appear_4_but_not_match,&no_chain_num,&more_chain_num,
				&match_four_num,cipher_verify,plain_verify);	
			all_encrypt_num[e] += second_out_time_encrypt_num[e];
			byte guess_key_10round[16][16]={{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
											{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
											{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
											{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}};
			byte key_10round[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的第十轮子密钥
			byte main_key[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//存放求得的初始密钥
			byte delta2 = mult(2 , delta);
			byte delta3 = mult(3 , delta);
			byte arr_delta[4][4] = {{delta2,delta3,delta,delta},{delta,delta2,delta3,delta},
				{delta,delta,delta2,delta3},{delta3,delta,delta,delta2}};
			recovery_10round_key(delta,differential_cipher_4_error,arr_delta,relationship_delta_difference_cipher,dc,
				guess_key_10round,key_10round,w,diff_delta_count,&second_success_num_in_out_time,&second_fail_num_in_out_time,cipher_verify,plain_verify,n,nt,base,key,
				&second_out_time_num_in_out_time,&other_fail_num,&overtime_success_num,&overtime_fail_num,&overtime_overtime_num);
		}
		
		//recovery_main_key(key_10round,main_key);
		for(int i=0;i<256;i++){	
			sbox[i] = sbox_no_error[i];//恢复sbox
		}
		middle2 = clock();
		excute_time[e] = (double)(middle2 - middle1)/ CLOCKS_PER_SEC;
		fpWrite = fopen("experiment.txt", "a+");

		printf("本次实验执行时间:%f\n",excute_time[e]);
		fprintf(fpWrite,"本次实验执行时间:%f\n",excute_time[e]);

		print_count(first_success_num,first_fail_num,first_out_time_num, second_success_num_in_fail, second_fail_num_in_fail,
			second_out_time_num_in_fail, second_success_num_in_out_time, second_fail_num_in_out_time,
			second_out_time_num_in_out_time, other_fail_num, no_chain_num, more_chain_num, match_four_num, invalid_error_num,
			overtime_success_num,overtime_fail_num,overtime_overtime_num);
	}
	print_encrypt_num( first_encrypt_num, all_encrypt_num, second_fail_encrypt_num, second_out_time_encrypt_num);
	int sum = 0;
	int max = 0;
	int min = 10000;
	for(int i=0;i<Experment_num;i++){
		sum += all_encrypt_num[i];
		if(all_encrypt_num[i]==0){//将无效错误的情况去掉
			continue;
		}
		if(all_encrypt_num[i]>max)
			max = all_encrypt_num[i];
		if(all_encrypt_num[i]<min)
			min = all_encrypt_num[i];
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("\n总实验次数:%d\n",Experment_num);
	fprintf(fpWrite,"\n总实验次数:%d\n",Experment_num);
	printf("share个数:%d\n",n);
	fprintf(fpWrite,"share个数:%d\n",n);
	printf("平均需要加密%d次才能找到16个字节。\n最多需要%d次，最少需要%d次。\n",sum/Experment_num,max,min);
	fprintf(fpWrite,"平均需要加密%d次才能找到16个字节。\n最多需要%d次，最少需要%d次。\n",sum/Experment_num,max,min);

	print_count(first_success_num,first_fail_num,first_out_time_num, second_success_num_in_fail, second_fail_num_in_fail,
			second_out_time_num_in_fail, second_success_num_in_out_time, second_fail_num_in_out_time,
			second_out_time_num_in_out_time, other_fail_num, no_chain_num, more_chain_num, match_four_num, invalid_error_num,
			overtime_success_num,overtime_fail_num,overtime_overtime_num);
	
	finish = clock(); 
	duration = (double)(finish - start) / CLOCKS_PER_SEC;  
	printf("总执行时间：%f seconds\n", duration ); 
	fprintf(fpWrite,"总执行时间：%f seconds\n", duration );
	fclose(fpWrite); 
	fpWrite = fopen("excute_time.txt","a+");
	printf("每次实验的执行时间:\n");
	fprintf(fpWrite,"每次实验的执行时间:\n");
	for(int i=0;i<Experment_num;i++){
		printf("%fs\n",excute_time[i]);
		fprintf(fpWrite,"%f\n",excute_time[i]);
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
	return 0;
}

/*
	byte in[16],out[16];
  	byte key[16];
  	printMes("in:",inex);
  	printMes("key:",keyex);

  	for(i=0;i<16;i++) key[i]=keyex[i];
  	for(i=0;i<16;i++) in[i]=inex[i];
  	int dt,base;
  printf("Without countermeasure, plain: \n");
  base=run_aes(&aes,in,out,key,outex,nt,0);           //运行普通的AES加密算法，返回加密10轮所用的时间，得到时间基准base 

  printf("Without countermeasure, RP: \n");
  run_aes(&aes_rp,in,out,key,outex,nt,base);          //运行AES_rp加密算法（使用有限域乘法+仿射变换代替S盒），得到时间基准base 
  printf("warning！得到时间基准base在mac上等于：%d\n",base); 


  for(n=3;n<=6;n+=1)
  {
    printf("n=%d\n",n);
    printf("With RP countermeasure: ");
    run_aes_share(in,out,key,outex,n,&subbyte_rp_share,nt,base);     //用share技术的AES加密算法 (使用有限域乘法share+仿射变换代替S盒),行移位share,列混合share，轮密钥加share,时间基准base
    
    printf("  With RP countermeasure, with flr: ");
    int rprg=rprg_flr(n);
    run_aes_share_prg(in,out,key,outex,n,&subbyte_rp_share_flr,base,nt,rprg);
    printf(" trand=%d tprgcount=%d\n",rprg*2*n,(480*n+1120)*(n-1));

//    printf("  With RP countermeasure, with ilr: ");
//    rprg=rprg_ilr(n);
//    run_aes_share_prg(in,out,key,outex,n,&subbyte_rp_share_ilr,base,nt,rprg);
//    printf(" trand=%d tprgcount=%d\n",8*n*(n-1)*(n-1),(960*n+160)*(n-1));
//
//    printf("  With RP countermeasure, with ilr2: ");
//    rprg=rprg_ilr(n);
//    run_aes_share_prg(in,out,key,outex,n,&subbyte_rp_share_ilr2,base,nt,rprg);
//    printf(" trand=%d tprgcount=%d\n",8*n*(n-1)*(n-1),(480*n+1120)*(n-1));
//
//    printf("  With RP countermeasure, with flr, multiple prg: ");
//    run_aes_share_mprg(in,out,key,outex,n,&subbyte_rp_share_flr_mprg,TFLR,base,nt);
//    printf(" trand=%d\n",(n*n+9*n-10)*(n-1));
//
//    printf("  With RP countermeasure, with ilr, multiple prg: ");
//    run_aes_share_mprg(in,out,key,outex,n,&subbyte_rp_share_ilr_mprg,TILR,base,nt);
//    printf(" trand=%d\n",(12*n-12)*(n-1));
    if(n<=4)
    {
      printf(" With RP countermeasure, with flr, mprgmat: ");
      run_aes_share_mprgmat(in,out,key,outex,n,base,nt);
      printf(" predicted rand: %d\n",n*(n-1)/2*2*31+3*(n-1)*2*38);
    }
    
    printf("  With randomized table : ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable,base,nt); 

    printf("  With randomized table inc: ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable_inc,base,nt); 

    printf("  With randomized table word: ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable_word,base,nt);

    printf("  With randomized table word inc: ");
    run_aes_share(in,out,key,outex,n,&subbyte_htable_word_inc,base,nt); 

    printf("  With randomized table common shares: ");
    run_aes_common_share(in,out,key,outex,n,&subbyte_cs_htable,base,nt); 
    
    printf("  With randomized table word common shares: ");
    run_aes_common_share(in,out,key,outex,n,&subbyte_cs_htable_word,base,nt); 

    printf("  With randomized table word inc common shares: ");
    run_aes_common_share(in,out,key,outex,n,&subbyte_cs_htable_word_inc,base,nt); 
   
  }*/


