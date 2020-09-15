#include "recovery.h"

int recovery_10round_key(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],struct Different_Cipher dc[4],byte guess_key_10round[16][16],
	byte key_10round[16],byte w[176],int diff_delta_count[4],int* first_success_num,int* first_fail_num,byte cipher_verify[16]
	,byte in[16],int n,int nt,int base,byte reall_main_key[16],int *first_out_time_num,int *other_fail_num,int *overtime_success_num){
    
    int chain_num[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int candidiate_key_count[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	for(int i=0;i<4;i++){//遍历四对密文that有四个字节不同的
		for(int j=0;j<4;j++){//遍历每对（有四个字节不同的）密文的每一对不同字节
			int candidate_count = 0;
			for(int diff=0;diff<diff_delta_count[i];diff++){
				for(int k=0;k<16;k++){//遍历错误字节位置,即要恢复的密钥的字节位置
					if(dc[i].diff_local[j] == k && relationship_delta_difference_cipher[i][diff]!= -1){
						if(table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][differential_cipher_4_error[i][j]].value == 1){
							byte out1 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out1[0];
							printf("第十轮子密钥第%2d个字节可能是：%02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],out1 ^ dc[i].diff_cipher[1][k]);
							FILE *fpWrite = fopen("experiment.txt", "a+");
							fprintf(fpWrite,"第十轮子密钥第%2d个字节可能是：%02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],out1 ^ dc[i].diff_cipher[1][k]);
							fclose(fpWrite);

                            chain_num[k] += 2;

							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[0][k];
							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[1][k];
							candidiate_key_count[k] = candidate_count;
						}
						else if(table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][differential_cipher_4_error[i][j]].value == 2){
							byte out1 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out1[0];
							byte out2 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out2[0];
							byte out3 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out1[1];
							byte out4 = table[arr_delta[relationship_delta_difference_cipher[i][diff]][j]][(int)differential_cipher_4_error[i][j]].out2[1];
							printf("第十轮子密钥第%2d个字节可能是：%02x %02x %02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],
								out1 ^ dc[i].diff_cipher[1][k],out3 ^ dc[i].diff_cipher[0][k],out3 ^ dc[i].diff_cipher[1][k]);
							FILE *fpWrite = fopen("experiment.txt", "a+");
							fprintf(fpWrite,"第十轮子密钥第%2d个字节可能是：%02x %02x %02x %02x\n",k,out1 ^ dc[i].diff_cipher[0][k],
								out1 ^ dc[i].diff_cipher[1][k],out3 ^ dc[i].diff_cipher[0][k],out3 ^ dc[i].diff_cipher[1][k]);
							fclose(fpWrite);

                            chain_num[k] += 4;

							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[0][k];
							guess_key_10round[k][candidate_count++] = out1 ^ dc[i].diff_cipher[1][k];
							guess_key_10round[k][candidate_count++] = out3 ^ dc[i].diff_cipher[0][k];
							guess_key_10round[k][candidate_count++] = out3 ^ dc[i].diff_cipher[1][k];
							candidiate_key_count[k] = candidate_count;
						}
						else{
							printf("都不是\n");
							FILE *fpWrite = fopen("experiment.txt", "a+");
							fprintf(fpWrite,"都不是\n");
							fclose(fpWrite);
						}
						break;
					}
				}
			}
		}
	}

    long long chain_sum = 1;
    for(int i=0;i<16;i++)
        chain_sum *= chain_num[i];
    printf("\nchain_sum:%d\n",chain_sum);
    FILE *fpWrite = fopen("experiment.txt", "a+");
    fprintf(fpWrite,"\nchain_sum:%d\n",chain_sum);
    fclose(fpWrite);
	int re_vok = verify_offline_key(guess_key_10round,key_10round,w,candidiate_key_count,first_success_num,first_fail_num,cipher_verify,
	in,n,nt,base,reall_main_key,first_out_time_num,other_fail_num);

    if(re_vok == 1 && chain_sum >= OverTime_Num){
        (*overtime_success_num)++;
    }
	if(re_vok == -1)
		return -1;
	else if(re_vok == -2)
		return -2;
	else if(re_vok == -3)
		return -3;
	return 1;
}

int recovery_main_key(byte key_10round[16],byte main_key[16]){
	byte temp[4];
	byte w[176];
	byte rcon[10];
	setrcon(rcon);
	
	for(int i=0;i<16;i++)
		w[160+i]=key_10round[i];

	for(int i=156;i>=0;i-=4){
		for(int j=0;j<4;j++)
			temp[j]=w[i+12+j];
		if((i % 16)==0){
			temp[0]=subbyte(w[i+13]) ^ rcon[i/16];
			temp[1]=subbyte(w[i+14]);
			temp[2]=subbyte(w[i+15]);
			temp[3]=subbyte(w[i+12]);
		}
		for(int j=0;j<4;j++)
			w[i+j]=w[i+j+16] ^ temp[j];
	}

	for(int i=0;i<16;i++){
		main_key[i] = w[i];
	}
	// printf("求得初始密钥是：\n");	
	// for(int i=0;i<16;i++){
	// 	printf("%02x,",w[i]);
	// 	if((i+1)%4==0)printf("\n");
	// }
	return 0;
}
