<<<<<<< HEAD
#include "encrypt.h"
#include "print.h"
int random_plain(byte in[16]){
	srand((unsigned)time(NULL) + rand());
	//模拟每次攻击使用随机明文
	for (int i = 0; i < 16; i++) {
		in[i] = 0 + rand() % (256 - 0);
	}
	// printf("\n随机明文是\n");
	// FILE *fpWrite = fopen("experiment.txt", "a+");
	// fpWrite = fopen("experiment.txt", "a+");
	// fprintf(fpWrite,"\n随机明文是\n");
	// fclose(fpWrite);
	// print_4_by_4(in);
	return 0;
}

int encrypt_find_different(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,byte* delta,
	byte differential_cipher_4_error[4][4],struct Different_Cipher dc[4],int relationship_delta_difference_cipher[4][4],
	int diff_delta_count[4],int* appear_4_but_not_match,int* no_chain,int* more_chain,int* one_chain,byte cipher_verify[16],
	byte plain_verify[16]){//第九轮出错导致密文四个字节不同的差分数组

	bool collect_one_error = false;//是否收集到一个错误的情况，即收集到第十轮出错的情况,记得改成false
	bool collect_cipher_done = false;//如果找到16个字节都出错，并且也找到第十轮出错（只有一个字节出错）的情况，如果找到了就停止加密
	bool collect_four_done = false;
	int error_local[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//记录错误的位置用
	int differential_cipher_4_error_count = 0;//是否已经找到了四对四个字节不同的密文对，取值范围0-3，大于4就break
	int cipher_verify_flag = 0;
	int current_cipher_number = 0;
	for(;current_cipher_number<Cipher_num;current_cipher_number++){
		random_plain(in);
		FILE *fpWrite ;
		byte out_no_error[16];
		byte out_error[16];
		if(Is_print){
			fpWrite= fopen("encrypt_state.txt", "a+");
			fprintf(fpWrite,"第%d次加密状态矩阵:--share----------\n",current_cipher_number);
			fclose(fpWrite);
			run_aes_share_print(in,out,key,outex,n,&subbyte_htable,nt,base);
			for(int i=0;i<16;i++){
				out_error[i] = out[i];
			}
			run_aes_share_no_error_print(in,out,key,outex,n,&subbyte_htable_no_error,nt,base);
			for(int i=0;i<16;i++){
				out_no_error[i] = out[i];
			}
		}
		else if(!Is_print){
			run_aes_share(in,out,key,outex,n,&subbyte_htable,nt,base); 
			for(int i=0;i<16;i++){
				out_error[i] = out[i];
			}
			run_aes_share_no_error(in,out,key,outex,n,&subbyte_htable_no_error,nt,base); 
			for(int i=0;i<16;i++){
				out_no_error[i] = out[i];
			}
		}
		int different_local[4] = {0,0,0,0};
		int different_count = 0;
		for(int k=0;k<16;k++){
			if(out_error[k] != out_no_error[k]){
				if(different_count>=4){//记住这个地方的bug！！第三次bug了
					different_count++;
					break;
				}
				different_local[different_count] = k;
				different_count++;
			}
		}
		if(different_count == 0 && !cipher_verify_flag){//记录plain,cipher_verify，用于验证
			cipher_verify_flag = true;
			printf("第%d次加密的密文相等\n\n",current_cipher_number);
			FILE *fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"第%d次加密的密文相等\n\n",current_cipher_number);
			fclose(fpWrite);
			for(int i=0;i<16;i++){
				plain_verify[i] = in[i];
			}
			for(int i=0;i<16;i++){
				cipher_verify[i] = out[i];
			}
		}
		else if((different_count == 1) && !collect_one_error){//第十轮出错，只有一个字节不同，计算德尔塔用
			collect_one_error = true;
			*delta = out_error[different_local[0]] ^ out_no_error[different_local[0]];
			FILE *fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			fclose(fpWrite);
			printf("第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			printf("本次加密的明文是：\n");
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"本次加密的明文是：\n");
			fclose(fpWrite);
			print_4_by_4(in);
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"加密的结果是：\n");
			fclose(fpWrite);
			printf("加密的结果是：\n");
			print_4_by_4(out_error);
			print_4_by_4(out_no_error);
		}
		else if(different_count == 4 && (!error_local[different_local[0]] || !error_local[different_local[1]] || 
			!error_local[different_local[2]] || !error_local[different_local[3]]) && !collect_four_done){//第九轮出错，导致密文四个字节不同

			if(!((different_local[0]==0&&different_local[1]==7&&different_local[2]==10&&different_local[3]==13)||
				(different_local[0]==1&&different_local[1]==4&&different_local[2]==11&&different_local[3]==14)||
				(different_local[0]==2&&different_local[1]==5&&different_local[2]==8&&different_local[3]==15)||
				(different_local[0]==3&&different_local[1]==6&&different_local[2]==9&&different_local[3]==12)))
				continue;//把那些错误位置不是0，7，10，13；1，4，11，14；2，5，8，15；3，6，9，12的排除
			
			FILE *fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			fclose(fpWrite);
			printf("第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			printf("本次加密的明文是：\n");
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"本次加密的明文是：\n");
			fclose(fpWrite);
			print_4_by_4(in);
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"加密的结果是：\n");
			fclose(fpWrite);
			printf("加密的结果是：\n");
			print_4_by_4(out_error);
			print_4_by_4(out_no_error);
			
			for(int q=0;q<4;q++){
				error_local[different_local[q]] = 1;//将本次四个错误字节位置存起来
				dc[differential_cipher_4_error_count].diff_local[q] = different_local[q];//将两条四个字节不同的密文的不同位置存储起来
				differential_cipher_4_error[differential_cipher_4_error_count][q] = out_error[different_local[q]] ^
					out_no_error[different_local[q]];//计算四个字节的差分
				//printf("差分：%02x\n",differential_cipher_4_error[differential_cipher_4_error_count][n]);
			}
			for(int y=0;y<16;y++){//将两条只有四个字节不同的密文存储起来
				dc[differential_cipher_4_error_count].diff_cipher[0][y] = out_error[y];
				dc[differential_cipher_4_error_count].diff_cipher[1][y] = out_no_error[y];
			}
			printf("此时different_local: ");
			printf("%d %d %d %d\n",different_local[0],different_local[1],different_local[2],different_local[3]);
			printf("error_local:\n");
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"此时different_local: ");
			fprintf(fpWrite,"%d %d %d %d\n",different_local[0],different_local[1],different_local[2],different_local[3]);
			fprintf(fpWrite,"error_local:\n");
			fclose(fpWrite);
			print_4_by_4_int(error_local);
			differential_cipher_4_error_count++;
			if(differential_cipher_4_error_count>=4)collect_four_done = true;//!!!!!!!
		}
		else{
			//printf("既不是一个字节不同，也不是4个字节不同\n");
		}
		int sum = 0;
		for(int k=0;k<16;k++){//如果16个字节都找到了，那就停止加密
			sum += error_local[k];
		}
		if((sum == 16) && collect_one_error && cipher_verify_flag && collect_four_done){
			collect_cipher_done = true;
			fpWrite = fopen("experiment.txt", "a+");
			printf("收集密文暂时结束！一共加密%d次\n",current_cipher_number);
			fprintf(fpWrite,"收集密文暂时结束！一共加密%d次\n",current_cipher_number);
			fclose(fpWrite);
			break;
		}
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("四个字节的差分：\n");
	fprintf(fpWrite,"四个字节的差分：\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%02x ",differential_cipher_4_error[i][j]);
			fprintf(fpWrite,"%02x ",differential_cipher_4_error[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
	byte delta_value = *delta;
	byte delta2 = mult(2 , delta_value);
	byte delta3 = mult(3 , delta_value);
	byte arr_delta[4][4] = {{delta2,delta3,delta_value,delta_value},{delta_value,delta2,delta3,delta_value},
		{delta_value,delta_value,delta2,delta3},{delta3,delta_value,delta_value,delta2}};
	fpWrite = fopen("experiment.txt", "a+");
	printf("delta:0x%02x\t2*delta:0x%02x\t3*delta:0x%02x\n",delta_value,delta2,delta3);
	fprintf(fpWrite,"delta:0x%02x\t2*delta:0x%02x\t3*delta:0x%02x\n",delta_value,delta2,delta3);
	fclose(fpWrite);
	int return_num = first_filter_difference_chain(delta_value,differential_cipher_4_error,arr_delta,
	relationship_delta_difference_cipher,diff_delta_count,appear_4_but_not_match,no_chain,more_chain,one_chain);
	fpWrite = fopen("experiment.txt", "a+");
	printf("第一次过滤返回值：%d\n",return_num);
	fprintf(fpWrite,"第一次过滤返回值：%d\n",return_num);
	fclose(fpWrite);



	int no_chain_flag = 0;
	while(return_num <4){
		no_chain_flag = 1;
		for(int rddc=0;rddc<4;rddc++){
			if(relationship_delta_difference_cipher[rddc][0]== -1){
				fpWrite = fopen("experiment.txt", "a+");
				printf("继续找：\n");
				fprintf(fpWrite,"继续找：\n");
				fclose(fpWrite);	
				for(int h=0;h<4;h++){
					diff_delta_count[h] = 0;
				}
				for(;current_cipher_number<Cipher_num;current_cipher_number++){
					random_plain(in);
					FILE *fpWrite ;
					byte out_no_error[16];
					byte out_error[16];
					if(Is_print){
						fpWrite= fopen("encrypt_state.txt", "a+");
						fprintf(fpWrite,"第%d次加密状态矩阵:--share----------\n",current_cipher_number);
						fclose(fpWrite);
						run_aes_share_print(in,out,key,outex,n,&subbyte_htable,nt,base);
						for(int i=0;i<16;i++){
							out_error[i] = out[i];
						}
						run_aes_share_no_error_print(in,out,key,outex,n,&subbyte_htable_no_error,nt,base);
						for(int i=0;i<16;i++){
							out_no_error[i] = out[i];
						}
					}
					else if(!Is_print){
						run_aes_share(in,out,key,outex,n,&subbyte_htable,nt,base); 
						for(int i=0;i<16;i++){
							out_error[i] = out[i];
						}
						run_aes_share_no_error(in,out,key,outex,n,&subbyte_htable_no_error,nt,base); 
						for(int i=0;i<16;i++){
							out_no_error[i] = out[i];
						}
					}
					int different_local[4] = {0,0,0,0};
					int different_count = 0;
					for(int k=0;k<16;k++){
						if(out_error[k] != out_no_error[k]){
							if(different_count>=4){//记住这个地方的bug！！第三次bug了
								different_count++;
								break;
							}
							different_local[different_count] = k;
							different_count++;
						}
					}
					if(different_count == 4 && dc[rddc].diff_local[0] == different_local[0] && dc[rddc].diff_local[1] == different_local[1] &&
							dc[rddc].diff_local[2] == different_local[2] && dc[rddc].diff_local[3] == different_local[3]){

						if(!((different_local[0]==0&&different_local[1]==7&&different_local[2]==10&&different_local[3]==13)||
							(different_local[0]==1&&different_local[1]==4&&different_local[2]==11&&different_local[3]==14)||
							(different_local[0]==2&&different_local[1]==5&&different_local[2]==8&&different_local[3]==15)||
							(different_local[0]==3&&different_local[1]==6&&different_local[2]==9&&different_local[3]==12)))
							continue;//把那些错误位置不是0，7，10，13；1，4，11，14；2，5，8，15；3，6，9，12的排除
						
						fpWrite = fopen("experiment.txt", "a+");
						fprintf(fpWrite,"第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
						fclose(fpWrite);
						printf("第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
						printf("本次加密的明文是：\n");
						fpWrite = fopen("experiment.txt", "a+");
						fprintf(fpWrite,"本次加密的明文是：\n");
						fclose(fpWrite);
						print_4_by_4(in);
						fpWrite = fopen("experiment.txt", "a+");
						fprintf(fpWrite,"加密的结果是：\n");
						fclose(fpWrite);
						printf("加密的结果是：\n");
						print_4_by_4(out_error);
						print_4_by_4(out_no_error);
							
						for(int q=0;q<4;q++){
							error_local[different_local[q]] = 1;//将本次四个错误字节位置存起来
							dc[rddc].diff_local[q] = different_local[q];//将两条四个字节不同的密文的不同位置存储起来
							differential_cipher_4_error[rddc][q] = out_error[different_local[q]] ^
								out_no_error[different_local[q]];//计算四个字节的差分
							//printf("差分：%02x\n",differential_cipher_4_error[rddc][n]);
						}
						for(int y=0;y<16;y++){//将两条只有四个字节不同的密文存储起来
							dc[rddc].diff_cipher[0][y] = out_error[y];
							dc[rddc].diff_cipher[1][y] = out_no_error[y];
						}
						break;
					}
				}
			}
		}
		return_num = later_filter_difference_chain(delta_value,differential_cipher_4_error,arr_delta,
		relationship_delta_difference_cipher,diff_delta_count);
		fpWrite = fopen("experiment.txt", "a+");
		printf("第二次过滤返回值：%d",return_num);
		fprintf(fpWrite,"第二次过滤返回值：%d",return_num);
		fclose(fpWrite);
	}
	if(no_chain_flag==1)(*no_chain)++;
	fpWrite = fopen("experiment.txt", "a+");
	printf("last四个字节的差分：\n");
	fprintf(fpWrite,"last四个字节的差分：\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%02x ",differential_cipher_4_error[i][j]);
			fprintf(fpWrite,"%02x ",differential_cipher_4_error[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	printf("收集密文最终结束！一共加密%d次\n\n",current_cipher_number);
	fprintf(fpWrite,"收集密文最终结束！一共加密%d次\n\n",current_cipher_number);
	fclose(fpWrite);
	
	return current_cipher_number;//返回加密次数
}
=======
#include "encrypt.h"
#include "print.h"
int random_plain(byte in[16]){
	srand((unsigned)time(NULL) + rand());
	//模拟每次攻击使用随机明文
	for (int i = 0; i < 16; i++) {
		in[i] = 0 + rand() % (256 - 0);
	}
	// printf("\n随机明文是\n");
	// FILE *fpWrite = fopen("experiment.txt", "a+");
	// fpWrite = fopen("experiment.txt", "a+");
	// fprintf(fpWrite,"\n随机明文是\n");
	// fclose(fpWrite);
	// print_4_by_4(in);
	return 0;
}

int encrypt_find_different(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,byte* delta,
	byte differential_cipher_4_error[4][4],struct Different_Cipher dc[4],int relationship_delta_difference_cipher[4][4],
	int diff_delta_count[4],int* appear_4_but_not_match,int* no_chain,int* more_chain,int* one_chain,byte cipher_verify[16],
	byte plain_verify[16]){//第九轮出错导致密文四个字节不同的差分数组

	bool collect_one_error = false;//是否收集到一个错误的情况，即收集到第十轮出错的情况,记得改成false
	bool collect_cipher_done = false;//如果找到16个字节都出错，并且也找到第十轮出错（只有一个字节出错）的情况，如果找到了就停止加密
	bool collect_four_done = false;
	int error_local[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//记录错误的位置用
	int differential_cipher_4_error_count = 0;//是否已经找到了四对四个字节不同的密文对，取值范围0-3，大于4就break
	int cipher_verify_flag = 0;
	int current_cipher_number = 0;
	for(;current_cipher_number<Cipher_num;current_cipher_number++){
		random_plain(in);
		FILE *fpWrite ;
		byte out_no_error[16];
		byte out_error[16];
		if(Is_print){
			fpWrite= fopen("encrypt_state.txt", "a+");
			fprintf(fpWrite,"第%d次加密状态矩阵:--share----------\n",current_cipher_number);
			fclose(fpWrite);
			run_aes_share_print(in,out,key,outex,n,&subbyte_htable,nt,base);
			for(int i=0;i<16;i++){
				out_error[i] = out[i];
			}
			run_aes_share_print(in,out,key,outex,n,&subbyte_htable_no_error,nt,base);
			for(int i=0;i<16;i++){
				out_no_error[i] = out[i];
			}
		}
		else if(!Is_print){
			run_aes_share(in,out,key,outex,n,&subbyte_htable,nt,base); 
			for(int i=0;i<16;i++){
				out_error[i] = out[i];
			}
			run_aes_share(in,out,key,outex,n,&subbyte_htable_no_error,nt,base); 
			for(int i=0;i<16;i++){
				out_no_error[i] = out[i];
			}
		}
		int different_local[4] = {0,0,0,0};
		int different_count = 0;
		for(int k=0;k<16;k++){
			if(out_error[k] != out_no_error[k]){
				if(different_count>=4){//记住这个地方的bug！！第三次bug了
					different_count++;
					break;
				}
				different_local[different_count] = k;
				different_count++;
			}
		}
		if(different_count == 0 && !cipher_verify_flag){//记录plain,cipher_verify，用于验证
			cipher_verify_flag = true;
			printf("第%d次加密的密文相等\n\n",current_cipher_number);
			FILE *fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"第%d次加密的密文相等\n\n",current_cipher_number);
			fclose(fpWrite);
			for(int i=0;i<16;i++){
				plain_verify[i] = in[i];
			}
			for(int i=0;i<16;i++){
				cipher_verify[i] = out[i];
			}
		}
		else if((different_count == 1) && !collect_one_error){//第十轮出错，只有一个字节不同，计算德尔塔用
			collect_one_error = true;
			*delta = out_error[different_local[0]] ^ out_no_error[different_local[0]];
			FILE *fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			fclose(fpWrite);
			printf("第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			printf("本次加密的明文是：\n");
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"本次加密的明文是：\n");
			fclose(fpWrite);
			print_4_by_4(in);
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"加密的结果是：\n");
			fclose(fpWrite);
			printf("加密的结果是：\n");
			print_4_by_4(out_error);
			print_4_by_4(out_no_error);
		}
		else if(different_count == 4 && (!error_local[different_local[0]] || !error_local[different_local[1]] || 
			!error_local[different_local[2]] || !error_local[different_local[3]]) && !collect_four_done){//第九轮出错，导致密文四个字节不同

			if(!((different_local[0]==0&&different_local[1]==7&&different_local[2]==10&&different_local[3]==13)||
				(different_local[0]==1&&different_local[1]==4&&different_local[2]==11&&different_local[3]==14)||
				(different_local[0]==2&&different_local[1]==5&&different_local[2]==8&&different_local[3]==15)||
				(different_local[0]==3&&different_local[1]==6&&different_local[2]==9&&different_local[3]==12)))
				continue;//把那些错误位置不是0，7，10，13；1，4，11，14；2，5，8，15；3，6，9，12的排除
			
			FILE *fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			fclose(fpWrite);
			printf("第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
			printf("本次加密的明文是：\n");
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"本次加密的明文是：\n");
			fclose(fpWrite);
			print_4_by_4(in);
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"加密的结果是：\n");
			fclose(fpWrite);
			printf("加密的结果是：\n");
			print_4_by_4(out_error);
			print_4_by_4(out_no_error);
			
			for(int q=0;q<4;q++){
				error_local[different_local[q]] = 1;//将本次四个错误字节位置存起来
				dc[differential_cipher_4_error_count].diff_local[q] = different_local[q];//将两条四个字节不同的密文的不同位置存储起来
				differential_cipher_4_error[differential_cipher_4_error_count][q] = out_error[different_local[q]] ^
					out_no_error[different_local[q]];//计算四个字节的差分
				//printf("差分：%02x\n",differential_cipher_4_error[differential_cipher_4_error_count][n]);
			}
			for(int y=0;y<16;y++){//将两条只有四个字节不同的密文存储起来
				dc[differential_cipher_4_error_count].diff_cipher[0][y] = out_error[y];
				dc[differential_cipher_4_error_count].diff_cipher[1][y] = out_no_error[y];
			}
			printf("此时different_local: ");
			printf("%d %d %d %d\n",different_local[0],different_local[1],different_local[2],different_local[3]);
			printf("error_local:\n");
			fpWrite = fopen("experiment.txt", "a+");
			fprintf(fpWrite,"此时different_local: ");
			fprintf(fpWrite,"%d %d %d %d\n",different_local[0],different_local[1],different_local[2],different_local[3]);
			fprintf(fpWrite,"error_local:\n");
			fclose(fpWrite);
			print_4_by_4_int(error_local);
			differential_cipher_4_error_count++;
			if(differential_cipher_4_error_count>=4)collect_four_done = true;//!!!!!!!
		}
		else{
			//printf("既不是一个字节不同，也不是4个字节不同\n");
		}
		int sum = 0;
		for(int k=0;k<16;k++){//如果16个字节都找到了，那就停止加密
			sum += error_local[k];
		}
		if((sum == 16) && collect_one_error && cipher_verify_flag && collect_four_done){
			collect_cipher_done = true;
			fpWrite = fopen("experiment.txt", "a+");
			printf("收集密文暂时结束！一共加密%d次\n",current_cipher_number);
			fprintf(fpWrite,"收集密文暂时结束！一共加密%d次\n",current_cipher_number);
			fclose(fpWrite);
			break;
		}
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	printf("四个字节的差分：\n");
	fprintf(fpWrite,"四个字节的差分：\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%02x ",differential_cipher_4_error[i][j]);
			fprintf(fpWrite,"%02x ",differential_cipher_4_error[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	fclose(fpWrite);
	byte delta_value = *delta;
	byte delta2 = mult(2 , delta_value);
	byte delta3 = mult(3 , delta_value);
	byte arr_delta[4][4] = {{delta2,delta3,delta_value,delta_value},{delta_value,delta2,delta3,delta_value},
		{delta_value,delta_value,delta2,delta3},{delta3,delta_value,delta_value,delta2}};
	fpWrite = fopen("experiment.txt", "a+");
	printf("delta:0x%02x\t2*delta:0x%02x\t3*delta:0x%02x\n",delta_value,delta2,delta3);
	fprintf(fpWrite,"delta:0x%02x\t2*delta:0x%02x\t3*delta:0x%02x\n",delta_value,delta2,delta3);
	fclose(fpWrite);
	int return_num = first_filter_difference_chain(delta_value,differential_cipher_4_error,arr_delta,
	relationship_delta_difference_cipher,diff_delta_count,appear_4_but_not_match,no_chain,more_chain,one_chain);
	fpWrite = fopen("experiment.txt", "a+");
	printf("第一次过滤返回值：%d\n",return_num);
	fprintf(fpWrite,"第一次过滤返回值：%d\n",return_num);
	fclose(fpWrite);



	int no_chain_flag = 0;
	while(return_num <4){
		no_chain_flag = 1;
		for(int rddc=0;rddc<4;rddc++){
			if(relationship_delta_difference_cipher[rddc][0]== -1){
				fpWrite = fopen("experiment.txt", "a+");
				printf("继续找：\n");
				fprintf(fpWrite,"继续找：\n");
				fclose(fpWrite);	
				for(int h=0;h<4;h++){
					diff_delta_count[h] = 0;
				}
				for(;current_cipher_number<Cipher_num;current_cipher_number++){
					random_plain(in);
					FILE *fpWrite ;
					byte out_no_error[16];
					byte out_error[16];
					if(Is_print){
						fpWrite= fopen("encrypt_state.txt", "a+");
						fprintf(fpWrite,"第%d次加密状态矩阵:--share----------\n",current_cipher_number);
						fclose(fpWrite);
						run_aes_share_print(in,out,key,outex,n,&subbyte_htable,nt,base);
						for(int i=0;i<16;i++){
							out_error[i] = out[i];
						}
						run_aes_share_print(in,out,key,outex,n,&subbyte_htable_no_error,nt,base);
						for(int i=0;i<16;i++){
							out_no_error[i] = out[i];
						}
					}
					else if(!Is_print){
						run_aes_share(in,out,key,outex,n,&subbyte_htable,nt,base); 
						for(int i=0;i<16;i++){
							out_error[i] = out[i];
						}
						run_aes_share(in,out,key,outex,n,&subbyte_htable_no_error,nt,base); 
						for(int i=0;i<16;i++){
							out_no_error[i] = out[i];
						}
					}
					int different_local[4] = {0,0,0,0};
					int different_count = 0;
					for(int k=0;k<16;k++){
						if(out_error[k] != out_no_error[k]){
							if(different_count>=4){//记住这个地方的bug！！第三次bug了
								different_count++;
								break;
							}
							different_local[different_count] = k;
							different_count++;
						}
					}
					if(different_count == 4 && dc[rddc].diff_local[0] == different_local[0] && dc[rddc].diff_local[1] == different_local[1] &&
							dc[rddc].diff_local[2] == different_local[2] && dc[rddc].diff_local[3] == different_local[3]){

						if(!((different_local[0]==0&&different_local[1]==7&&different_local[2]==10&&different_local[3]==13)||
							(different_local[0]==1&&different_local[1]==4&&different_local[2]==11&&different_local[3]==14)||
							(different_local[0]==2&&different_local[1]==5&&different_local[2]==8&&different_local[3]==15)||
							(different_local[0]==3&&different_local[1]==6&&different_local[2]==9&&different_local[3]==12)))
							continue;//把那些错误位置不是0，7，10，13；1，4，11，14；2，5，8，15；3，6，9，12的排除
						
						fpWrite = fopen("experiment.txt", "a+");
						fprintf(fpWrite,"第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
						fclose(fpWrite);
						printf("第%d次加密有%d字节不同!\n",current_cipher_number,different_count);
						printf("本次加密的明文是：\n");
						fpWrite = fopen("experiment.txt", "a+");
						fprintf(fpWrite,"本次加密的明文是：\n");
						fclose(fpWrite);
						print_4_by_4(in);
						fpWrite = fopen("experiment.txt", "a+");
						fprintf(fpWrite,"加密的结果是：\n");
						fclose(fpWrite);
						printf("加密的结果是：\n");
						print_4_by_4(out_error);
						print_4_by_4(out_no_error);
							
						for(int q=0;q<4;q++){
							error_local[different_local[q]] = 1;//将本次四个错误字节位置存起来
							dc[rddc].diff_local[q] = different_local[q];//将两条四个字节不同的密文的不同位置存储起来
							differential_cipher_4_error[rddc][q] = out_error[different_local[q]] ^
								out_no_error[different_local[q]];//计算四个字节的差分
							//printf("差分：%02x\n",differential_cipher_4_error[rddc][n]);
						}
						for(int y=0;y<16;y++){//将两条只有四个字节不同的密文存储起来
							dc[rddc].diff_cipher[0][y] = out_error[y];
							dc[rddc].diff_cipher[1][y] = out_no_error[y];
						}
						break;
					}
				}
			}
		}
		return_num = later_filter_difference_chain(delta_value,differential_cipher_4_error,arr_delta,
		relationship_delta_difference_cipher,diff_delta_count);
		fpWrite = fopen("experiment.txt", "a+");
		printf("第二次过滤返回值：%d",return_num);
		fprintf(fpWrite,"第二次过滤返回值：%d",return_num);
		fclose(fpWrite);
	}
	if(no_chain_flag==1)(*no_chain)++;
	fpWrite = fopen("experiment.txt", "a+");
	printf("last四个字节的差分：\n");
	fprintf(fpWrite,"last四个字节的差分：\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%02x ",differential_cipher_4_error[i][j]);
			fprintf(fpWrite,"%02x ",differential_cipher_4_error[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	printf("收集密文最终结束！一共加密%d次\n\n",current_cipher_number);
	fprintf(fpWrite,"收集密文最终结束！一共加密%d次\n\n",current_cipher_number);
	fclose(fpWrite);
	
	return current_cipher_number;//返回加密次数
}
>>>>>>> 5ecc1506ac1b2d8658c0e0d7caad6cb613c4a7c7
