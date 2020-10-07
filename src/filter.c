#include "filter.h"


int first_filter_difference_chain(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],int diff_delta_count[4],int* appear_4_but_not_match,int* no_chain,
	int* more_chain,int* one_chain){
	int num = 0;
	int temp[4] = {0,0,0,0};
	for(int i=0;i<4;i++){//遍历differential_cipher_4_error的第一维
		for(int j=0;j<4;j++){//遍历arr_delta的第一维
			int match_num = 0;
			for(int k=0;k<4;k++){
				if(table[arr_delta[j][k]][differential_cipher_4_error[i][k]].value>=1){
					match_num++;
					//printf("match_num: %d\n",match_num);
				}
			}
			//printf("\n");
			if(match_num == 4){
				relationship_delta_difference_cipher[i][diff_delta_count[i]] = j;
				FILE *fpWrite = fopen("experiment.txt", "a+");
				fprintf(fpWrite,"diff:%d\tdelta:%d\n",i,j);
				fclose(fpWrite);
				printf("diff:%d\tdelta:%d\n",i,j);
				diff_delta_count[i]++;
				if(i==0)temp[0] = 1;
				else if(i==1)temp[1] = 1;
				else if(i==2)temp[2] = 1;
				else if(i==3)temp[3] = 1;
				//break;
			}
		}
	}
	printf("diff_delta_count:\n");
	for(int i=0;i<4;i++){
		printf("%d\n",diff_delta_count[i]);
	}
	if(diff_delta_count[0]==1&&diff_delta_count[1]==1&&diff_delta_count[2]==1&&diff_delta_count[3]==1){
		(*one_chain)++;
	}
	else if(diff_delta_count[0]>=1&&diff_delta_count[1]>=1&&diff_delta_count[2]>=1&&diff_delta_count[3]>=1){
		(*more_chain)++;
	}

	FILE *fpWrite = fopen("experiment.txt", "a+");	
	for(int i=0;i<4;i++){
		printf("i:%d\n",i);
		fprintf(fpWrite,"i:%d\n",i);
		for(int j=0;j<diff_delta_count[i];j++){
			printf("relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	printf("relationship_delta_difference_cipher:\n");
	fprintf(fpWrite,"relationship_delta_difference_cipher:\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%d,",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"%d,",relationship_delta_difference_cipher[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	int res = temp[0]+temp[1]+temp[2]+temp[3];
	printf("temp:%d\n",res);
	fprintf(fpWrite,"temp:%d\n",res);
	fclose(fpWrite);
	return res;
}

int later_filter_difference_chain(byte delta,byte differential_cipher_4_error[4][4],byte arr_delta[4][4],
	int relationship_delta_difference_cipher[4][4],int diff_delta_count[4]){
	int num = 0;
	int temp[4] = {0,0,0,0};
	for(int i=0;i<4;i++){//遍历differential_cipher_4_error的第一维
		for(int j=0;j<4;j++){//遍历arr_delta的第一维
			int match_num = 0;
			for(int k=0;k<4;k++){
				if(table[arr_delta[j][k]][differential_cipher_4_error[i][k]].value>=1){
					match_num++;
					//printf("match_num: %d\n",match_num);
				}
			}
			//printf("\n");
			if(match_num == 4){
				relationship_delta_difference_cipher[i][diff_delta_count[i]] = j;
				FILE *fpWrite = fopen("experiment.txt", "a+");
				fprintf(fpWrite,"diff:%d\tdelta:%d\n",i,j);
				fclose(fpWrite);
				printf("diff:%d\tdelta:%d\n",i,j);
				diff_delta_count[i]++;
				if(i==0)temp[0] = 1;
				else if(i==1)temp[1] = 1;
				else if(i==2)temp[2] = 1;
				else if(i==3)temp[3] = 1;
				//break;
			}
		}
	}
	FILE *fpWrite = fopen("experiment.txt", "a+");
	for(int i=0;i<4;i++){
		printf("i:%d\n",i);
		fprintf(fpWrite,"i:%d\n",i);
		for(int j=0;j<diff_delta_count[i];j++){
			printf("relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"relationship_delta_difference_cipher:%d\n",relationship_delta_difference_cipher[i][j]);
		}
	}
	printf("\n");
	fprintf(fpWrite,"\n");
	printf("relationship_delta_difference_cipher:\n");
	fprintf(fpWrite,"relationship_delta_difference_cipher:\n");
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			printf("%d,",relationship_delta_difference_cipher[i][j]);
			fprintf(fpWrite,"%d,",relationship_delta_difference_cipher[i][j]);
		}
		printf("\n");
		fprintf(fpWrite,"\n");
	}
	int res = temp[0]+temp[1]+temp[2]+temp[3];
	printf("temp:%d\n",res);
	fprintf(fpWrite,"temp:%d\n",res);
	fclose(fpWrite);
	return res;
}
