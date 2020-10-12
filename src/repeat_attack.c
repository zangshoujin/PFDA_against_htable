<<<<<<< HEAD
#include "repeat_attack.h"
#include "recovery.h"
typedef unsigned char byte;

int repeat_attack(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,int* appear_4_but_not_match,int* no_chain_num,int* more_chain_num,int* one_chain_num,
    int all_encrypt_num[Experment_num],int later_encrypt_num[attack_round][Experment_num],byte w[176],int e,int* success_num,int* fail_num,int* timeout_num,
    int* other_fail_num,int* success_num_in_timeout,int* fail_num_in_timeout,int* timeout_in_timeout,byte *plain_verify,int i){
        byte delta = 0;
        byte differential_cipher_4_error[4][4]={0};
        struct Different_Cipher dc[4];
        int relationship_delta_difference_cipher[4][4] = {{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1}};//记录一组差分值对应第几组delta
        int diff_delta_count[4]={0,0,0,0};//记录一组差分值能够匹配几组delta
        byte cipher_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
        // later_out_time_encrypt_num[e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
        //     relationship_delta_difference_cipher,diff_delta_count,appear_4_but_not_match,no_chain_num,more_chain_num,
        //     one_chain_num,cipher_verify);
        later_encrypt_num[i][e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
                relationship_delta_difference_cipher,diff_delta_count,appear_4_but_not_match,no_chain_num,more_chain_num,
                one_chain_num,cipher_verify,plain_verify);
        all_encrypt_num[e] += later_encrypt_num[i][e];
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
        return recovery_10round_key(delta,differential_cipher_4_error,arr_delta,relationship_delta_difference_cipher,dc,
            guess_key_10round,key_10round,w,diff_delta_count,success_num,fail_num,cipher_verify,plain_verify,n,nt,base,key,
            timeout_num,other_fail_num,success_num_in_timeout,fail_num_in_timeout,timeout_in_timeout);
=======
#include "repeat_attack.h"
#include "recovery.h"
typedef unsigned char byte;

int repeat_attack(byte in[16],byte out[16],byte key[16],byte outex[16],int n,int nt,int base,int* appear_4_but_not_match,int* no_chain_num,int* more_chain_num,int* one_chain_num,
    int all_encrypt_num[Experment_num],int later_encrypt_num[attack_round][Experment_num],byte w[176],int e,int* success_num,int* fail_num,int* timeout_num,
    int* other_fail_num,int* success_num_in_timeout,int* fail_num_in_timeout,int* timeout_in_timeout,byte *plain_verify,int i){
        byte delta = 0;
        byte differential_cipher_4_error[4][4]={0};
        struct Different_Cipher dc[4];
        int relationship_delta_difference_cipher[4][4] = {{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1},{-1,-1,-1,-1}};//记录一组差分值对应第几组delta
        int diff_delta_count[4]={0,0,0,0};//记录一组差分值能够匹配几组delta
        byte cipher_verify[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//验证的时候使用
        // later_out_time_encrypt_num[e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
        //     relationship_delta_difference_cipher,diff_delta_count,appear_4_but_not_match,no_chain_num,more_chain_num,
        //     one_chain_num,cipher_verify);
        later_encrypt_num[i][e] = encrypt_find_different(in,out,key,outex,n,nt,base,&delta,differential_cipher_4_error,dc,
                relationship_delta_difference_cipher,diff_delta_count,appear_4_but_not_match,no_chain_num,more_chain_num,
                one_chain_num,cipher_verify,plain_verify);
        all_encrypt_num[e] += later_encrypt_num[i][e];
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
        return recovery_10round_key(delta,differential_cipher_4_error,arr_delta,relationship_delta_difference_cipher,dc,
            guess_key_10round,key_10round,w,diff_delta_count,success_num,fail_num,cipher_verify,plain_verify,n,nt,base,key,
            timeout_num,other_fail_num,success_num_in_timeout,fail_num_in_timeout,timeout_in_timeout);
>>>>>>> 5ecc1506ac1b2d8658c0e0d7caad6cb613c4a7c7
}