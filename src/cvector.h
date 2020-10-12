////////////cvector.h////////////////////////////////
#ifndef VECTOR_H
#define VECTOR_H
 
#include <stdlib.h>
#include <assert.h>
 
/////////结点存放自己的数据结构//////////
typedef unsigned char node;
 
typedef struct VectorSt {
	int size;
	int maxSize;
	node *data;
} *Vector;
 
 
 
Vector VectorNew(void);
void VectorPushBack(Vector v, node e);
node VectorPopBack(Vector v);
node VectorGet(Vector v, int index);
int VectorSize(Vector v);
int VectorMaxSize(Vector v);
void VectorRm(Vector v, int index);
void VectorDelete(Vector v);
 
#endif