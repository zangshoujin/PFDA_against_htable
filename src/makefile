<<<<<<< HEAD
AESOBJ = encrypt.o aes.o aes_rp.o share.o aes_share.o aes_htable.o runaes.o common.o aes_rp_prg.o prg.o prgmat.o difftribute_table.o filter.o print.o recovery.o verify.o repeat_attack.o

DESOBJ = share.o des_carlet.o des_crv.o des.o rundes.o des_htable.o des_share.o common.o

all : runaes.out

rundes.out : $(DESOBJ)
	gcc -O3 -o $@ $(DESOBJ)

runaes.out : $(AESOBJ)
	gcc -O3 -o $@ $(AESOBJ)

prg.out : prg.o share.o common.o aes.o
	gcc -O3 -o $@ prg.o share.o common.o aes.o

%.o: %.c
	gcc -O3 -o $@ -c $<

clean:
=======
AESOBJ = encrypt.o aes.o aes_rp.o share.o aes_share.o aes_htable.o runaes.o common.o aes_rp_prg.o prg.o prgmat.o difftribute_table.o filter.o print.o recovery.o verify.o repeat_attack.o

DESOBJ = share.o des_carlet.o des_crv.o des.o rundes.o des_htable.o des_share.o common.o

all : runaes.out

rundes.out : $(DESOBJ)
	gcc -O3 -o $@ $(DESOBJ)

runaes.out : $(AESOBJ)
	gcc -O3 -o $@ $(AESOBJ)

prg.out : prg.o share.o common.o aes.o
	gcc -O3 -o $@ prg.o share.o common.o aes.o

%.o: %.c
	gcc -O3 -o $@ -c $<

clean:
>>>>>>> 5ecc1506ac1b2d8658c0e0d7caad6cb613c4a7c7
	rm -f *.o *.out *.txt