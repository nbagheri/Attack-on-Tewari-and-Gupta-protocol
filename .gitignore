// Implementation : Passive Secret Disclosure Attack on an Ultralightweight Authentication Protocol for Internet of Things 
// By: Nasour Bagheri (1/4/2017)

#define _CRT_SECURE_NO_DEPRECATE
#include "stdafx.h"
#include "ConsoleApplication2.h"
#include "conio.h"
#include "Hwa.h"


int main()
{
    int nRetCode = 0;

    	FILE *Enc14;
	Enc14 = fopen("E:/Enc14.txt", "wb");
	if ((!Enc14))
	{
		printf("cacnot open file Enc.bin \n");
		getch();
	}
	
	
	unsigned int P, Q, R, S, n, m, IDS, K1, K2,t1,t2,b, P1, Q1, R1, S1, n1, m1, IDS1,hids,ht1,ht2,hk1,hk2;
        //******************Initialization********************
	n =0x12345678;
	m =0x9abcdef0 ;
	IDS =0x13579bdf;
	K1 =0x2468ace0;

	//********* Extracting Secret Parameters*********
	for (int a = 0; a<32; a++)
	{
		
		fprintf(Enc14, "a=%d\n", a);
		t2= (S >> a) ^ (S <<(32 - a));
		m1 = t2^IDS;
		n1 = P^m1^IDS;
		K2 = Q^n1;
		t1 = K2^m1;
		Q1 = n1^K2;
		P1 = IDS^m1^n1;
		hids = wt(IDS);
		ht1 = wt(t1);


		R1 = (Q1 << (hids)) ^ (Q1 >> (32 - (hids)));
		R1 = (R1 << (ht1)) ^ (R1 >> (32 - (ht1)));

		t2 = R1^n1;
		ht2 = wt(t2);
		b = IDS^m1;
		hk2 = wt(K2);
		S1 = (b << (hk2)) ^ (b >> (32 - hk2));

		S1 = (S1 << (ht2)) ^ (S1 >> (32 - ht2));

		if ((R1 == R)&&(S1=S))
		{
			fprintf(Enc14, "a=%d\n", a);
			fprintf(Enc14, "New      Values P1=0x%08x,Q1=0x%08x,R1=0x%08x,S1=0x%08x,n1=0x%08x,m1=0x%08x, IDS=0x%08x, K2=0x%08x\n\n\n", P1, Q1, R1, S1, n1, m1, IDS, K2);
		
  IDS1 = IDS^n;
  t1 = Q;
  ht1 = wt(t1);
  t2 = IDS^m1;
  ht2 = wt(t2);
  IDS1 = (IDS1 << (ht1)) ^ (IDS1 >> (32 - (ht1)));
  IDS1 = (IDS1 << (ht2)) ^ (IDS1 >> (32 - (ht2)));
  
  K2 = R^n;
  t2 = IDS^m1;
  ht2 = wt(t2);
  K2 = (K2 << (ht2)) ^ (K2 >> (32 - (ht2)));

  		fprintf(Enc14, "K\oplus m=0x%08x,K_new=0x%08x,IDS_new=0x%08x\n\n", (K1^ m),K2,IDS1);
}
	}

	false(Enc14);

	printf("end\n");




	return nRetCode;
}
