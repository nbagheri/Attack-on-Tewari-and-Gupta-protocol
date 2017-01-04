// Implementation (calculation hamming wight) : Passive Secret Disclosure Attack on an Ultralightweight Authentication Protocol for Internet of Things 
// By: Nasour Bagheri (1/4/2017)

#ifndef _shift_h
#define _shift_h
#define CHAR_BIT 8


unsigned short int wt(int y)
{
	int x=0;
	for (int a = 0; a < 32; a++)
	{
		if (y % 2 != 0) x++;
		y = y >> 1;
	}
	
	return (x);
}

#endif
 
