#include <stdlib.h>
#include <stdio.h>

int main(int agrc, char *argv[]) {
	
	#ifdef FILES
		char buffer[5];
		FILE* file;
		file	= fopen("a.txt","a+");
		fread(buffer,5,1,file);
		fclose(file);
	#endif

	printf("my pid %d\n",getpid());
	write(1, "this is to 1\n", 13);
	write(2, "this is to 2\n", 13);
	
	return 0;
}
