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
	
	printf("my pid %d\n",current->pid);
	
	return 0;
}
