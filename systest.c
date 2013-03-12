#include <stdio.h>
#include <stdlib.h>

#define FILE_PATH_UID "/proc/sysmon_uid"
#define FILE_PATH_TOGGLE "/proc/sysmon_toggle"
#define FILE_PATH_LOG "/proc/sysmon_log"


int main()
{
	FILE *file;
	char dirpath[80] = "/nethome/sliang32/cs3210-proj3/test";
	char mkcmd[80];
	char *ret[1000];	
		
	file = fopen(FILE_PATH_TOGGLE, "w");
	if(file != NULL){
		fprintf(file, "1", "1");
		fclose(file);
	}else{
		printf("sysmon_toggle not open\n");
		return 1;
	}
	
	printf("Kprobe toggled ON\n");
	file = fopen(FILE_PATH_UID, "w");
	if(file != NULL){
		fprintf(file, "396531", "396531");
		fclose(file);
	}else{
		printf("sysmon_uid not open\n");
		return 1;
	}
	printf("Set UID\n");
	
	sprintf(mkcmd, "mkdir %s", dirpath);
	system(mkcmd);

	file = fopen(FILE_PATH_LOG, "r");
	if(file != NULL){
		while(!feof(file))
		{
       			fscanf(file,"%s",ret);
			printf("%s ", ret);
		}//end while loop
		printf("\n");
		fclose(file);
	}else{
		printf("sysmon_log not open\n");
		return 1;
	}
	
	file = fopen(FILE_PATH_TOGGLE, "w");
	if(file != NULL){
		fprintf(file, "0", "0");
		fclose(file);
	}else{
		printf("sysmon_toggle not open\n");
		return 1;
	}
	
	printf("Kprobe toggled OFF\n");

	return 0;
}//end main function
