#include <stdio.h>
#include <stdlib.h>

#define FILE_PATH_UID "/proc/sysmon_uid"
#define FILE_PATH_TOGGLE "/proc/sysmon_toggle"
#define FILE_PATH_LOG "/proc/sysmon_log"


main()
{
	FILE *file;
	char dirpath[80] = "/nethome/sliang32/cs3210-proj3/test";
	char *mkcmd[80];
	char *ret[1000];	
		
	file = fopen(FILE_PATH_UID, "w");
	fprintf(file, "396531", "396531");
	fclose file;

	file = fopen(FILE_PATH_TOGGLE, "w");
	fprintf(file, "1", "1");
	fclose file;
	
	sprintf(mkcmd, "mkdir %s", dirpath);
	system(mkcmd);

	file = fopen(FILE_PATH_LOG, "r");
	while(!feof(file))
	{
       		fscanf(file,"%s",ret);
		printf("%s ", ret);
	}//end while loop
	printf("\n");
	fclose(file);

	
}//end main function
