obj-m += sysmon.o
obj-m += sysmon_uid.o
obj-m += sysmon_toggle.o
obj-m += sysmon_log.o

KVERSION = $(shell uname -r)

all: sysmon.o sysmon_uid.o sysmon_toggle.o sysmon_log.o systest part3 part3_off

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

sysmon.o: sysmon.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

sysmon_uid.o: sysmon_uid.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

sysmon_toggle.o: sysmon_toggle.c sysmon.h
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

sysmon_log.o: sysmon_log.c sysmon.h
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

systest: systest.c
	gcc -o systest systest.c

part3: part3.c
	gcc -o part3 part3.c

part3_off: part3_off.c
	gcc -o part3_off part3_off.c
