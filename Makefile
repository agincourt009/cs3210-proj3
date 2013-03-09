obj-m += sysmon.o
obj-m += sysmon_uid.o

KVERSION = $(shell uname -r)

all: sysmon.o sysmon_uid.o
#all: sysmon.o

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

sysmon.o: sysmon.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

sysmon_uid.o: sysmon_uid.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
