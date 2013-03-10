obj-m += sysmon.o
obj-m += sysmon_uid.o
obj-m += sysmon_toggle.o
obj-m += sysmon_log.o

KVERSION = $(shell uname -r)

all: sysmon.o sysmon_uid.o sysmon_toggle.o sysmon_log.o

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

sysmon.o: sysmon.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

sysmon_uid.o: sysmon_uid.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

sysmon_toggle.o: sysmon_toggle.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

sysmon_log.o: sysmon_log.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
