obj-m += sysmon.o

KVERSION = $(shell uname -r)

all: sysmon.o

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

sysmon.o: sysmon.c
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
