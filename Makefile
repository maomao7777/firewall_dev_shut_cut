KVERSION := $(shell uname -r)
KERNEL_FULL_DIR=/usr/src/linux-headers-$(KVERSION)/
DIR= $(shell pwd)
DSC_DIR=$(shell pwd)

obj-m:=  dsc.o


dsc-objs = dsc_main.o
dsc-objs += dsc_config.o dsc_cmd_tbl.o dsc_cmd.o ex_string.o


# EXTRA_CFLAGS += -DDSC_SAMPLE_HANDLER=1
# dsc-objs += sample_l2_handler.o sample_l3_handler.o

dsc-objs += dsc_debug.o


dsc-objs += captive_portal_handler.o captive_portal_l2_handler.o


dsc-objs += dsc_walledgarden_handler.o 


dsc-objs += dns_redirect_l2_handler.o dns_redirect_l3_handler.o


EXTRA_CFLAGS +=-DHAS_NOFITY_INTERFACE

EXTRA_CFLAGS += -I$(PWD)/ -I$(PWD)/include -I$(KERNEL_FULL_DIR)/include/ -I../../configs/include/
##############################################



##############################################

all: clean build

clean:
	$(RM) *.o *.ko *mod.c *~  .*.o.cmd .*.ko.cmd

build:
	$(MAKE) -C $(KERNEL_FULL_DIR) ARCH=$(ARCH) M=$(DIR) modules
        
install:
	mkdir -p $(PREFIX)/lib;\
	cp dsc.ko $(PREFIX)/lib
