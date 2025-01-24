KERNEL_DIR=/lib/modules/$(shell uname -r)/build

obj-m += pidtest.o

all:
        make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
        make -C $(KERNEL_DIR) M=$(PWD) clean
