CC=gcc
CFLAGS=-c -Wall -g -lnfnetlink -lnetfilter_queue -lsodium -lzmq -lpthread -D_REENTRANT
LDFLAGS=-g -lnfnetlink -lnetfilter_queue -lsodium -lzmq -lpthread


EXEC=crypt_bridge
SRC= $(wildcard *.c)
OBJ= $(SRC:.c=.o)


all:	$(EXEC)

-include $(OBJ:.o=.d)

.c.o:	
	@echo 'Building file: $<'
	@echo 'Invoking: GCC Compiler'
	$(CC) $(CFLAGS) -o $@ $<
	@echo 'Finished building: $<'
	@echo ' '

$(EXEC): $(OBJ)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC Linker'
	$(CC) -o $@ $^ $(LDFLAGS)
	@echo 'Finished building target: $@'
	@echo ' '

.PHONY: clean cleanall install

clean:
	rm -rf *.o *.d
cleanall:
	rm -rf *.o *.d
	rm -rf $(EXEC)

install: 
	cp $(EXEC) /usr/sbin/$(EXEC)

