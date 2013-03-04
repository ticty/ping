###################
# Makefile for ping
###################


# target setting
PING    =   ping

Target  =   $(PING)
Doc     =   ping.8

name_prefix     =   my

doc_path        =   ./doc
install_prefix  =   /usr/local/bin
man_prefix      =   /usr/share/man/man8


# compile & link config
CC      =   gcc

DEFINES =   

CFLAGS  =   -O3 -g -Wall -W \
            -MMD -MP -MF "$(@:%.o=%.d)" -MT "$@" -MT "$(@:%.o=%.d)"

LDFLAGS =    

OBJ_DIR =   .obj


# source & object
SRCS    =   ping.c \
            misc.c

OBJS    =   ${SRCS:%.c=$(OBJ_DIR)/%.o}

DEPS    =   ${OBJS:.o=.d}


# make rule
all: $(Target)


-include $(DEPS)


$(PING): $(OBJS)
	@$(CC) $(LDFLAGS) -o "$@" $(OBJS)
	@-chmod 755 $@
	@echo ""
	@echo "### Bulid $@ success ###"
	@echo ""


$(OBJ_DIR)/%.o: %.c
	@test -d $(OBJ_DIR) || mkdir -p -m 777 $(OBJ_DIR)
	$(CC) $(DEFINES) $(CFLAGS) -c "$<" -o "$@"
	@-chmod 666 "$@" "$(@:%.o=%.d)"    # deal with run make as root
	@echo ""


mode: permission $(Target)
	chown root $(Target)
	chmod a+rx,u+ws $(Target)

permission:
	@if [ `id -u` -eq 0 ]; \
	then \
		exit 0; \
	else \
		echo "*** please run with root permission ***"; \
		exit 1; \
	fi

install: permission $(Target) $(doc_path)/$(Doc)
	install -d -m 0755 $(install_prefix)
	cp -f $(Target) $(install_prefix)/$(name_prefix)$(Target)
	chown root $(install_prefix)/$(name_prefix)$(Target)
	chmod a+rx,u+ws $(install_prefix)/$(name_prefix)$(Target)
	install -d -m 0755 $(man_prefix)
	install -m 0644 $(doc_path)/$(Doc) $(man_prefix)/$(name_prefix)$(Doc)
	@echo ""
	@echo "### Install finished ###"

uninstall: permission
	-rm -f $(install_prefix)/$(name_prefix)$(Target)
	-rm -f $(man_prefix)/$(name_prefix)$(Doc)

clean:
	-rm -f $(OBJS) $(Target) $(DEPS)
	-rm -rf $(OBJ_DIR)


.PHONY: mode permission install uninstall clean

#end of Makefile
