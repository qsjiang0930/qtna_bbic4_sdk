.PHONY: qevt_server qevt_send_event qproc_mon qproc_mon_send_event qevt_mlpm

PROGS= show_rfcal_version restore_bootcfg_env writerfmem fast_steer_sta

INSTALL_DIR= $(PREFIX)/sbin/

HOSTAPD_SRC=$(shell awk '/ZHOSTAPD_VERSION=/' ../../zhostapd/zhostapd.mk | sed 's/ZHOSTAPD_VERSION\=//')
HOSTAPD_SRC_BASE=../../zhostapd/$(HOSTAPD_SRC)

install: $(PROGS)
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 $(PROGS) $(INSTALL_DIR)

qevt_server.o: qevt_server.c qevt_server.h qevt_event_id.h
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	-I$(HOSTAPD_SRC_BASE)/src/utils -I$(HOSTAPD_SRC_BASE)/src/common \
	-I./ -c qevt_server.c

qevt_event_id.o: qevt_event_id.c qevt_event_id.h qevt_server.h
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	-I$(HOSTAPD_SRC_BASE)/src/utils -I$(HOSTAPD_SRC_BASE)/src/common \
	-I./ -c qevt_event_id.c

wpa_ctrl.o: $(HOSTAPD_SRC_BASE)/src/common/wpa_ctrl.c
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	-I$(HOSTAPD_SRC_BASE)/src/utils -I$(HOSTAPD_SRC_BASE)/src/common \
	-c $(HOSTAPD_SRC_BASE)/src/common/wpa_ctrl.c

os_unix.o: $(HOSTAPD_SRC_BASE)/src/utils/os_unix.c
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	-I$(HOSTAPD_SRC_BASE)/src/utils -I$(HOSTAPD_SRC_BASE)/src/common \
	-c $(HOSTAPD_SRC_BASE)/src/utils/os_unix.c

qevt_server: qevt_server.o qevt_event_id.o wpa_ctrl.o os_unix.o
	$(CC) $(CFLAGS) $(LDFLAGS) -liw -pthread -o qevt_server qevt_server.o qevt_event_id.o wpa_ctrl.o os_unix.o

qevt_mlpm.o: qevt_mlpm.c
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	-I./ -c qevt_mlpm.c

qevt_mlpm:qevt_mlpm.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o qevt_mlpm qevt_mlpm.o

qevt_send_system_event.o: qevt_send_system_event.c qevt_server.h
	$(CC) $(CFLAGS) -DCONFIG_CTRL_IFACE -DCONFIG_CTRL_IFACE_UNIX \
	-I$(HOSTAPD_SRC_BASE)/src/utils -I$(HOSTAPD_SRC_BASE)/src/common \
	-I./ -c qevt_send_system_event.c

qevt_send_event: qevt_send_system_event.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o qevt_send_event qevt_send_system_event.o

qproc_mon.o: qproc_mon.c qproc_mon.h
	$(CC) $(CFLAGS) -I./ -c qproc_mon.c

qproc_mon: qproc_mon.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o qproc_mon qproc_mon.o

qproc_mon_send_event.o: qproc_mon_send_event.c qproc_mon.h
	$(CC) $(CFLAGS) -DCONFIG_QPROC_MONITOR_LOG -I./ -c qproc_mon_send_event.c

qproc_mon_send_event: qproc_mon_send_event.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o qproc_mon_send_event qproc_mon_send_event.o

fast_steer_sta.o: fast_steer_sta.c
	$(CC) $(CFLAGS) -DCONFIG_QTN_BSA_SUPPORT -I../../../../drivers/include/shared \
	-I../../wireless-tools/wireless_tools.29 -I$(HOSTAPD_SRC_BASE)/src/drivers -c $^

fast_steer_sta: fast_steer_sta.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

#ql2t
.PHONY: ql2t
ql2t:
	(export CFLAGS; export LDFLAGS; $(MAKE) -C ql2t install)

install_qevent: qevt_server qevt_send_event qproc_mon qproc_mon_send_event ql2t qevt_mlpm
	install -m 755 -d $(INSTALL_DIR)
	install -m 755 qevt_server $(INSTALL_DIR)
	install -m 755 qevt_server_event.conf $(PREFIX)/etc/
	install -m 755 qevt_send_event $(INSTALL_DIR)
	install -m 755 qproc_mon $(INSTALL_DIR)
	install -m 755 qproc_mon.conf $(PREFIX)/etc/
	install -m 755 qproc_mon_send_event $(INSTALL_DIR)
	install -m 755 qevt_mlpm $(INSTALL_DIR)

clean:
	rm -f $(PROGS)
	rm -f qevt_server wpa_ctrl.o qevt_server.o os_unix.o qevt_event_id.o
	rm -f qevt_send_event qevt_send_system_event.o
	rm -f qproc_mon qproc_mon.o
	rm -f qproc_mon_send_event qproc_mon_send_event.o
	$(MAKE) -C ql2t clean
