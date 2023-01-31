#!/usr/bin/perl -w
use strict;
use warnings;

#
# Copyright (c) 2011-2012 Quantenna Communications, Inc.
# All rights reserved.
#
# qcsapi_rpc_gen.pl
#
# Generate an rpc interface definition .x file based on qcsapi.h,
# and also generate client and server stub adapters
#

use Carp;
use File::Basename;

# Make all dies a stacktrace
# $SIG{ __DIE__ } = sub { Carp::confess( @_ ) };

my $my_name = basename($0);
my $config_file;
my $config_file_basename;
my $qcsapi_header_file;
my $qcsapi_header_file_basename;
my %procedure_id_map = ();
my %procedure_args = ();
my $error_cnt = 0;

# generate additional code in the server/client adapters for debug prints?
my $src_debug = 0;
my $debug = 0;

my $outfilepath = "generated";
my $outfilebase = "qcsapi_rpc";
my $autogenmsg = " ########## DO NOT EDIT ###########\n\nAutomatically generated on ".`date --rfc-2822`;
my $dual_license = "/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2017 Quantenna Communications, Inc.          **
**                                                                           **
**  File        :                                                            **
**  Description :                                                            **
**                                                                           **
*******************************************************************************
**                                                                           **
**  Redistribution and use in source and binary forms, with or without       **
**  modification, are permitted provided that the following conditions       **
**  are met:                                                                 **
**  1. Redistributions of source code must retain the above copyright        **
**     notice, this list of conditions and the following disclaimer.         **
**  2. Redistributions in binary form must reproduce the above copyright     **
**     notice, this list of conditions and the following disclaimer in the   **
**     documentation and/or other materials provided with the distribution.  **
**  3. The name of the author may not be used to endorse or promote products **
**     derived from this software without specific prior written permission. **
**                                                                           **
**  Alternatively, this software may be distributed under the terms of the   **
**  GNU General Public License (\"GPL\") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR \"AS IS\" AND ANY EXPRESS OR       **
**  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES**
**  OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  **
**  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,         **
**  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT **
**  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,**
**  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    **
**  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      **
**  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF **
**  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.        **
**                                                                           **
*******************************************************************************
EH0*/
";

# Selected APIs cannot be called remotely (callback registry, currently unserializable things)
my @blacklist = qw(
	qcsapi_gpio_monitor_reset_device
	qcsapi_vsp_add_wl
	qcsapi_vsp_del_wl
	qcsapi_vsp_del_wl_index
	qcsapi_vsp_get_wl
);

my $qcsapi_rpc_x_prefix = "
/*
 * qcsapi_rpc.x
 *
 * $autogenmsg
 */

typedef string str<>;

struct __rpc_string {
	string data<>;
};
typedef struct __rpc_string * __rpc_string_p;

struct __rpc_qcsapi_mac_addr {
	unsigned char data[6];
};
typedef struct __rpc_qcsapi_mac_addr * __rpc_qcsapi_mac_addr_p;

struct __rpc_qcsapi_mac_addr_list {
	unsigned char data[48];
};
typedef struct __rpc_qcsapi_mac_addr_list * __rpc_qcsapi_mac_addr_list_p;

struct __rpc_qcsapi_int_a32 {
	int data[32];
};
typedef struct __rpc_qcsapi_int_a32 *__rpc_qcsapi_int_a32_p;

struct __rpc_qcsapi_SSID {
	unsigned char data[33];
};

";

my $structure_dep = "";
my %structure_dep_added;
my @structure_names = ();
my $types = "";

my $program_prefix = "
program QCSAPI_PROG {
version QCSAPI_VERS {
";

my $program_suffix = "
} = 1;
} = 0x20000002;
";

my $program_functions = "";

my $blacklist_defines = "
%
%/* defines for local-only functions */
";

my $client_adapter = "$dual_license
/*
 * $autogenmsg
 *
 * Adapter from qcsapi.h functions
 * to RPC client functions.
 */

#include <stdio.h>
#include <errno.h>
#include <inttypes.h>

#include <qcsapi.h>
#include \"$outfilebase.h\"
#include <qcsapi_rpc/client/qcsapi_rpc_client.h>

static int retries_limit = 3;

/* Default timeout can be changed using clnt_control() */
static struct timeval __timeout = { 25, 0 };

static CLIENT *__clnt = NULL;

#ifdef PCIE_RPC_LOCK_ENABLE
CLIENT *__clnt_pci = NULL;
#endif

static const int debug = $src_debug;

static CLIENT *qcsapi_adapter_get_client(void)
{
	if (__clnt == NULL) {
		fprintf(stderr, \"%s: client is null!\\n\", __FUNCTION__);
		exit (1);
	}

	return __clnt;
}

void client_qcsapi_set_rpcclient(CLIENT * clnt)
{
	__clnt = clnt;
}

#ifdef PCIE_RPC_LOCK_ENABLE
void hidden_client_qcsapi_set_rpcclient(CLIENT * clnt)
{
	__clnt_pci = clnt;
}
#endif

static client_qcsapi_callback_pre_t __pre_callback = NULL;
static client_qcsapi_callback_post_t __post_callback = NULL;
static client_qcsapi_callback_reconnect_t __reconnect_callback = NULL;

#ifdef PCIE_RPC_LOCK_ENABLE
static client_qcsapi_locker_t __locker = NULL;
static client_qcsapi_unlocker_t __unlocker = NULL;
#endif

void client_qcsapi_set_callbacks(client_qcsapi_callback_pre_t pre,
		client_qcsapi_callback_post_t post,
		client_qcsapi_callback_reconnect_t reconnect)
{
	__pre_callback = pre;
	__post_callback = post;
	__reconnect_callback = reconnect;
}

#ifdef PCIE_RPC_LOCK_ENABLE
void client_qcsapi_set_lock(client_qcsapi_locker_t locker,
		client_qcsapi_unlocker_t unlocker)
{
	__locker = locker;
	__unlocker = unlocker;
}

static int __client_qcsapi_lock(void)
{
	if (__locker) {
		return __locker();
	} else {
		return -1;
	}
}

static int __client_qcsapi_unlock(int fd)
{
	if (__unlocker) {
		return __unlocker(fd);
	} else {
		return -1;
	}
}
#endif

#define client_qcsapi_pre() __client_qcsapi_pre(__FUNCTION__)
static void * __client_qcsapi_pre(const char *func)
{
	if (__pre_callback) {
		return __pre_callback(func);
	}
	return (void *)QCSAPI_RPC_CALLBACK_UNSET;
}

#define client_qcsapi_post(x) __client_qcsapi_post(__FUNCTION__, (x))
static void __client_qcsapi_post(const char *func, int was_error)
{
	if (__post_callback) {
		__post_callback(func, was_error);
	}
}

#define client_qcsapi_reconnect() __client_qcsapi_reconnect(__FUNCTION__)
static void __client_qcsapi_reconnect(const char *func)
{
	if (__reconnect_callback) {
		__reconnect_callback(func);
	}
}

static void sad_copy_rpc2packed(const struct __rpc_qcsapi_sample_assoc_data * rpc,
	struct qcsapi_sample_assoc_data * pack)
{
	memcpy(pack->mac_addr, rpc->mac_addr.data, sizeof(pack->mac_addr));
	memcpy(&pack->assoc_id,   &rpc->assoc_id,  sizeof(pack->assoc_id));
	memcpy(&pack->bw,         &rpc->bw, sizeof(pack->bw));
	memcpy(&pack->tx_stream,  &rpc->tx_stream, sizeof(pack->tx_stream));
	memcpy(&pack->rx_stream,  &rpc->rx_stream, sizeof(pack->rx_stream));
	memcpy(&pack->time_associated, &rpc->time_associated, sizeof(pack->time_associated));
	memcpy(&pack->achievable_tx_phy_rate, &rpc->achievable_tx_phy_rate, sizeof(pack->achievable_tx_phy_rate));
	memcpy(&pack->achievable_rx_phy_rate, &rpc->achievable_rx_phy_rate, sizeof(pack->achievable_rx_phy_rate));
	memcpy(&pack->rx_packets, &rpc->rx_packets, sizeof(pack->rx_packets));
	memcpy(&pack->tx_packets, &rpc->tx_packets, sizeof(pack->tx_packets));
	memcpy(&pack->rx_errors,  &rpc->rx_errors,  sizeof(pack->rx_errors));
	memcpy(&pack->tx_errors,  &rpc->tx_errors,  sizeof(pack->tx_errors));
	memcpy(&pack->rx_dropped, &rpc->rx_dropped, sizeof(pack->rx_dropped));
	memcpy(&pack->tx_dropped, &rpc->tx_dropped, sizeof(pack->tx_dropped));
	memcpy(pack->tx_wifi_drop, rpc->tx_wifi_drop, sizeof(pack->tx_wifi_drop));
	memcpy(&pack->rx_ucast,   &rpc->rx_ucast, sizeof(pack->rx_ucast));
	memcpy(&pack->tx_ucast,   &rpc->tx_ucast, sizeof(pack->tx_ucast));
	memcpy(&pack->rx_mcast,   &rpc->rx_mcast, sizeof(pack->rx_mcast));
	memcpy(&pack->tx_mcast,   &rpc->tx_mcast, sizeof(pack->tx_mcast));
	memcpy(&pack->rx_bcast,   &rpc->rx_bcast, sizeof(pack->rx_bcast));
	memcpy(&pack->tx_bcast,   &rpc->tx_bcast, sizeof(pack->tx_bcast));
	memcpy(&pack->link_quality, &rpc->link_quality, sizeof(pack->link_quality));
	memcpy(&pack->ip_addr,    &rpc->ip_addr,  sizeof(pack->ip_addr));
	memcpy(&pack->rx_bytes,   &rpc->rx_bytes, sizeof(pack->rx_bytes));
	memcpy(&pack->tx_bytes,   &rpc->tx_bytes, sizeof(pack->tx_bytes));
	memcpy(pack->last_rssi_dbm, rpc->last_rssi_dbm, sizeof(pack->last_rssi_dbm));
	memcpy(pack->last_rcpi_dbm, rpc->last_rcpi_dbm, sizeof(pack->last_rcpi_dbm));
	memcpy(pack->last_evm_dbm,  rpc->last_evm_dbm,  sizeof(pack->last_evm_dbm));
	memcpy(pack->last_hw_noise, rpc->last_hw_noise, sizeof(pack->last_hw_noise));
	memcpy(&pack->protocol,   &rpc->protocol, sizeof(pack->protocol));
	memcpy(&pack->vendor,     &rpc->vendor,   sizeof(pack->vendor));
}

void sad_transform_rpc2packed(unsigned int num,
	const struct __rpc_qcsapi_sample_assoc_data * rpc,
	struct qcsapi_sample_assoc_data * packed)
{
	if (num && rpc && packed) {
		unsigned int i;
		for (i = 0; i < num; i++)
			sad_copy_rpc2packed(rpc + i, packed + i);
	}
}

";

my $server_adapter = "
/*
 * $autogenmsg
 *
 * Adapter from qcsapi.h functions
 * to RPC server functions.
 */

#include <inttypes.h>
#include <qcsapi.h>
#include \"$outfilebase.h\"

static const int debug = $src_debug;

#define ARG_ALLOC_SIZE	8192

static void *arg_alloc(void)
{
	void *mem = malloc(ARG_ALLOC_SIZE);
	if (mem) {
		memset(mem, 0, ARG_ALLOC_SIZE);
	}
	return mem;
}

static void arg_free(void *arg)
{
	free(arg);
}

static void* __rpc_prepare_data(void *input_ptr, int length)
{
	void *data = NULL;

	if (!input_ptr)
		return NULL;

	data = malloc(length);
	if (data)
		memcpy(data, input_ptr, length);

	return data;
}

static void sad_copy_packed2rpc(const struct qcsapi_sample_assoc_data * pack,
	struct __rpc_qcsapi_sample_assoc_data * rpc)
{
	memcpy(rpc->mac_addr.data, pack->mac_addr, sizeof(rpc->mac_addr.data));
	memcpy(&rpc->assoc_id,   &pack->assoc_id,  sizeof(rpc->assoc_id));
	memcpy(&rpc->bw,         &pack->bw,        sizeof(rpc->bw));
	memcpy(&rpc->tx_stream,  &pack->tx_stream, sizeof(rpc->tx_stream));
	memcpy(&rpc->rx_stream,  &pack->rx_stream, sizeof(rpc->rx_stream));
	memcpy(&rpc->time_associated, &pack->time_associated, sizeof(rpc->time_associated));
	memcpy(&rpc->achievable_tx_phy_rate, &pack->achievable_tx_phy_rate, sizeof(rpc->achievable_tx_phy_rate));
	memcpy(&rpc->achievable_rx_phy_rate, &pack->achievable_rx_phy_rate, sizeof(rpc->achievable_rx_phy_rate));
	memcpy(&rpc->rx_packets, &pack->rx_packets, sizeof(rpc->rx_packets));
	memcpy(&rpc->tx_packets, &pack->tx_packets, sizeof(rpc->tx_packets));
	memcpy(&rpc->rx_errors,  &pack->rx_errors,  sizeof(rpc->rx_errors));
	memcpy(&rpc->tx_errors,  &pack->tx_errors,  sizeof(rpc->tx_errors));
	memcpy(&rpc->rx_dropped, &pack->rx_dropped, sizeof(rpc->rx_dropped));
	memcpy(&rpc->tx_dropped, &pack->tx_dropped, sizeof(rpc->tx_dropped));
	memcpy(rpc->tx_wifi_drop, pack->tx_wifi_drop, sizeof(rpc->tx_wifi_drop));
	memcpy(&rpc->rx_ucast,   &pack->rx_ucast, sizeof(rpc->rx_ucast));
	memcpy(&rpc->tx_ucast,   &pack->tx_ucast, sizeof(rpc->tx_ucast));
	memcpy(&rpc->rx_mcast,   &pack->rx_mcast, sizeof(rpc->rx_mcast));
	memcpy(&rpc->tx_mcast,   &pack->tx_mcast, sizeof(rpc->tx_mcast));
	memcpy(&rpc->rx_bcast,   &pack->rx_bcast, sizeof(rpc->rx_bcast));
	memcpy(&rpc->tx_bcast,   &pack->tx_bcast, sizeof(rpc->tx_bcast));
	memcpy(&rpc->link_quality, &pack->link_quality, sizeof(rpc->link_quality));
	memcpy(&rpc->ip_addr,    &pack->ip_addr,  sizeof(rpc->ip_addr));
	memcpy(&rpc->rx_bytes,   &pack->rx_bytes, sizeof(rpc->rx_bytes));
	memcpy(&rpc->tx_bytes,   &pack->tx_bytes, sizeof(rpc->tx_bytes));
	memcpy(rpc->last_rssi_dbm, pack->last_rssi_dbm, sizeof(rpc->last_rssi_dbm));
	memcpy(rpc->last_rcpi_dbm, pack->last_rcpi_dbm, sizeof(rpc->last_rcpi_dbm));
	memcpy(rpc->last_evm_dbm,  pack->last_evm_dbm,  sizeof(rpc->last_evm_dbm));
	memcpy(rpc->last_hw_noise, pack->last_hw_noise, sizeof(rpc->last_hw_noise));
	memcpy(&rpc->protocol,   &pack->protocol, sizeof(rpc->protocol));
	memcpy(&rpc->vendor,     &pack->vendor,   sizeof(rpc->vendor));
}

struct qcsapi_sample_assoc_data * sad_alloc_packed(unsigned int num)
{
	struct qcsapi_sample_assoc_data * packed = NULL;
	if (num) {
		packed = malloc(sizeof(struct qcsapi_sample_assoc_data) * num);
		if (packed)
			memset(packed, 0, sizeof(struct qcsapi_sample_assoc_data) * num);
	}
	return packed;
}

static struct __rpc_qcsapi_sample_assoc_data * sad_alloc_rpc(unsigned int num)
{
	struct __rpc_qcsapi_sample_assoc_data * rpc = NULL;
	if (num) {
		rpc = malloc(sizeof(struct __rpc_qcsapi_sample_assoc_data) * num);
		if (rpc)
			memset(rpc, 0, sizeof(struct __rpc_qcsapi_sample_assoc_data) * num);
	}
	return rpc;
}

struct __rpc_qcsapi_sample_assoc_data * sad_clone_rpc(unsigned int num,
	const struct qcsapi_sample_assoc_data * packed)
{
	struct __rpc_qcsapi_sample_assoc_data * rpc = NULL;
	if (num && packed) {
		rpc = sad_alloc_rpc(num);
		if (rpc) {
			unsigned int i;
			for (i = 0; i < num; i++)
				sad_copy_packed2rpc(packed + i, rpc + i);
		}
	}
	return rpc;
}

";

use constant {
	MEMCPY_ARG	=> 0x00000001,
	STRCPY_ARG	=> 0x00000002,
	SPTR_ARG	=> 0x00000004,
	U64PTR_ARG	=> 0x00000008,
	ALLOC_ARG	=> 0x00000010,
	NON_NULL	=> 0x00000020,
	U64_ARG		=> 0x00000040,
	FLOAT_ARG	=> 0x00000080,
	STRING_PTR	=> 0x00000100,
	ENUM_TYPE	=> 0x00000200,
	QCSAPI_MAC	=> 0x00000400,
	STR_ARRAY	=> 0x00000800,
	INT_ARRAY	=> 0x00001000,
	QCSAPI_MAC_LIST	=> 0x00002000,
};

# type map: (input type, output type, input post, output post);
my %input_type_map = (
##       qcsapi.h       , [ type flags,             XDR type,         c type,        array?
	'const char *' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_16' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_32' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_64' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_128' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_256' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_512' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_1024' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_2048' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const string_4096' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const qcsapi_SSID' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const qcsapi_mcs_rate' => [STRCPY_ARG | STRING_PTR, '__rpc_string *', '__rpc_string *'],
	'const qcsapi_mac_addr' => [QCSAPI_MAC, '__rpc_qcsapi_mac_addr_p'],
	'const qcsapi_mac_addr_list' => [QCSAPI_MAC_LIST, '__rpc_qcsapi_mac_addr_list_p'],
	'const qcsapi_int_a32' => [INT_ARRAY, '__rpc_qcsapi_int_a32_p'],
	'const qcsapi_unsigned_int' => [0, 'unsigned int', 'unsigned int'],
	'qcsapi_unsigned_int' => [0, 'unsigned int'],
	'const unsigned int' => [0, 'unsigned int', 'unsigned int'],
	'unsigned int' => [0, 'unsigned int', 'unsigned int'],
	'const int' => [0, 'int', 'int'],
	'int32_t' => [0, 'int32_t', 'int32_t'],
	'int8_t' => [0, 'int8_t'],
	'uint8_t' => [0, 'uint8_t'],
	'const uint8_t' => [0, 'uint8_t'],
	'uint16_t' => [0, 'uint16_t'],
	'const uint16_t' => [0, 'uint16_t'],
	'uint32_t' => [0, 'uint32_t'],
	'const uint32_t' => [0, 'uint32_t'],
	'int' => [0, 'int'],
	'unsigned long' => [0, 'uint32_t'],
	'const size_t' => [0, 'uint32_t'],
	'size_t' => [0, 'uint32_t'],
	'time_t' => [0, 'uint32_t'],
	'float' => [0, 'float'],
	'u_int64_t' => [0, 'uint64_t', 'uint64_t'],
	'uint64_t' => [0, 'uint64_t', 'uint64_t'],
);

my %output_type_map = (
	'char *' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'char **' => [STR_ARRAY | NON_NULL, 'str', 'char **', '<>'],
	'string_16' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_32' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_64' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_128' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_256' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_512' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_1024' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_2048' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'string_4096' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'qcsapi_SSID' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'unsigned long *' => [SPTR_ARG, 'unsigned long *'],
	'unsigned int *' => [SPTR_ARG, 'unsigned int *'],
	'int *' => [SPTR_ARG, 'int *'],
	'uint8_t *' => [SPTR_ARG, 'uint8_t *'],
	'uint16_t *' => [SPTR_ARG, 'uint16_t *'],
	'uint32_t *' => [SPTR_ARG, 'uint32_t *'],
	'qcsapi_unsigned_int *' => [SPTR_ARG, 'unsigned int *'],
	'qcsapi_mac_address_filtering *' => [SPTR_ARG, 'int *'],
	'qcsapi_mac_addr' => [QCSAPI_MAC, '__rpc_qcsapi_mac_addr_p'],
	'qcsapi_mac_addr_list' => [QCSAPI_MAC_LIST, '__rpc_qcsapi_mac_addr_list_p'],
	'qcsapi_mcs_rate' => [STRCPY_ARG | STRING_PTR, '__rpc_string *'],
	'u_int64_t *' => [SPTR_ARG, 'uint64_t *', 'uint64_t *'],
	'uint64_t *' => [SPTR_ARG, 'uint64_t *', 'uint64_t *'],
	'qcsapi_int_a32 *' => [INT_ARRAY, '__rpc_qcsapi_int_a32_p'],
);

my %string_field_map = (
##	type => size
	'const string_16' => '17',
	'const string_32' => '33',
	'const string_64' => '65',
	'const string_128' => '129',
	'const string_256' => '257',
	'const string_512' => '513',
	'const string_1024' => '1025',
	'const string_2048' => '2049',
	'const string_4096' => '4097',
	'string_16' => '17',
	'string_32' => '33',
	'string_64' => '65',
	'string_128' => '129',
	'string_256' => '257',
	'string_512' => '513',
	'string_1024' => '1025',
	'string_2048' => '2049',
	'string_4096' => '4097',
);

my $union_qcsapi_measure_report_result = "qcsapi_measure_report_result";

my @allowed_unions = (
	'_qcsapi_measure_request_param', 'qcsapi_measure_request_param',
	'_qcsapi_measure_report_result', 'qcsapi_measure_report_result',
);

&parse_arguments(\@ARGV);
&parse_qcsapi_rpc_config();
parse_qcsapi_header();
if ($error_cnt > 0) {
	die "$my_name: $error_cnt error(s) found in $config_file or $qcsapi_header_file\n";
}
write_outputs();

sub write_outputs
{
	my $fn;
	my $sp_line = "\n/***********/\n\n";
	$fn = "$outfilepath/$outfilebase".".x";
	open(OUT_X, ">$fn") or die "Could not open $fn for writing: $!\n";
	print OUT_X $qcsapi_rpc_x_prefix;
	print OUT_X $structure_dep;
	print OUT_X $sp_line;
	print OUT_X $types;
	print OUT_X $sp_line;
	print OUT_X $blacklist_defines;
	print OUT_X $program_prefix;
	print OUT_X $program_functions;
	print OUT_X $program_suffix;
	close(OUT_X);

	$fn = "$outfilepath/$outfilebase"."_clnt_adapter.c";
	open(OUT_CL, ">$fn") or die "Could not open $fn for writing: $!\n";
	print OUT_CL $client_adapter;
	close(OUT_CL);

	$fn = "$outfilepath/$outfilebase"."_svc_adapter.c";
	open(OUT_SV, ">$fn") or die "Could not open $fn for writing: $!\n";
	print OUT_SV $server_adapter;
	close(OUT_SV);
}

sub add_stub
{
	my ($api_name, $return_type, $args_ref) = @_;
	my @args = @{$args_ref};

	my $c = "";

	$c .= "$return_type $api_name(@args)\n";
	$c .= "{\n";
	$c .= "\t/* stubbed, not implemented */\n";
	$c .= "\tfprintf(stderr, \"%s not implemented\\n\", \"$api_name\");\n";
	$c .= "\treturn -qcsapi_programming_error;\n";
	$c .= "}\n";

	$client_adapter .= $c;
	$blacklist_defines .= "%#define " . uc($api_name) . "_REMOTE $procedure_id_map{$api_name}\n";
}

sub __arg_type_str
{
	my ($arg, $name_prefix, $tarr_ref, $is_struct_field) = @_;
	if ($tarr_ref) {
		my @tarr = @{$tarr_ref};
		my $typename = $tarr[1];
		my $post = "";
		my $arraypart = $arg->{array};
		$arraypart = "" unless $arraypart;
		if ($#tarr >= 3) {
			$post = $tarr[3];
		}

		if ($is_struct_field && arg_is($arg, QCSAPI_MAC)) {
			$typename = "__rpc_qcsapi_mac_addr";
		} elsif ($is_struct_field && arg_is($arg, QCSAPI_MAC_LIST)) {
			$typename = "__rpc_qcsapi_mac_addr_list";
		} elsif ($is_struct_field && $arg->{type} eq "qcsapi_SSID") {
			$typename = "__rpc_qcsapi_SSID";
		}
		return $typename . " " . $name_prefix . $arg->{name} . $post . $arraypart;
	}
	return undef;
}

sub input_arg_type_str
{
	my ($arg, $name_prefix, $is_struct_field) = @_;
	return __arg_type_str($arg, $name_prefix, $input_type_map{$arg->{type}}, $is_struct_field);
}

sub output_arg_type_str
{
	my ($arg, $name_prefix, $is_struct_field) = @_;
	return __arg_type_str($arg, $name_prefix, $output_type_map{$arg->{type}}, $is_struct_field);
}

sub is_input_arg
{
	my ($arg_type) = @_;
	return defined($input_type_map{$arg_type});
}

sub is_string_arg {
	my ($arg_type) = @_;
	return defined($string_field_map{$arg_type});
}

sub arg_attrs
{
	my ($arg) = @_;
	if (is_input_arg($arg->{type})) {
		return $input_type_map{$arg->{type}}->[0];
	} else {
		my $v = $output_type_map{$arg->{type}}->[0];
		die "Argument type '$arg->{type}' is not present in input_type_map or output_type_map" unless defined($v);
		return $v;
	}
}

sub arg_xdrtype
{
	my ($arg) = @_;
	if (is_input_arg($arg->{type})) {
		return $input_type_map{$arg->{type}}->[1];
	} else {
		my $v = $output_type_map{$arg->{type}}->[1];
		die "Argument type '$arg->{type}' is not present in input_type_map or output_type_map" unless defined($v);
		return $v;
	}
}

sub arg_ctype
{
	my ($arg) = @_;
	if (is_input_arg($arg->{type})) {
		if (defined($input_type_map{$arg->{type}}->[2])) {
			return $input_type_map{$arg->{type}}->[2];
		} else {
			return $input_type_map{$arg->{type}}->[1];
		}
	} else {
		if (defined($output_type_map{$arg->{type}}->[2])) {
			return $output_type_map{$arg->{type}}->[2];
		} else {
			return $output_type_map{$arg->{type}}->[1];
		}
	}
}

sub arg_is
{
	my ($arg, $t) = @_;
	my $equal = (arg_attrs($arg) & $t) == $t;
	return $equal;
}

sub nullcheck_arg
{
	my ($arg) = @_;

	if ($arg->{struct_type}) {
		return 0;
	} elsif (arg_is($arg, NON_NULL)) {
		return 1;
	}

	return 0;
}

sub __add_client_req_arg
{
	my ($api_name, $pn, $arg, $structs) = @_;

	my $c = "";

	if ($arg->{struct_type}) {
		if (($api_name eq "qcsapi_wifi_get_per_assoc_data")
				&& ($arg->{struct_type} eq "qcsapi_sample_assoc_data")) {
			# special processing for qcsapi_wifi_get_per_assoc_data
			# nothing to output
		} elsif (($api_name eq "qcsapi_wifi_get_scs_param_report")
				&& ($arg->{struct_type} eq "qcsapi_scs_param_rpt")) {
			# nothing to output
		} elsif ($arg->{struct_type} eq $union_qcsapi_measure_report_result) {
			$c .= "\t__rpc_qcsapi_measure_report_result $arg->{name}_tmp;\n";
			$c .= "\t$arg->{name}_tmp.type = (int)param_type;\n";
			$c .= "\tmemcpy(&$arg->{name}_tmp.__rpc_qcsapi_measure_report_result_u, $arg->{name}, sizeof(*$arg->{name}));\n";
			$c .= "\t__req.$arg->{name} = &$arg->{name}_tmp;\n\n";
		} else {
			my $cast = "__rpc_".$arg->{struct_type}."*";
			$c .= "\t__req.$arg->{name} = ($cast)$arg->{name};\n\n";
		}
	} else {
		my $cast = arg_ctype($arg);
		if (arg_is($arg, STRING_PTR)) {
			$c .= "\t__rpc_string __rpc$arg->{name} = {(char *)$arg->{name}};\n";
			$c .= "\t__rpc_string *p__rpc$arg->{name} = ($arg->{name}) ? &__rpc$arg->{name} : NULL;\n";
			$c .= "\t__req.$arg->{name} = p__rpc$arg->{name};\n\n";
		} elsif (arg_is($arg, QCSAPI_MAC)) {
			$c .= "\tstruct __rpc_qcsapi_mac_addr __rpc$arg->{name};\n";
			$c .= "\tif ($arg->{name}) {\n";
			$c .= "\t\tmemcpy(__rpc$arg->{name}.data, $arg->{name}, sizeof(__rpc$arg->{name}));\n";
			$c .= "\t\t__req.$arg->{name} = &__rpc$arg->{name};\n";
			$c .= "\t} else {\n";
			$c .= "\t\t__req.$arg->{name} = NULL;\n";
			$c .= "\t}\n";
		} elsif (arg_is($arg, QCSAPI_MAC_LIST)) {
			$c .= "\tstruct __rpc_qcsapi_mac_addr_list __rpc$arg->{name};\n";
			$c .= "\tif ($arg->{name}) {\n";
			$c .= "\t\tmemcpy(__rpc$arg->{name}.data, $arg->{name}, sizeof(__rpc$arg->{name}));\n";
			$c .= "\t\t__req.$arg->{name} = &__rpc$arg->{name};\n";
			$c .= "\t} else {\n";
			$c .= "\t\t__req.$arg->{name} = NULL;\n";
			$c .= "\t}\n";
		} elsif (arg_is($arg, INT_ARRAY)) {
			$c .= "\tstruct __rpc_qcsapi_int_a32 __rpc$arg->{name};\n";
			$c .= "\tif ($arg->{name}) {\n";
			$c .= "\t\tmemcpy(__rpc$arg->{name}.data, $arg->{name}, sizeof(__rpc$arg->{name}));\n";
			$c .= "\t\t__req.$arg->{name} = &__rpc$arg->{name};\n";
			$c .= "\t} else {\n";
			$c .= "\t\t__req.$arg->{name} = NULL;\n";
			$c .= "\t}\n";
		} elsif (arg_is($arg, STR_ARRAY)) {
			$c .= "\t/* TODO: string array member - $arg->{name} */\n";
		} else {
			$c .= "\t__req.$arg->{name} = ($cast)$arg->{name};\n\n";
		}
	}

	return $c;
}

sub add_client_req_arg
{
	my ($api_name, $arg, $structs) = @_;
	return __add_client_req_arg($api_name, "", $arg, $structs);
}

sub add_client_resp_arg
{
	my ($api, $arg, $structs) = @_;
	my $cast;

	if ($arg->{struct_type}) {
		$cast = "__rpc_" . $arg->{struct_type} . ' * ';
	} else {
		$cast = arg_ctype($arg);
	}
	return "\t__resp.$arg->{name} = ($cast)$arg->{name};\n";
}

sub __add_client_req_post
{
	my ($api_name, $pn, $arg, $structs, $arrayp_depth) = @_;

	my $c = "";
	my $arrayp = "";
	for (my $i = 0; $i < $arrayp_depth; $i++) {
		$arrayp .= "[__i_$i]";
	}
	my $pn_us = "";
	my $pn_dot = "";
	my $pn_arrow = "";
	if ($pn) {
		$pn_us = $pn . "_";
		$pn_dot = $pn . ".";
		$pn_arrow = $pn . "->";
	}

	$c .= "\tif (__resp.return_code >= 0) {\n";
	if ($arg->{array} && scalar(@{$arg->{array_lens}}) > $arrayp_depth) {
		my $itername = "__i_$arrayp_depth";
		$c .= "\t{\n";
		$c .= "\t\tint $itername;\n";
		$c .= "\t\tfor ($itername = 0; $itername < ARRAY_SIZE(".$pn_arrow."$arg->{name}$arrayp); $itername++) {\n";
		$c .= "\t\t" . __add_client_req_post($api_name, $pn, $arg, $structs, $arrayp_depth + 1);
		$c .= "\t\t}\n";
		$c .= "\t}\n";
	} elsif ($arg->{struct_type}) {
		if ($api_name eq "qcsapi_wifi_wds_get_psk" && $arg->{name} eq "pre_shared_key") {
			$c .= "\t\tif (__resp.$arg->{name} && $arg->{name})\n";
			$c .= "\t\t\tmemcpy($arg->{name}, __resp.$arg->{name}, sizeof(struct $arg->{struct_type}));\n";
		} elsif (($api_name eq "qcsapi_wifi_get_per_assoc_data")
				&& ($arg->{struct_type} eq "qcsapi_sample_assoc_data")) {
			# special processing for qcsapi_wifi_get_per_assoc_data
			$c .= "\t\tif (__resp.$arg->{name}.$arg->{name}_val && __resp.$arg->{name}.$arg->{name}_len && (__resp.$arg->{name}.$arg->{name}_len == num_entry) && $arg->{name})\n";
			$c .= "\t\t\tsad_transform_rpc2packed(num_entry, __resp.$arg->{name}.$arg->{name}_val, $arg->{name});\n";
		} elsif (($api_name eq "qcsapi_wifi_get_scs_param_report")
				&& ($arg->{struct_type} eq "qcsapi_scs_param_rpt")) {
			# special processing for qcsapi_wifi_get_scs_param_report
			$c .= "\t\tif (__resp.$arg->{name}.$arg->{name}_val && __resp.$arg->{name}.$arg->{name}_len && (__resp.$arg->{name}.$arg->{name}_len == param_num) && $arg->{name}) {\n";
			$c .= "\t\t\tmemcpy($arg->{name}, __resp.$arg->{name}.$arg->{name}_val, sizeof(qcsapi_scs_param_rpt) * param_num);\n";
			$c .= "\t\t} else {\n";
			$c .= "\t\t\tif (debug) { fprintf(stderr, \"%s:%d %s Wrong request or response parameters\\n\", __FILE__, __LINE__, __FUNCTION__); }\n";
			$c .= "\t\t}\n";
		} else {
			$c .= "\t\tif (__resp.$arg->{name} && $arg->{name})\n";
			if ($arg->{struct_type} eq $union_qcsapi_measure_report_result) {
				$c .= "\t\t\tmemcpy($arg->{name}, &__resp.$arg->{name}->__rpc_qcsapi_measure_report_result_u, sizeof(*$arg->{name}));\n";
			} else {
				$c .= "\t\t\tmemcpy($arg->{name}, __resp.$arg->{name}, sizeof(*$arg->{name}));\n";
			}
		}
	} elsif (arg_is($arg, QCSAPI_MAC)) {
		$c .= "\t\tif ($arg->{name} && __resp.$arg->{name})\n";
		$c .= "\t\t\tmemcpy($arg->{name}, __resp.$arg->{name}->data,\n";
		$c .= "\t\t\t\tsizeof(qcsapi_mac_addr));\n";
	} elsif (arg_is($arg, QCSAPI_MAC_LIST)) {
		$c .= "\t\tif ($arg->{name} && __resp.$arg->{name})\n";
		$c .= "\t\t\tmemcpy($arg->{name}, __resp.$arg->{name}->data,\n";
		$c .= "\t\t\t\tsizeof(qcsapi_mac_addr_list));\n";
	} elsif (arg_is($arg, STRING_PTR)) {
		$c .= "\t\tif ($arg->{name} && __resp.$arg->{name})\n";
		$c .= "\t\t\tstrcpy($arg->{name}, __resp.$arg->{name}->data);\n";
	} elsif (arg_is($arg, STR_ARRAY)) {
		$c .= "\t\tunsigned int i;\n";
		$c .= "\t\tfor (i = 0; i < __resp.$arg->{name}.$arg->{name}"."_len; i++) {\n";
		$c .= "\t\t\tif(__resp.$arg->{name}.$arg->{name}"."_val[i])\n";
		$c .= "\t\t\t\tstrcpy($arg->{name}\[i\], __resp.$arg->{name}.$arg->{name}"."_val[i]);\n";
		$c .= "\t\t}\n";
		$c .= "\t\t$arg->{name}\[i\] = NULL;\n";
	} elsif (arg_is($arg, U64_ARG)) {
		$c .= "\tsscanf(__resp.".$pn_us."$arg->{name}$arrayp, \"%\" SCNu64, ";
		$c .= "&".$pn_arrow."$arg->{name}$arrayp);\n";
	} elsif (arg_is($arg, U64PTR_ARG)) {
		$c .= "\tif ($arg->{name}$arrayp)\n";
		$c .= "\t\tsscanf(__resp.".$pn_us."$arg->{name}$arrayp, \"%\" SCNu64, $arg->{name}$arrayp);\n";
	} elsif (arg_is($arg, FLOAT_ARG)) {
		$c .= "\tsscanf(__resp.".$pn_us."$arg->{name}$arrayp, \"%f\", ";
		$c .= "&".$pn_arrow."$arg->{name}$arrayp);\n";
	} elsif (arg_is($arg, SPTR_ARG) || arg_is($arg, ENUM_TYPE)) {
		$c .= "\t\tif ($arg->{name} &&  __resp.$arg->{name})\n";
		$c .= "\t\t\t*$arg->{name} = *__resp.$arg->{name}$arrayp;\n";
	} else {
		$c .= "\t".$pn_arrow."$arg->{name}$arrayp = __resp.".$pn_us."$arg->{name}$arrayp;\n";
	}

	$c .= "\t}\n";

	return $c;
}

sub __add_server_resp_post
{
	my ($api_name, $pn, $arg, $structs, $arrayp_depth) = @_;

	my $s = "";
	my $arrayp = "";
	for (my $i = 0; $i < $arrayp_depth; $i++) {
		$arrayp .= "[__i_$i]";
	}
	my $pn_us = "";
	my $pn_dot = "";
	my $pn_arrow = "";
	if ($pn) {
		$pn_us = $pn . "_";
		$pn_dot = $pn . ".";
		$pn_arrow = $pn . "->";
	}

	if ($arg->{array} && scalar(@{$arg->{array_lens}}) > $arrayp_depth) {
		my $itername = "__i_$arrayp_depth";
		$s .= "\t{\n";
		$s .= "\t\tint $itername;\n";
		$s .= "\t\tfor ($itername = 0; $itername < ARRAY_SIZE(".$pn_dot."$arg->{name}$arrayp); $itername++) {\n";
		$s .= "\t\t" . __add_server_resp_post($api_name, $pn, $arg, $structs, $arrayp_depth + 1);
		$s .= "\t\t}\n";
		$s .= "\t}\n";
	} elsif ($arg->{struct_type}) {
		if (($api_name eq "qcsapi_wifi_get_per_assoc_data")
				&& ($arg->{struct_type} eq "qcsapi_sample_assoc_data")) {
			# special processing for qcsapi_wifi_get_per_assoc_data
			# clone "rpc" data from "packed" form, release temporary "packed" buffer
			$s .= "\t__resp->$arg->{name}.$arg->{name}_val = sad_clone_rpc(__req->num_entry, tmp_packed_ptr);\n";
			$s .= "\tif (__resp->$arg->{name}.$arg->{name}_val)\n";
			$s .= "\t\t__resp->$arg->{name}.$arg->{name}_len = __req->num_entry;\n";
			$s .= "\tif (tmp_packed_ptr)\n";
			$s .= "\t\tfree(tmp_packed_ptr);\n"
		} elsif (($api_name eq "qcsapi_wifi_get_scs_param_report")
				&& ($arg->{struct_type} eq "qcsapi_scs_param_rpt")) {
			# special processing for qcsapi_wifi_get_scs_param_report
			$s .= "\t__resp->$arg->{name}.$arg->{name}_len = __req->param_num;\n";
		} else {
			$s .= "\t__resp->$arg->{name} = __rpc_prepare_data(__req->$arg->{name}, sizeof(*__resp->$arg->{name}));\n";
		}
	} elsif (arg_is($arg, STR_ARRAY)) {
		$s .= "\t__resp->list_SSID.list_SSID_val = list_SSID;\n";
		$s .= "\t__resp->list_SSID.list_SSID_len = __req->arrayc;\n";
		$s .= "\tfor (i = 0; i < __req->arrayc; i++) {\n";
		$s .= "\t\tif (list_SSID\[i\]\[0\] == '\\0') {\n";
		$s .= "\t\t\t__resp->list_SSID.list_SSID_len = i;\n";
		$s .= "\t\t\tbreak;\n";
		$s .= "\t\t}\n";
		$s .= "\t}\n";
		$s .= "\tfor (i = __resp->list_SSID.list_SSID_len; i < __req->arrayc; i++) {\n";
		$s .= "\t\targ_free(list_SSID[i]);\n";
		$s .= "\t}\n";
	} elsif (arg_is($arg, U64_ARG)) {
		$s .= "\tsprintf(__resp->".$pn_us."$arg->{name}$arrayp, \"%\" PRIu64, ";
		$s .= $pn_dot."$arg->{name}$arrayp);\n";
	} elsif (arg_is($arg, U64PTR_ARG)) {
		$s .= "\tsprintf(__resp->".$pn_us."$arg->{name}$arrayp, \"%\" PRIu64, ";
		$s .= "_$arg->{name}$arrayp);\n";
	} elsif (arg_is($arg, FLOAT_ARG)) {
		$s .= "\tsprintf(__resp->".$pn_us."$arg->{name}$arrayp, \"%f\", ";
		$s .= $pn_dot."$arg->{name}$arrayp);\n";
	} elsif (arg_is($arg, QCSAPI_MAC) || arg_is($arg, QCSAPI_MAC_LIST)) {
		$s .= "\t__resp->$arg->{name} = __rpc_prepare_data(__req->$arg->{name}, sizeof(*__resp->$arg->{name}));\n";
	} elsif (arg_is($arg, STRING_PTR)) {
		$s .= "\tif ($arg->{name}) {\n";
		$s .= "\t\t__resp->$arg->{name} = malloc(sizeof(*__resp->$arg->{name}));\n";
		$s .= "\t\t__resp->$arg->{name}->data = $arg->{name};\n";
		$s .= "\t}\n";
	} elsif (arg_is($arg, STRCPY_ARG)) {
		if (arg_is($arg, ALLOC_ARG)) {
			$s .= "\t__resp->".$pn_us."$arg->{name}$arrayp = arg_alloc();\n";
		}
		$s .= "\tstrcpy(__resp->".$pn_us."$arg->{name}$arrayp,\n";
		$s .= "\t\t".$pn_dot."$arg->{name}$arrayp);\n";
	} else {
		$s .= "\t__resp->$arg->{name} = __rpc_prepare_data(__req->$arg->{name}, sizeof(*__resp->$arg->{name}));\n";
	}

	return $s;
}

sub add_client_req_post
{
	my ($api_name, $arg, $structs) = @_;
	return __add_client_req_post($api_name, "", $arg, $structs, 0);
}

sub add_server_resp_post
{
	my ($api_name, $arg, $structs) = @_;
	return __add_server_resp_post($api_name, "", $arg, $structs, 0);
}

sub add_server_resp_arg
{
	my ($api_name, $arg, $structs) = @_;

	my $arg_type = $arg->{type};
	my $arg_type_noptr = $arg_type;
	$arg_type_noptr =~ s/\s*\*\s*//;
	my $s = "";

	if ($arg->{struct_type}) {
		$s .= "\t/* server struct local copy for $arg->{name}: $arg->{type} */\n";
		$s .= "\t$structs->{$arg->{struct_type}}->{canonical_name} $arg->{name};\n";
		$s .= "\tmemset(&$arg->{name}, 0, sizeof($arg->{name}));\n";
	} elsif ($arg->{name} eq "list_SSID") {
		$s .= "\tunsigned int i;\n";
		$s .= "\tchar **list_SSID = malloc(sizeof(char *) * __req->arrayc);\n";
		$s .= "\tfor (i = 0; i < __req->arrayc && list_SSID; i++) {\n";
		$s .= "\t\tlist_SSID[i] = arg_alloc();\n";
		$s .= "\t}\n";
	} elsif ($arg_type =~ /char \*$/) {
		$s .= "\t__resp->$arg->{name} = arg_alloc();\n";
	} elsif (arg_is($arg, U64PTR_ARG)) {
		$s .= "\tuint64_t _$arg->{name} = 0;\n";
		$s .= "\tuint64_t *$arg->{name} = &_$arg->{name};\n";
	} elsif (arg_is($arg, SPTR_ARG)) {
		$s .= "\t$arg_type_noptr _$arg->{name} = 0;\n";
		$s .= "\t$arg_type_noptr *$arg->{name} = &_$arg->{name};\n";
	} elsif (arg_is($arg, MEMCPY_ARG)) {
		$s .= "\t$arg_type $arg->{name};\n";
		$s .= "\tmemset(&$arg->{name}, 0, sizeof($arg->{name}));\n";
	} elsif (arg_is($arg, ALLOC_ARG)) {
		my $cast = arg_xdrtype($arg);
		$s .= "\t$cast $arg->{name} = arg_alloc();\n";
		$s .= "\t__resp->$arg->{name} = $arg->{name};\n";
	} else {
		$s .= "\t$arg_type $arg->{name} = &__resp->$arg->{name};\n";
	}

	return $s;
}

# parse the argument into structure
# const struct abc *data;
# - type: const struct abc *
# - name: data
# - is_input: yes
# - is_pointer: yes
# - structure_type: yes
sub args_parser
{
	my ($args_input, $args_output, $structs) = @_;

	foreach my $arg (@{$args_input}) {
		$arg =~ /^\s*(.*)\s+([0-9a-zA-Z_]+)$/;
		my $arg_type = $1;
		my $arg_name = $2;
		my $struct_type = undef;
		my $is_input;
		my $is_pointer;

		if ($arg_type =~ /^(const\s+)?(struct\s+)?(.*?)\s(\**)$/ && $structs->{$3}) {
			$struct_type = $3;
			$is_input = defined($1);
			$is_pointer = defined($4);
		} else {
			$is_input = is_input_arg($arg_type);
			if(!$is_input) {
				$is_pointer = 1;
			}
		}

		my %a = (
			type => $arg_type,
			name => $arg_name,
			is_input => $is_input,
			is_pointer => $is_pointer,
			struct_type => $struct_type,
		);

		push @{$args_output}, \%a;
	}
}

sub arg_is_struct
{
	my ($name, $struct) = @_;

	if (defined($struct->{$name})) {
		return 1;
	}

	return 0;
}

sub struct_arg_type_str
{
	my ($arg, $struct_type, $name_prefix) = @_;
	my $typename = "__rpc_" . $struct_type;
	my $arraypart = $arg->{array};
	$arraypart = "" unless $arraypart;

	return $typename . " " . $name_prefix . $arg->{name} . $arraypart;
}

sub union_is_forbidden
{
	my ($struct_name, $struct) = @_;

	if ($struct->{$struct_name}->{struct_or_union} eq "union") {
		foreach my $union_name (@allowed_unions) {
			if ($union_name eq $struct_name) {
				return 0;
			}
		}

		return 1;
	}

	return 0;
}

sub union_define
{
	my ($union_name) = @_;

	my $type_prefix = "union ";
	my $union_type_name4rpc = "__rpc_" . $union_name;
	my $union_dep = "";

	if ($union_name eq $union_qcsapi_measure_report_result) {
		$union_dep .= $type_prefix. $union_type_name4rpc . " switch (int type) {\n";
		$union_dep .= "\tcase 14:\n";		#QCSAPI_NODE_MEAS_BASIC
		$union_dep .= "\t\tuint8_t basic;\n";
		$union_dep .= "\tcase 15:\n";		#QCSAPI_NODE_MEAS_CCA
		$union_dep .= "\t\tuint8_t cca;\n";
		$union_dep .= "\tcase 16:\n";		#QCSAPI_NODE_MEAS_RPI
		$union_dep .= "\t\tuint8_t rpi[8];\n";
		$union_dep .= "\tcase 17:\n";		#QCSAPI_NODE_MEAS_CHAN_LOAD
		$union_dep .= "\t\tuint8_t channel_load;\n";
		$union_dep .= "\tcase 18:\n";		#QCSAPI_NODE_MEAS_NOISE_HIS
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_noise_histogram_s noise_histogram;\n";
		$union_dep .= "\tcase 19:\n";		#QCSAPI_NODE_MEAS_BEACON:
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_beacon_s beacon;\n";
		$union_dep .= "\tcase 20:\n";		#QCSAPI_NODE_MEAS_FRAME
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_frame_s frame;\n";
		$union_dep .= "\tcase 21:\n";		#QCSAPI_NODE_MEAS_TRAN_STREAM_CAT
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_tran_stream_cat_s tran_stream_cat;\n";
		$union_dep .= "\tcase 22:\n";		#QCSAPI_NODE_MEAS_MULTICAST_DIAG
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_multicast_diag_s multicast_diag;\n";
		$union_dep .= "\tcase 23:\n";		#QCSAPI_NODE_TPC_REP
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_tpc_s tpc;\n";
		$union_dep .= "\tcase 24:\n";		#QCSAPI_NODE_LINK_MEASURE
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_link_measure_s link_measure;\n";
		$union_dep .= "\tcase 25:\n";		#QCSAPI_NODE_NEIGHBOR_REP
		$union_dep .= "\t\t__rpc_qcsapi_measure_rpt_neighbor_report_s neighbor_report;\n";
		$union_dep .= "\tdefault:\n";
		$union_dep .= "\t\tint common[16];\n";
		$union_dep .= "};\n\n";
	}

	return $union_dep;
}

sub structure_define
{
	my ($structs) = @_;

	foreach my $struct_name (@structure_names) {
		my $structure_type_name4rpc = "__rpc_" . $struct_name;

		if (!defined($structure_dep_added{$struct_name})) {
			my $structure = $structs->{$struct_name};
			my $type_prefix = "struct ";
			my @fields;

			if (union_is_forbidden($struct_name, $structs)) {
				die "Union $struct_name is not supported. Unions require complex endian support.\n";
			}

			if ($structure->{struct_or_union} eq "union") {
				$structure_dep .= union_define($struct_name);
			} else {
				$structure_dep .= $type_prefix. $structure_type_name4rpc . " {\n";

				foreach my $field (@{$structure->{fields}}) {
					my $field_x_line;
					my $field_type = $field->{type};

					if ($field->{type} =~ /^\s*(struct\s+)?(.*?)\s*(\**)\s*$/) {
						$field_type = $2;
					}

					if (arg_is_struct($field_type, $structs)) {
						$field_x_line = struct_arg_type_str($field, $field_type, "");
					} elsif (is_string_arg($field->{type})) {
						#define string as array instead of pointer to keep the memory structure of the struct
						$field_x_line = "uint8_t " . $field->{name} . "[$string_field_map{$field->{type}}]";
					} elsif (is_input_arg($field->{type})) {
						$field_x_line = input_arg_type_str($field, "", 1);
					} else {
						$field_x_line = output_arg_type_str($field, "", 1);
					}

					$structure_dep .= "\t" . $field_x_line . ";\n";
				}
				$structure_dep .= "};\n\n";
				$structure_dep_added{$struct_name} = $structure_type_name4rpc;
			}

		}
	}
}

sub add_structure_name
{
	my ($arg, $structs) = @_;
	my $struct_type = $arg->{type};
	my $is_struct = 0;

	if (($arg->{type} =~ /^(const\s+)?(struct\s+)?(.*?)\s*(\**)$/) && $structs->{$3}) {
		$is_struct = 1;
		$struct_type = $3;
	}

	if ($is_struct) {
		my $structure = $structs->{$struct_type};
		my @fields;

		foreach my $field (@{$structure->{fields}}) {
			add_structure_name($field, $structs);
		}

		push @structure_names, $struct_type;
	}
}

sub xdr_struct_field
{
	my ($api_name, $arg, $structs, $name_prefix) = @_;

	if ($arg->{struct_type}) {
		my $structure_type_name4rpc = "__rpc_" . $arg->{struct_type};
		my $pointer = " ";
		if ($arg->{is_pointer}) {
			$pointer = " * ";
		}

		add_structure_name($arg, $structs);

		if (($api_name eq "qcsapi_wifi_get_per_assoc_data")
				&& ($arg->{struct_type} eq "qcsapi_sample_assoc_data")) {
			# special processing for qcsapi_wifi_get_per_assoc_data
			return  "\t" . $structure_type_name4rpc . " " . $arg->{name} . "<>;\n";
		} elsif (($api_name eq "qcsapi_wifi_get_scs_param_report")
				&& ($arg->{struct_type} eq "qcsapi_scs_param_rpt")) {
			# special processing for qcsapi_wifi_get_scs_param_report
			return  "\t" . $structure_type_name4rpc . " " . $arg->{name} . "<>;\n";
		} else {
			return  "\t" . $structure_type_name4rpc . $pointer . $arg->{name} . ";\n";
		}
	} elsif ($arg->{is_input}) {
		return "\t" . input_arg_type_str($arg, $name_prefix, 0) . ";\n";
	} else {
		return "\t" . output_arg_type_str($arg, $name_prefix, 0) . ";\n";
	}
}

sub procedure_arglist_is_matched
{
	my ($conf_file_args, $hdr_file_args) = @_;

	$conf_file_args =~ s/\s*//g;
	$hdr_file_args =~ s/\s*//g;

	return ($conf_file_args eq $hdr_file_args);
}

sub add_func
{
	my ($api_name, $api_args, $return_type, $args_ref, $structs) = @_;
	my @arg_strs = @{$args_ref};

	my $req_struct_fields = "";
	my $resp_struct_fields = "";
	my $server_adapter_sp_args = "";
	my $rpc_data_struct = $api_name. "_rpcdata";

	$" = ", ";
	$client_adapter .= "$return_type $api_name(@arg_strs)\n{\n";
	if ($api_name eq "qcsapi_wifi_get_scs_param_report") {
		$client_adapter .= "\tCOMPILE_TIME_ASSERT(sizeof(qcsapi_scs_param_rpt) == sizeof(__rpc_qcsapi_scs_param_rpt));\n\n";
	}
	if ($api_name eq "qcsapi_flash_image_update") {
		$client_adapter .= "\tint retries = retries_limit;\n";
		$client_adapter .= "\tstatic struct timeval timeout = { 60, 0 };\n"
	} else {
		$client_adapter .= "\tint retries = 0;\n";
	}
	$client_adapter .= "\tint ret;\n";
	$client_adapter .="#ifdef PCIE_RPC_LOCK_ENABLE\n";
	$client_adapter .= "\tint fd_lock = 0;\n";
	$client_adapter .="#endif\n";
	$client_adapter .= "\tCLIENT *clnt = qcsapi_adapter_get_client();\n";
	$client_adapter .= "\tenum clnt_stat __rpcret;\n";
	$client_adapter .= "\tstruct $rpc_data_struct __req;\n";
	$client_adapter .= "\tstruct $rpc_data_struct __resp;\n";
	$client_adapter .= "\tmemset(&__req, 0, sizeof(__req));\n";
	$client_adapter .= "\tmemset(&__resp, 0, sizeof(__resp));\n";

	$server_adapter .= "bool_t ".lc($api_name)."_remote_1_svc($rpc_data_struct *__req, $rpc_data_struct *__resp, struct svc_req *rqstp)\n{\n";

	my @serverinv;
	my @args;

	args_parser(\@arg_strs, \@args, $structs);

	if ($debug) {
		foreach my $arg (@args) {
			print "$api_name: $arg->{name}: $arg->{type}\n";
		}
	}

	# check client stub for nulls
	my @clientnullcheck;
	foreach my $arg (@args) {
		if (nullcheck_arg($arg)) {
			push @clientnullcheck, "$arg->{name} == NULL";
		}
	}
	if ($#clientnullcheck >= 0) {
		$client_adapter .= "\tif (" . join(" || ", @clientnullcheck) . ") {\n";
		$client_adapter .= "\t\treturn -EFAULT;\n";	# qcsapi idiomatic EFAULT for null pointer, not EINVAL
		$client_adapter .= "\t}\n";
	}

	# pre call
	foreach my $arg (@args) {
		my $cast = "";
		my $arg4server;

		if ($arg->{struct_type}) {
			$cast = "($arg->{type})";
			if (($api_name eq "qcsapi_wifi_get_per_assoc_data")
					&& ($arg->{struct_type} eq "qcsapi_sample_assoc_data")) {
				# special processing for qcsapi_wifi_get_per_assoc_data
				$arg4server = "tmp_packed_ptr";
			} elsif (($api_name eq "qcsapi_wifi_get_scs_param_report")
				&& ($arg->{struct_type} eq "qcsapi_scs_param_rpt")) {
				# special processing for qcsapi_wifi_get_scs_param_report
				$arg4server = "($arg->{type})__resp->$arg->{name}.$arg->{name}_val";
			} elsif ($arg->{struct_type} eq $union_qcsapi_measure_report_result) {
				$arg4server = "$cast". "&(__req->$arg->{name}->__rpc_qcsapi_measure_report_result_u)";
			} else {
				$arg4server = "$cast". "__req->$arg->{name}";
			}
		}

		# convent some args for server adapter
		if (!$arg->{struct_type}) {
			my $s = "";
			if (($api_name eq "qcsapi_wifi_wds_get_psk")
					&& ($arg->{name} eq "pre_shared_key")) {
				$arg->{type} = "struct qcsapi_data_32bytes *";
				$arg->{struct_type} = "qcsapi_data_32bytes";
				$arg4server = "(uint8_t *)__req->$arg->{name}";
			} elsif (arg_is($arg, STRING_PTR)) {
				if ($arg->{is_input}) {
					$server_adapter_sp_args .= "\tchar * " . $arg->{name} .
						" = (__req->$arg->{name} == NULL) ? " .
						"NULL : " .
						"__req->$arg->{name}->data" . ";\n";
				} else {
					$server_adapter_sp_args .= "\tchar * " . $arg->{name} .
						" = (__req->$arg->{name} == NULL) ? " .
						"NULL : " .
						"arg_alloc()" . ";\n";
				}
				$arg4server = $arg->{name};
			} elsif (arg_is($arg, QCSAPI_MAC) || arg_is($arg, QCSAPI_MAC_LIST)) {
				$server_adapter_sp_args .= "\tuint8_t * " . $arg->{name} .
						" = (__req->$arg->{name} == NULL) ? " .
						"NULL : " .
						"__req->$arg->{name}->data" . ";\n";
				$arg4server = $arg->{name};
			} elsif (arg_is($arg, INT_ARRAY)) {
				$server_adapter_sp_args .= "\tint * " . $arg->{name} .
						" = (__req->$arg->{name} == NULL) ? " .
						"NULL : " .
						"__req->$arg->{name}->data" . ";\n";
				$arg4server = $arg->{name};
			} elsif (arg_is($arg, ENUM_TYPE)) {
				$cast = "($arg->{type})";
				$server_adapter_sp_args .= "\t$arg->{type} " . $arg->{name} . "=$cast"."__req->$arg->{name};\n";
				$arg4server = $arg->{name};
			} elsif (arg_is($arg, STR_ARRAY)) {
				$s .= "\tunsigned int i;\n";
				$s .= "\tchar **$arg->{name} = malloc(sizeof(char *) * __req->arrayc);\n";
				$s .= "\tfor (i = 0; i < __req->arrayc && list_SSID; i++) {\n";
				$s .= "\t\tlist_SSID[i] = arg_alloc();\n";
				$s .= "\t}\n";
				$server_adapter_sp_args .= $s;
				$arg4server = $arg->{name};
			} else {
				$arg4server = "__req->$arg->{name}";
			}
		}

		if ($arg->{is_input}) {
			$req_struct_fields .= xdr_struct_field($api_name, $arg, $structs, "");
		} else {
			$resp_struct_fields .= xdr_struct_field($api_name, $arg, $structs, "");
		}

		$client_adapter .= add_client_req_arg($api_name, $arg, $structs);

		push (@serverinv, $arg4server);
	}

	$server_adapter .= $server_adapter_sp_args . "\n";
	$server_adapter .= "\tmemset(__resp, 0, sizeof(*__resp));" . "\n";
	$server_adapter .= "\tif (debug) { fprintf(stderr, \"%s:%d %s pre\\n\", __FILE__, __LINE__, __FUNCTION__); }\n";

	$client_adapter .= "\tif (debug) { fprintf(stderr, \"%s:%d %s pre\\n\", __FILE__, __LINE__, __FUNCTION__); }\n";
	$client_adapter .="#ifdef PCIE_RPC_LOCK_ENABLE\n";
	$client_adapter .= "\tfd_lock = __client_qcsapi_lock();\n";
	$client_adapter .= "\tif(!fd_lock)  { fprintf(stderr, \"%s:%d %s fd_lock init error! \\n\", __FILE__, __LINE__, __FUNCTION__);}\n";
	$client_adapter .="#endif\n";
	$client_adapter .= "\tif (client_qcsapi_pre() == NULL) {\n";
	$client_adapter .="#ifdef PCIE_RPC_LOCK_ENABLE\n";
	$client_adapter .= "\t\tif(fd_lock)\n";
	$client_adapter .= "\t\t\t__client_qcsapi_unlock(fd_lock);\n";
	$client_adapter .="#endif\n";
	$client_adapter .= "\t\treturn -200;\n";
	$client_adapter .= "\t}\n";
	$client_adapter .="#ifdef PCIE_RPC_LOCK_ENABLE\n";
	$client_adapter .= "\tif((uintptr_t)clnt == PCIE_VIRTUAL_CLNT_ADDR && __clnt_pci) clnt = __clnt_pci;\n";
	$client_adapter .="#endif\n";
	$client_adapter .= "\twhile (1) {\n";
	$client_adapter .= "\t\t__rpcret = clnt_call(clnt, ".uc($api_name)."_REMOTE,\n";
	$client_adapter .= "\t\t\t\t(xdrproc_t)xdr_$rpc_data_struct, (caddr_t)&__req,\n";
	$client_adapter .= "\t\t\t\t(xdrproc_t)xdr_$rpc_data_struct, (caddr_t)&__resp,\n";
	if ($api_name eq "qcsapi_flash_image_update") {
		$client_adapter .= "\t\t\t\ttimeout);\n";
	} else {
		$client_adapter .= "\t\t\t\t__timeout);\n";
	}
	$client_adapter .= "\t\tif (__rpcret == RPC_SUCCESS) {\n";
	$client_adapter .= "\t\t\tclient_qcsapi_post(0);\n";
	$client_adapter .="#ifdef PCIE_RPC_LOCK_ENABLE\n";
	$client_adapter .= "\t\tif(fd_lock)\n";
	$client_adapter .= "\t\t\t__client_qcsapi_unlock(fd_lock);\n";
	$client_adapter .="#endif\n";
	$client_adapter .= "\t\t\tbreak;\n";
	$client_adapter .= "\t\t} else {\n";
	$client_adapter .= "\t\t\tif (retries >= retries_limit) {\n";
	$client_adapter .= "\t\t\tclnt_perror (clnt, \"$api_name call failed\");\n";
	$client_adapter .= "\t\t\tclnt_perrno (__rpcret);\n";
	$client_adapter .= "\t\t\t\tclient_qcsapi_post(1);\n";
	$client_adapter .="#ifdef PCIE_RPC_LOCK_ENABLE\n";
	$client_adapter .= "\t\tif(fd_lock)\n";
	$client_adapter .= "\t\t\t\t__client_qcsapi_unlock(fd_lock);\n";
	$client_adapter .="#endif\n";
	$client_adapter .= "\t\t\t\txdr_free((xdrproc_t)xdr_$rpc_data_struct, (caddr_t)&__resp);\n";
	$client_adapter .= "\t\t\t\treturn -ENOLINK;\n";
	$client_adapter .= "\t\t\t}\n";
	$client_adapter .= "\t\t\tretries++;\n";
	$client_adapter .= "\t\t\tclient_qcsapi_reconnect();\n";
	$client_adapter .= "\t\t}\n\n";
	$client_adapter .= "\t}\n\n";

	if ($api_name eq "qcsapi_wifi_get_per_assoc_data") {
		# special processing for qcsapi_wifi_get_per_assoc_data
		$server_adapter .= "\n\tstruct qcsapi_sample_assoc_data * tmp_packed_ptr = sad_alloc_packed(__req->num_entry);\n";
	}
	elsif ($api_name eq "qcsapi_wifi_get_scs_param_report") {
		# special processing for qcsapi_wifi_get_scs_param_report
		$server_adapter .= "\tif (__req->param_num) {\n";
		$server_adapter .= "\t\t__resp->p_scs_param_rpt.p_scs_param_rpt_val = calloc(__req->param_num, sizeof(qcsapi_scs_param_rpt));\n";
		$server_adapter .= "\t\tif (__resp->p_scs_param_rpt.p_scs_param_rpt_val == NULL) {\n";
		$server_adapter .= "\t\t\tif (debug) { fprintf(stderr, \"%s:%d %s Error memory allocation\\n\", __FILE__, __LINE__, __FUNCTION__); }\n";
		$server_adapter .= "\t\t\treturn 0;\n";
		$server_adapter .= "\t\t}\n";
		$server_adapter .= "\t}\n";
	}

	$server_adapter .= "\n\t__resp->return_code = $api_name(@serverinv);\n\n";

	#warn "$0: $api_name: @args\n";

	# post call
	foreach my $arg (@args) {
		if ($arg->{is_input}) {
		} else {
			$client_adapter .= add_client_req_post($api_name, $arg, $structs);
			$server_adapter .= add_server_resp_post($api_name, $arg, $structs);
		}
	}

	$client_adapter .= "\tif (debug) { fprintf(stderr, \"%s:%d %s post\\n\", __FILE__, __LINE__, __FUNCTION__); }\n";
	$server_adapter .= "\tif (debug) { fprintf(stderr, \"%s:%d %s post\\n\", __FILE__, __LINE__, __FUNCTION__); }\n";

	$client_adapter .= "\n\tret = __resp.return_code;\n";
	$client_adapter .= "\txdr_free((xdrproc_t)xdr_$rpc_data_struct, (caddr_t)&__resp);\n";
	$client_adapter .= "\n\treturn ret;\n";
	$client_adapter .= "}\n\n";

	$server_adapter .= "\n\treturn 1;\n";
	$server_adapter .= "}\n\n";

	# X language structure
	$types .= "struct $rpc_data_struct {\n";
	$types .= $req_struct_fields;
	$types .= $resp_struct_fields;
	$types .= "\t$return_type return_code;\n";
	$types .= "};\n";

	if (!defined $procedure_id_map{$api_name}) {
		&show_error_msg("No procedure ID in $config_file_basename for $api_name()\n");
	} elsif (!procedure_arglist_is_matched($procedure_args{$api_name},  $api_args)) {
		&show_error_msg("Mismatched args in $qcsapi_header_file_basename for " .
				"$api_name($procedure_args{$api_name})\n");
	} else {
		$program_functions .= "\t\t$rpc_data_struct " . uc($api_name) . "_REMOTE(" .
				$rpc_data_struct . ") = $procedure_id_map{$api_name};\n";
	}
}

use constant {
	TOPLEVEL	=> 0,
	IN_STRUCT	=> 1,
	IN_ANON_STRUCT	=> 2,
	POST_STRUCT	=> 3,
	IN_ENUM		=> 4,
	IN_ANON_ENUM	=> 5,
	IN_UNION	=> 7,
	IN_ANON_UNION	=> 8,
	POST_UNION	=> 9,
};

sub parse_qcsapi_header
{
	$_ = `gcc -E -I../../../../../include/ -I../../../../../ -I../../../../../drivers/include/shared/ $qcsapi_header_file`;

	s/\r//g;
	s/\#.*?\n/\n/g;		# remove pound comments
	s/\n//g;		# remove newlines
	s/\s+/ /g;		# single spaces only
	s/([{;}])/$1\n/g;	# ;,{,} cause newline
	s/extern\s+//g;		# remove extern
	s/__extension__//g;	# remove extensions
	s/__attribute__\s*\(\(.*?\)\)//g;
	s/\(\s*void\s*\)/()/g;	# remove 'void' only args

	my %impossible;
	foreach my $i (@blacklist) {
		$impossible{$i} = 1;
	}

	my @pstate_stack;
	my %init_state = (
		pstate => TOPLEVEL
	);
	push @pstate_stack, \%init_state;
	my $in_typedef = 0;
	my %structures;
	my %enums;
	my @qcsapis;

	foreach my $line (split(/\n/)) {
		my $state = $pstate_stack[-1];
		my $pstate = $state->{pstate};
		my $pushstate = undef;
		my $pushstruct = "(anon)";
		my $parsed = 1;
		$line =~ s/^\s*(.*?)\s*$/$1/g;
		print "state $pstate, depth $#pstate_stack line: '$line'\n" if $debug;
		if ($pstate == TOPLEVEL) {
			if ($line =~ /^typedef\s+/) {
				$in_typedef = 1;
				$line =~ s/^\s*typedef\s+//;
			}
		} elsif (($pstate == POST_STRUCT) || ($pstate == POST_UNION)) {
			if ($line =~ /^\s*(\**\w+)\s*\;\s*$/) {
				$structures{$1}->{fields} = $state->{fields};
				unless ($structures{$1}->{canonical_name}) {
					$structures{$1}->{canonical_name} = $1;
				}
				if ($pstate == POST_UNION) {
					$structures{$1}->{struct_or_union} = "union";
				} else {
					$structures{$1}->{struct_or_union} = "struct";
				}
				pop @pstate_stack;
			} elsif ($line =~ /^;$/) {
				pop @pstate_stack;
			} else {
				$parsed = 0;
			}
		} elsif ($pstate == IN_ENUM) {
			if ($line =~ /.*}$/) {
			} elsif ($line =~ /^;$/) {
				$enums{$state->{struct_name}}++;
				pop @pstate_stack;
			} else {
				$parsed = 0;
			}
		} elsif ($pstate == IN_ANON_ENUM) {
			if ($line =~ /.*}$/) {
			} elsif ($line =~ /^(\w+)\s*;$/) {
				$enums{$1}++;
				pop @pstate_stack;
			} elsif ($line =~ /^;$/) {
				pop @pstate_stack;
			} else {
				$parsed = 0;
			}
		}


		if ($pstate == TOPLEVEL && $line =~ /^(\w+)\s+(qcsapi_\w+)\s*\((.*)\)\s*;$/) {
			push @qcsapis, $line;
		} elsif ($line =~ /^(.*\s+)\*?\s*(\w+)\s*\((.*)\)\s*;$/) {
			# non qcsapi function, ignore
		} elsif ($line =~ /^union\s+(\w+)\s+{/) {
			$pushstate = IN_UNION;
			$pushstruct = $1;
		} elsif ($line =~ /^union\s*{/) {
			$pushstate = IN_ANON_UNION;
		} elsif ($line =~ /^enum\s+(\w+)\s+{/) {
			$pushstate = IN_ENUM;
			$pushstruct = $1;
		} elsif ($line =~ /^enum\s*{/) {
			$pushstate = IN_ANON_ENUM;
		} elsif ($line =~ /^(const\s+)?struct\s+(\w+)\s*{$/) {
			$pushstate = IN_STRUCT;
			$pushstruct = $2;
			print "Parsing structure: $2\n" if $debug;
		} elsif ($in_typedef && $line =~ /^\s*struct\s*{\s*$/) {
			$pushstate = IN_ANON_STRUCT;
			print "Parsing anonymous structure\n" if $debug;
		} elsif ($pstate == TOPLEVEL && $in_typedef) {
			# 1 line typedef, ignore
			$in_typedef = 0;
		} elsif ($pstate == IN_STRUCT || $pstate == IN_ANON_STRUCT || $pstate == IN_UNION || $pstate == IN_ANON_UNION) {
			if ($line =~ /^\s*(.*\s+\**)\s*(\w+)\s*(\[.*?\])?\s*\;\s*$/) {
				my $type = $1;
				my $name = $2;
				my $arr = $3;
				my $field = {};
				$type =~ s/^\s*(.*?)\s*$/$1/g;
				$field->{type} = $type;
				$field->{name} = $name;
				$field->{is_input} = is_input_arg($type);
				if ($arr) {
					$field->{array} = $arr;
					$arr =~ s/^[^\d]*(.*?)[^\d]*$/$1/g;	# remove non number ends, "[2][3]" -> "2][3"
					my @array_lens = split(/[^\d]+/, $arr);	# lengths: (2, 3)
					$field->{array_lens} = \@array_lens;
				}
				push @{$state->{fields}}, $field;
				print "Struct $state->{struct_name}, field: '$name', type '$type'\n" if $debug;
			} elsif ($line =~ /^\s*}\s*$/) {
				if ($pstate == IN_UNION) {
					$state->{pstate} = POST_UNION;
				} else {
					$state->{pstate} = POST_STRUCT;
				}
				if ($pstate == IN_STRUCT || $pstate == IN_UNION) {
					$structures{$state->{struct_name}}->{fields} = $state->{fields};
					if ($pstate == IN_STRUCT) {
						$structures{$state->{struct_name}}->{struct_or_union} = "struct";
						$structures{$state->{struct_name}}->{canonical_name} = "struct $state->{struct_name}";
					} elsif ($pstate == IN_UNION) {
						$structures{$state->{struct_name}}->{struct_or_union} = "union";
						$structures{$state->{struct_name}}->{canonical_name} = "union $state->{struct_name}";
					}
				}
			} elsif ($line =~ /^\w+\s+\(\s*\*\s*\w+\s*\)\s*\(.*?\)\s*\;\s*$/) {
				# can't parse function pointers, don't bother. These cannot be serialized anyway
			} else {
				$parsed = 0;
			}
		}

		die "$0: Could not parse line: '$line', current state $pstate\n" unless $parsed;

		if ($pushstate) {
			my %newstate = (
				pstate => $pushstate,
				struct_name => $pushstruct,
			);
			push @pstate_stack, \%newstate;
		}
	}

	foreach my $s (sort keys %structures) {
		print "Parsed structure '$s'. Fields:\n" if $debug;
		foreach my $fr (@{$structures{$s}->{fields}}) {
			print "\tField: '$fr->{name}', type '$fr->{type}'\n" if $debug;
			if ($debug && defined($fr->{array})) {
				print "\tArray lengths: ";
				foreach my $len (@{$fr->{array_lens}}) {
					print "[$len]";
				}
				print "\n";
			}
		}
	}

	foreach my $e (sort keys %enums) {
		print "Found enum: $e\n" if $debug;
		$input_type_map{"$e"} = [ENUM_TYPE, 'int'];
		$input_type_map{"const $e"} = [ENUM_TYPE, 'int'];
		$output_type_map{"$e *"} = [ENUM_TYPE, 'int *'];
	}

	foreach (@qcsapis) {
		/^(\w+)\s+(qcsapi_\w+)\s*\((.*)\)\s*;$/;
		my $api_name = $2;
		my $api_args = $3;
		my $return_type = $1;
		my @args = split(/\,/, $api_args);

		for (my $i = 0; $i <= $#args; $i++) {
			my $arg = $args[$i];
			$arg =~ s/^\s*(.*?)\s*$/$1/g;	# remove space
			$arg =~ s/(\*)\s*([0-9a-zA-Z_]+)/$1 $2/g;	# single space to separate arg name
			$arg =~ s/\s+/ /g;		# all spaces are single space
			$args[$i] = $arg;
		}
		if ($impossible{$api_name}) {
			add_stub($api_name, $return_type, \@args);
		} else {
			add_func($api_name, $api_args, $return_type, \@args, \%structures);
		}
	}

	structure_define(\%structures);
}

sub show_error_msg()
{
	my ($msg) = @_;

	$error_cnt++;
	print "$my_name: $msg";
}

sub parse_qcsapi_rpc_config()
{
	my $locate_beginning = 0;
	my $locate_ending = 0;
	my $procedure_id = 0;
	my $api_name;
	my $api_args;
	my $cnt = 0;

	open (CONFIG_FD, "$config_file") || die "failed to open configuration file $config_file";

	while (my $line = <CONFIG_FD>) {
		$cnt++;
		if ($locate_beginning eq 0) {
			if ($line =~ /^\<procedure_id_map\>\s+$/) {
				$locate_beginning = 1;
			}
		} elsif ($locate_ending eq 0) {
			if ($line =~ /^\s+(\d+)\s+int\s+(\w+)\((.+)\);\s+$/) {
				$procedure_id = $1;
				$api_name = $2;
				$api_args = $3;
				$api_args =~ s/\s*void\s*//g;	# remove 'void' only args

				# sanity check
				if (defined($procedure_id_map{$api_name})) {
					&show_error_msg("Two procedure IDs for QCSAPI $api_name\n");
				} elsif (defined($procedure_id_map{$procedure_id})) {
					&show_error_msg("Procedure ID $procedure_id is assigned to $api_name" .
						" and $procedure_id_map{$procedure_id}\n");
				} elsif ($procedure_id < 1 || $procedure_id >= (2 ** 32)) {
					&show_error_msg("Invalid procedure ID $procedure_id " .
						"for QCSAPI $api_name\n");
				}

				$procedure_id_map{$api_name} = $procedure_id;
				$procedure_id_map{$procedure_id} = $api_name;
				$procedure_args{$api_name} = $api_args;
			} elsif ($line =~ /^\<\/procedure_id_map\>\s+$/) {
				$locate_ending = 1;
			} elsif ($line !~ /^\s*#/ && $line !~/^\s*$/) {
				&show_error_msg("Cannot parse line $cnt: $line");
			}
		}

		if ($locate_ending eq 1) {
			last;
		}
	}

	close CONFIG_FD;
}

sub show_usage()
{
	print "Usage:\n";
	print "   $0 <qcsapi_head_file> <configuration file>\n";
}

sub parse_arguments()
{
	my ($argv) = @_;
	my @argv_array = @{$argv};

	if (scalar(@argv_array) < 2) {
		show_usage();
		die;
	}

	$qcsapi_header_file = $argv_array[0];
	$qcsapi_header_file_basename = basename($qcsapi_header_file);
	$config_file = $argv_array[1];
	$config_file_basename = basename($config_file);
}
