#!/usr/lib/cgi-bin/php-cgi

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="en" xml:lang="en">
<head>
	<title>Quantenna Communications</title>
	<link rel="stylesheet" type="text/css" href="./themes/style.css" media="screen" />

	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta http-equiv="expires" content="0" />
	<meta http-equiv="CACHE-CONTROL" content="no-cache" />
</head>
<script language="javascript" type="text/javascript" src="./js/menu.js"></script>
<script language="javascript" type="text/javascript" src="./js/webif.js"></script>
<?php
include("common.php");
$privilege = get_privilege(1);

?>

<?php
$curr_mode=exec("call_qcsapi verify_repeater_mode");
if($curr_mode == 1)
    $curr_mode = "Repeater";
else
    $curr_mode = exec("call_qcsapi get_mode wifi0");
$curr_ipaddr="";
$curr_mask="";
$curr_gw="";
$curr_dns="";
$old_static="";
$static=2;//indicate the value of the setting, 0:DHCP, 1:Static IP, 2:the column "staticip" not exit
$dhcp_exit=2;
$is_pcie=exec("ifconfig | grep pcie") == ""? 0:1;
$curr_proxy_arp="";
$dns_arr_len=0;

function update_staticip($value)
{
	$contents = file_get_contents("/mnt/jffs2/wireless_conf.txt");
	parse_str(trim($contents));
	$old=$staticip;
	$old="staticip=".$old;
	$new="staticip=".$value;
	$contents = str_replace($old, $new, $contents);
	file_put_contents("/mnt/jffs2/wireless_conf.txt", $contents);
	if ( $value == 1 )
	{
		//If the dhcp client is still running, kill it
		$process_id = exec("ps | grep \"dhclient -4\" | grep -v \"grep\" | awk '{print $1}'");
		if($process_id != "")
		{
			exec("kill $process_id");
		}
	}
	else
	{
		exec("dhclient -4 br0 &");
	}
}

function update_staticip_add($value)
{
	$contents = file_get_contents("/mnt/jffs2/wireless_conf.txt");
	parse_str(trim($contents));
	$newstatic = "staticip=".$value."&";
	$contents = str_pad($contents, (strlen($newstatic)+strlen($contents)), $newstatic, STR_PAD_LEFT);
	file_put_contents("/mnt/jffs2/wireless_conf.txt", $contents);
	if ( $value == 1 )
	{
		//If the dhcp client is still running, kill it
		$process_id = exec("ps | grep \"dhclient -4\" | grep -v \"grep\" | awk '{print $1}'");
		if($process_id != "")
		{
			exec("kill $process_id");
		}
	}
	else
	{
		exec("dhclient -4 br0 &");
	}
}

function is_valid_ip($ip)
{
	if(!strcmp(long2ip(sprintf('%u',ip2long($ip))),$ip))
		return true;
	return false;
}

function load_value()
{
	global $curr_ipaddr,$curr_mask,$old_static,$static,$dhcp_exit, $curr_proxy_arp, $curr_gw, $curr_dns, $dns_arr_len;

	$curr_ipaddr=read_ipaddr();
	$curr_mask=read_netmask();
	$curr_gw=read_default_gw();
	$contents = file_get_contents("/mnt/jffs2/wireless_conf.txt");
	parse_str(trim($contents));
	$old_static=$staticip;
	//Check "statip" is available.
	if($old_static=="")
	{
		$dhcp_exit=0;
		$process_id = exec("ps | grep \"dhclient -4\" | grep -v \"grep\" | awk '{print $1}'");
		if($process_id == "")
		{
			$static=1;
		}
		else
		{
			$static=0;
		}
	}
	else
	{
		$dhcp_exit=1;
		$static=$old_static;
	}

	$curr_dns=trim(shell_exec("call_qcsapi get_ip_dns"));
	if(is_qcsapi_error($curr_dns) || ($curr_dns == ""))
	{
		$dns_arr_len = 0;
	}
	else
	{
		$curr_dns=explode("\n",$curr_dns);
		$dns_arr_len = count($curr_dns);
	}

	//Get Proxy ARP
	$curr_proxy_arp=trim(shell_exec("call_qcsapi get_proxy_arp wifi0"));
	if(is_qcsapi_error($curr_proxy_arp))
	{
		$curr_proxy_arp="";
	}
}

function set_value()
{
	global $curr_ipaddr,$curr_mask,$old_static,$static,$dhcp_exit, $curr_proxy_arp;

	$new_proxy_arp = $_POST['chk_proxy_arp'];
	$new_static=$_POST['ckb_staticip'];
	$count = $_POST['NumRows'];
	$chkbox_arr = $_POST['chk_box'];
	$chkbox_arr = explode(",", $chkbox_arr);

	$del_dns = $_POST['del_dns'];
	$add_dns = $_POST['add_dns'];


	$new_proxy_arp_esc = escapeshellarg($new_proxy_arp);

	if ($dhcp_exit==1)
	{
		if($old_static!=$new_static)
		{
			update_staticip($new_static);
		}
	}
	else
	{
		if (isset($_POST['ckb_staticip']))
		{
			update_staticip_add($new_static);
		}
	}

	if(isset($_POST['ipaddress']) || isset($_POST['netmask']))
	{
		$new_addr = escape_any_characters($_POST['ipaddress']);
		$new_mask = escape_any_characters($_POST['netmask']);
		$new_addr_esc = escapeshellarg($new_addr);
		$new_mask_esc = escapeshellarg($new_mask);

		$ret_val_ip = file_put_contents("/mnt/jffs2/ipaddr", $new_addr);
		$ret_val_mask = file_put_contents("/mnt/jffs2/netmask", $new_mask);

		if ($ret_val_ip > 0 && $ret_val_mask > 0)
		{
			$br0_ipaddr = read_br_ip();
			if($br0_ipaddr != "")
				exec("ifconfig br0 $new_addr_esc netmask $new_mask_esc");
			else
				exec("ifconfig eth1_0 $new_addr_esc netmask $new_mask_esc");
		}
	}

	if(isset($_POST['gateway']))
	{
		$new_gw = escape_any_characters($_POST['gateway']);
		$new_gw_esc = escapeshellarg($new_gw);

		if ($new_gw == "")
		{
			# deleting old gw
			exec("route del default");
			exec("rm /mnt/jffs2/gateway");
		}
		else
		{
			$ret_val_gw = file_put_contents("/mnt/jffs2/gateway", $new_gw);

			if ($ret_val_gw > 0)
			{
				exec("route del default");
				exec("route add default gw $new_gw_esc");
			}
		}
	}

	if ($add_dns == 1) {
		for($i = 0; $i < $count; $i++) {
			$add_val = $_POST['txtbox_dns'][$i];
			$add_val_esc = escapeshellarg($add_val);
			exec("call_qcsapi set_ip_dns add $add_val_esc");
		}
	}
	if ($del_dns == 1) {
		for($i = 0; $i <= $count; $i++) {
			if ($chkbox_arr[$i] == "true")
			{
				$del_val = $_POST['txtbox_dns'][$i];
				$del_val_esc = escapeshellarg($del_val);
				exec("call_qcsapi set_ip_dns del $del_val_esc");
			}
		}
	}

	if ($new_proxy_arp == "on")
	{
		$new_proxy_arp=1;
	}
	else
	{
		$new_proxy_arp=0;
	}

	//Set Proxy ARP
	if( $curr_mode == "Repeater"){
		if ($new_proxy_arp != $curr_proxy_arp)
		{
			exec("call_qcsapi set_proxy_arp wifi1 $new_proxy_arp");
		}
	}
	else{
		if ($new_proxy_arp != $curr_proxy_arp)
		{
			exec("call_qcsapi set_proxy_arp wifi0 $new_proxy_arp");
		}
	}
}

if(isset($_POST['action']))
{
	if (!(isset($_POST['csrf_token']) && $_POST['csrf_token'] === get_session_token())) {
		header('Location: login.php');
		exit();
	}
	load_value();
	set_value();
}
load_value()
?>

<script type="text/javascript">
var privilege="<?php echo $privilege; ?>";
var dns_arr = <?php echo '["' . implode('", "', $curr_dns) . '"]' ?>;
function reload()
{
	window.location.href="config_networking.php";
}

function checkIP(ipaddr, netmask){
	var pattern = /^\d{1,3}(\.\d{1,3}){3}$/;
	if (!pattern.exec(ipaddr) || !pattern.exec(netmask)) {
		return false;
	}

	var aryIP = ipaddr.split('.');
	var aryMask = netmask.split('.');
	var preMask = 255;
	var is_net_allzero = 1;
	var is_net_allone = 1;
	var is_host_allzero = 1;
	var is_host_allone = 1;

	if (parseInt(aryIP[0]) >= 224 || parseInt(aryIP[0]) == 127) {
		return false;
	}

	for(key in aryIP)
	{
		if (parseInt(aryIP[key]) > 255 || parseInt(aryIP[key])< 0) {
			return false;
		}

		var curMask = parseInt(aryMask[key]);
		if (curMask > 255 || curMask < 0 || (preMask < 255 && curMask > 0)) {
			//Invalid netmask, out of range
			return false;
		}

		if (curMask < 255 && ((255 - curMask) & (256 - curMask))) {
			//Invalid netmask, against the rule of continouse 1s and then 0s
			return false;
		}
		preMask = curMask;

		if (curMask > 0) {
			//check net address, all 0s or all 1s are invalid
			var netaddr = parseInt(aryIP[key]) & curMask;
			if (is_net_allzero > 0 && netaddr > 0) {
				is_net_allzero = 0;
			}

			if (is_net_allone > 0 && netaddr < curMask) {
				is_net_allone = 0;
			}
		}
		if (curMask < 255) {
			//check host address, all 0s or all 1s are invalid
			var hostaddr = parseInt(aryIP[key]) & (255 - curMask);
			if (is_host_allzero > 0 && hostaddr > 0) {
				is_host_allzero = 0;
			}

			if (is_host_allone > 0 && hostaddr < (255 - curMask)) {
				is_host_allone = 0;
			}
		}
	}

	return !(is_net_allzero + is_net_allone + is_host_allzero + is_host_allone);
}

function validate()
{
	var res = document.getElementById("result");
	var newIP = document.getElementById("ipaddress");
	var newMask = document.getElementById("netmask");
	var gw = document.getElementById("gateway");

	if(!checkIP(newIP.value, newMask.value)) {
		res.innerHTML="Invalid IP address or netmask!";
		res.style.visibility="visible";
		return;
	}
	if((gw.value != "") && (!checkIP(gw.value, newMask.value))) {
		res.innerHTML="Invalid Gateway IP address";
		res.style.visibility="visible";
		return;
	}

	var tmp1=document.getElementById("action");
	if(tmp1.value==1) {
		res.innerHTML="Please login with the new IP address.";
		res.style.visibility="visible";
	}
	document.mainform.submit();
}

function addDnsRow(tableID)
{
	set_visible('oui_table', true);
	var oui_value = document.getElementById("txt_oui");
	document.getElementById("add_dns").value = 1;
	var table = document.getElementById(tableID);

        var rowCount = table.rows.length;
        var row = table.insertRow(rowCount);

        var cell1 = row.insertCell(0);
        var element1 = document.createElement("input");
        element1.type = "checkbox";
        element1.name="chkbox[]";
        cell1.appendChild(element1);

	var cell2 = row.insertCell(1);
	var element2 = document.createElement("input");
	element2.type="text";
	element2.name="txtbox_dns[]";
	element2.value=oui_value.value;
	element2.readOnly = true;
	cell2.appendChild(element2);

	document.getElementById("NumRows").value = rowCount;
	document.getElementById("txt_oui").value="";

	set_visible('tr_warning', true);
}

function deleteDnsRow(tableID)
{
	var chk_box_arr = new Array();
        var table = document.getElementById(tableID);
        var rowCount = table.rows.length;
	var checkCount = 0;
	document.getElementById("del_dns").value = 1;

        for(var i=1; i<rowCount; i++) {
		var row = table.rows[i];
                var chkbox = row.cells[0].childNodes[0];
		chk_box_arr[i-1]=chkbox.checked
	}

	document.getElementById("chk_box").value = chk_box_arr;
	document.getElementById("NumRows").value = rowCount - 1;

	for(var i=1; i<rowCount; i++) {
		var row = table.rows[i];
		var chkbox = row.cells[0].childNodes[0];
		if(null != chkbox && true == chkbox.checked) {
			checkCount++;
			table.rows[i].style.display = 'none';
		}
	}
	if (checkCount == 0)
	{
		alert("select dns consortium to delete");
	}
	else
	{
		set_visible('tr_warning', true);
	}
}

function modechange(obj)
{
	var tmp=document.getElementById("ipaddress");
	var tmp1=document.getElementById("action");
	if (obj.name == "ckb_staticip")
	{
		if(obj.value==0)
		{
			set_disabled("ipaddress",true);
			set_disabled("netmask",true);
			set_disabled("gateway",true);
			tmp1.value=0;
		}
		else if (obj.value==1)
		{
			tmp1.value=1;
			set_disabled("ipaddress",false);
			set_disabled("netmask",false);
			set_disabled("gateway",false);
		}
	}
}

function populate_dns(curr_oui)
{
	var table = document.getElementById("oui_table");

	var rowCount = table.rows.length;
        var row = table.insertRow(rowCount);

        var cell1 = row.insertCell(0);
        var element1 = document.createElement("input");
        element1.type = "checkbox";
        element1.name = "chkbox[]";
        cell1.appendChild(element1);

        var cell2 = row.insertCell(1);
        var element2 = document.createElement("input");
        element2.type="text";
        element2.name="txtbox_dns[]";
        element2.value=curr_oui;
        element2.readOnly = true;
        cell2.appendChild(element2);
}

function onload_event()
{
	var dns_arr_len = "<?php echo $dns_arr_len; ?>";

	init_menu();


	if (dns_arr_len == 0)
	{
		set_visible('oui_table', false);
	}
	else
	{
		for( var i=0; i<dns_arr_len; i++) {
			populate_dns(dns_arr[i]);
		}
	}

	set_visible('tr_warning', false);
}
</script>

<body class="body" onload="onload_event();">
	<div class="top">
		<a class="logo" href="./status_device.php">
			<img src="./images/logo.png"/>
		</a>
	</div>
<form enctype="multipart/form-data" action="config_networking.php" id="mainform" name="mainform" method="post">
<div class="container">
		<div class="left">
			<script type="text/javascript">
				createMenu('<?php echo $curr_mode;?>',privilege);
			</script>
		</div>
	<div style="width:800px;">
		<div class="right">
			<div class="righttop">CONFIG - NETWORKING</div>
			<div class="rightmain">
				<table class="tablemain">
					<tr>
						<td width="35%"></td>
						<td width="65%">DHCP:<input name="ckb_staticip" type="radio" value="0" <?php if($static==0) echo "checked=\"checked\""?>onclick="modechange(this);"/>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Static IP:<input name="ckb_staticip" type="radio" value="1" <?php if($static==1) echo "checked=\"checked\""?>onclick="modechange(this);"/>
						<input id="action" name="action" type="hidden" <?php if($static==0) echo "value=\"0\"";else echo "value=\"1\"";?>>
						</td>
					</tr>
					<tr>
						<td width="35%">IP Address:</td>
						<td width="65%">
							<input name="ipaddress" type="text" id="ipaddress" value="<?php echo $curr_ipaddr; ?>" class="textbox" <?php if($static==0) echo "disabled=\"disabled\""?>/>
						</td>
					</tr>
					<tr>
					<td>Netmask:</td>
						<td>
							<input name="netmask" type="text" id="netmask" value="<?php echo $curr_mask; ?>" class="textbox" <?php if($static==0) echo "disabled=\"disabled\""?>/>
						</td>
					</tr>
					<tr>
					<td>Gateway:</td>
						<td>
							<input name="gateway" type="text" id="gateway" value="<?php echo $curr_gw; ?>" class="textbox" <?php if($static==0) echo "disabled=\"disabled\""?>/>
						</td>
					</tr>
					<tr <?php if($is_pcie == 1) echo "style=\"display: none;\""; ?>>
						<td>Ethernet0 MAC Address:</td>
						<td>
							<input name="txt_ethernetmac" type="text" id="txt_ethernetmac" value="<?php $tmp = read_emac_addr();echo $tmp; ?>" class="textbox" disabled="disabled"/>
						</td>
					</tr>
					<tr <?php if($is_pcie == 1) echo "style=\"display: none;\""; ?>>
						<td>Ethernet1 MAC Address:</td>
						<td>
							<input name="txt_ethernetmac" type="text" id="txt_ethernetmac" value="<?php
							$tmp = exec("call_qcsapi get_mac_addr eth1_1");
							if((strpos($tmp, "API error") === FALSE))
							{
								echo $tmp;
							} else {
								echo "";
							}
							?>" class="textbox" disabled="disabled"/>
						</td>
					</tr>
					<tr <?php if($is_pcie == 0) echo "style=\"display: none;\""; ?>>
						<td>PCIE MAC Address:</td>
						<td>
							<input name="txt_pciemac" type="text" id="txt_pciemac" value="<?php $tmp = exec("call_qcsapi get_mac_addr pcie0");echo $tmp; ?>" class="textbox" disabled="disabled"/>
						</td>
					</tr>
					<tr>
						<td>Wireless MAC Address:</td>
						<td>
							<input name="txt_wirelessmac" type="text" id="txt_wirelessmac" value="<?php $tmp = read_wmac_addr();echo $tmp; ?>" class="textbox" disabled="disabled"/>
						</td>
					</tr>
					<tr>
						<td>BSSID:</td>
						<td><input name="txt_bssid" type="text" id="txt_bssid" value="<?php $tmp=exec("call_qcsapi get_bssid wifi0");echo $tmp;?>" class="textbox" disabled="disabled"/></td>
					</tr>
					<tr>
						<td class="divline" colspan="2";></td>
					</tr>
					<tr id="tr_proxy_arp">
						<td colspan="4";> Proxy ARP:&nbsp;&nbsp;
						<input name="chk_proxy_arp" id="chk_proxy_arp" type="checkbox"  class="checkbox" <?php if($curr_proxy_arp==1) echo "checked=\"checked\""?>/>
						</td>
					</tr>
					<tr>
						<td class="divline" colspan="2";></td>
					</tr>
				</table>

				<table class="tablemain">
					<tr id="tr_oui">
						<td>DNS server:</td>
						<td>
							<input name="txt_oui" type="text" id="txt_oui" class="textbox"/>
						</td>
						<td><button name="btn_dns_add" id="btn_dns_add" type="button" onclick="addDnsRow('oui_table');" class="button" style="width:60px;">ADD</button></td>
						<td><button name="btn_dns_del" id="btn_dns_del" type="button" onclick="deleteDnsRow('oui_table');" class="button" style="width:80px;">REMOVE</button></td>

					<table id="oui_table" width="350px" border="1">
						<td width="20%">option</td>
						<td width="20%">DNS Server list</td>
					</table>

					<input name="NumRows" id="NumRows" type="hidden"/>
					<input name="chk_box" id="chk_box" type="hidden"/>
					<input name="add_dns" id="add_dns" type="hidden"/>
					<input name="del_dns" id="del_dns" type="hidden"/>
					</tr>
				</table>
				<table class="tablemain">
					<tr id="tr_warning">
						<td colspan="2"; style="color:red; font-size:smaller;">*To apply the changes, click save button*</td>
					</tr>
					<tr>
						<td class="divline" colspan="2";></td>
					</tr>
				</table>
				<div id="result" style="visibility:hidden; text-align:left; margin-left:20px; margin-top:20px; font:16px Calibri, Candara, corbel, "Franklin Gothic Book";">
				</div>
				<div class="rightbottom">
					<button name="btn_save" id="btn_save" type="button" onclick="validate();"  class="button">Save</button>
					<button name="btn_cancel" id="btn_cancel" type="button" onclick="reload();"  class="button">Cancel</button>
				</div>
			</div>
		</div>
	</div>
</div>
<input type="hidden" name="csrf_token" value="<?php echo get_session_token(); ?>" />
</form>
<div class="bottom">
	<a href="help/aboutus.php">About Quantenna</a> |  <a href="help/contactus.php">Contact Us</a> | <a href="help/privacypolicy.php">Privacy Policy</a> | <a href="help/terms.php">Terms of Use</a> | <a href="help/h_networking.php">Help</a><br />
	<div><?php echo $str_copy ?></div>
</div>

</body>
</html>

