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
<script language="javascript" type="text/javascript" src="./js/cookiecontrol.js"></script>
<script language="javascript" type="text/javascript" src="./js/menu.js"></script>
<script language="javascript" type="text/javascript" src="./js/webif.js"></script>
<?php
include("common.php");
$privilege = get_privilege(2);
?>

<script type="text/javascript">
var privilege="<?php echo $privilege; ?>";
</script>

<?php
$curr_mode=exec("get_qfdr_running_mode");
if($curr_mode!="Station")
{
	echo "<script langauge=\"javascript\">alert(\"Only support in the Extender mode.\");</script>";
	echo "<script language='javascript'>location.href='status_device.php'</script>";
	return;
}

$chk=0;
$ssid="";
$proto="open";
$psk="";

//=================Load Value======================
function getValue()
{
	global $chk,$ssid,$proto,$psk;

	$mode=exec("call_qcsapi get_qfdr_param 5g_ap_mode");
	$ssid=exec("call_qcsapi get_qfdr_param 5g_ap_ssid");
	$proto=exec("call_qcsapi get_qfdr_param 5g_ap_security");
	$psk=exec("call_qcsapi get_qfdr_param 5g_ap_wpakey");

	if ($mode == "fixed")
		$chk=1;
	else
		$chk=0;
}
//=====================================================
//========================Save Value===================
function setValue()
{
	global $chk,$ssid,$proto,$psk,$interface_id;
	if ($_POST['action'] == "1")
	{
		$change_flag=0;

		$new_chk = $_POST['chk_fixed'];
		$new_ssid = $_POST['txt_ssid'];
		$new_proto = $_POST['cmb_proto'];
		$new_psk = $_POST['txt_psk'];
		if ($new_chk=="on")
		{$new_chk="1";}
		else
		{$new_chk="0";}
		//Enable or disable mbss
		if ($new_chk != $chk)
		{
			$change_flag++;
			if ($new_chk == "1")
			{
				exec("call_qcsapi set_qfdr_param 5g_ap_mode fixed");
				if($new_ssid!=$ssid)
				{
					exec("call_qcsapi set_qfdr_param 5g_ap_ssid $new_ssid");
				}
				if($new_proto!=$proto)
				{
					exec("call_qcsapi set_qfdr_param 5g_ap_security $new_proto");
				}
				if($new_psk!=$psk)
				{
					exec("call_qcsapi set_qfdr_param 5g_ap_wpakey $new_psk");
				}
			}
			else
			{
				exec("call_qcsapi set_qfdr_param 5g_ap_mode clone");
			}
		}
		else//Only change configuration
		{
			if($new_ssid!=$ssid)
			{
				$change_flag++;
				exec("call_qcsapi set_qfdr_param 5g_ap_ssid $new_ssid");
			}
			if($new_proto!=$proto)
			{
				$change_flag++;
				exec("call_qcsapi set_qfdr_param 5g_ap_security $new_proto");
			}
			if($new_psk!=$psk)
			{
				$change_flag++;
				exec("call_qcsapi set_qfdr_param 5g_ap_wpakey $new_psk");
			}
				$change_flag++;
		}
		if ($change_flag>0)
		{
			exec("perform_cmd_on_remote \"qfdr_sync_config qfdr\"");
			exec("rebuild_qfdr_ap 5g");
		}
	}
}

//=====================================================
getValue();

if(isset($_POST['action']))
{
	setValue();
	getValue();
}
?>

<script type="text/javascript">

nonascii = /[^\x20-\x7E]/;
nonhex = /[^A-Fa-f0-9]/g;

function reload()
{
	var cmb_if = document.getElementById("chk_fixed");
	window.location.href="config_qfdr_ap.php?id="+cmb_if.checked;

}
function validate_psk()
{
        pw = document.getElementById("txt_psk");
        pw.value=pw.value.replace(/(\")/g, '\"');
        if (pw.value.length < 8 || pw.value.length > 64)
        {
                alert("Allowed Passphrase is 8 to 63 ASCII characters or 64 Hexadecimal digits");
                return false;
        }
        if ((nonascii.test(pw.value)))
        {
                alert("Allowed Passphrase is 8 to 63 ASCII characters or 64 Hexadecimal digits");
                return false;
        }
        if (pw.value.length == 64 && (nonhex.test(pw.value)))
        {
                alert("Allowed Passphrase is 8 to 63 ASCII characters or 64 Hexadecimal digits");
                return false;
        }

        return true;
}

function validate()
{
	//Validate SSID
	var ssid = document.getElementById("txt_ssid");
	ssid.value=ssid.value.replace(/(\")/g, '\"');

	if (ssid.value.length < 1 || ssid.value.length > 32)
	{
		alert("SSID must contain between 1 and 32 ASCII characters");
		return false;
	}

	if ((nonascii.test(ssid.value)))
	{
		alert("Only ASCII characters allowed in SSID");
		return false;
	}

	if ((ssid.value[0] == ' ') || (ssid.value[ssid.value.length - 1] == ' '))
	{
		alert("SPACE is not allowed at the start or end of the SSID");
		return false;
	}
	//Validate PSK\
	if (document.mainform.cmb_proto.selectedIndex > 0)
	{
		if (!validate_psk())
			return false;
	}
	var cmb_if = document.getElementById("chk_fixed");
	document.mainform.action="config_qfdr_ap.php?id="+cmb_if.checked;
	document.mainform.submit();
}

function modechange(obj)
{
	if (obj.name == "cmb_proto")
	{
		if (document.mainform.cmb_proto.selectedIndex > 0)
		{
			set_visible('tr_passphrase', true);
		}
		else
		{
			set_visible('tr_passphrase', false);
		}
	}
	if (obj.name == "chk_fixed")
	{
		if (document.mainform.chk_fixed.checked)
		{
			set_disabled('txt_ssid',false);
			set_disabled('cmb_proto',false);
			set_disabled('txt_psk',false);
		}
		else
		{
			set_disabled('txt_ssid',true);
			set_disabled('cmb_proto',true);
			set_disabled('txt_psk',true);
		}
	}
}

function onload_event()
{
	init_menu();
	var chk = "<?php echo $chk; ?>";
	var proto="<?php echo $proto; ?>";

	set_control_value('chk_fixed', chk, 'checkbox');
	set_control_value('txt_ssid', '<?php echo $ssid; ?>', 'text');
	set_control_value('cmb_proto', proto, 'combox');
	set_control_value('txt_psk', '<?php echo $psk; ?>', 'text');

	if (proto == "open")
	{
		set_visible('tr_passphrase', false);
	}
	if (chk == "0")
	{
		set_disabled('txt_ssid',true);
		set_disabled('cmb_proto',true);
		set_disabled('txt_psk',true);
	}
}

</script>

<body class="body" onload="onload_event();">
	<div class="top">
		<a class="logo" href="./status_device.php">
			<img src="./images/logo.png"/>
		</a>
	</div>
<form enctype="multipart/form-data" id="mainform" name="mainform" method="post">
<div class="container">
	<div class="left">
		<script type="text/javascript">
			createMenu('<?php $tmp=exec("get_qfdr_running_mode"); echo $tmp;?>','<?php $tmp=exec("qweconfig get mode.wlan1"); echo $tmp;?>',privilege);
		</script>
	</div>
	<div class="right">
		<div class="righttop">
			<p>QFDR AP Configuration</p>
		</div>
		<div class="rightmain">
			<table class="tablemain">
				<tr>
					<td>Fixed AP:</td>
					<td>
						<input name="chk_fixed" id="chk_fixed" type="checkbox"  class="checkbox" onchange="modechange(this);"/>
					</td>
				</tr>
				<tr>
					<td>SSID:</td>
					<td>
						<input name="txt_ssid" type="text" id="txt_ssid" class="textbox"/>
					</td>
				</tr>
				<tr>
					<td>Encryption:</br></td>
					<td>
						<select name="cmb_proto" class="combox" id="cmb_proto" onchange="modechange(this)">
							<option value="open"> NONE-OPEN </option>
							<option value="wpa2_psk_aes"> WPA2-AES </option>
							<option value="mixed"> WPA2 + WPA (mixed mode) </option>
						</select>
					</td>
				</tr>
				<tr id="tr_passphrase">
					<td>Passphrase:</br></td>
					<td>
						<input name="txt_psk" type="text" id="txt_psk" class="textbox"/>
					</td>
				</tr>
				<tr>
					<td class="divline" colspan="2";></td>
				</tr>
			</table>
			<div class="rightbottom">
				<button name="btn_save" id="btn_save" type="button" onclick="validate();"  class="button">Save</button>
				<button name="btn_cancel" id="btn_cancel" type="button" onclick="reload();"  class="button">Cancel</button>
			</div>
			<input id="action" name="action" type="hidden" value="1">
		</div>
	</div>
</div>
</form>
<div class="bottom">
	<a href="help/aboutus.php">About Quantenna</a> |  <a href="help/contactus.php">Contact Us</a> | <a href="help/privacypolicy.php">Privacy Policy</a> | <a href="help/terms.php">Terms of Use</a> | <a href="help/h_mbss.php">Help</a><br />
	<div>&copy; 2013 Quantenna Communications, Inc. All Rights Reserved.</div>
</div>

</body>
</html>
