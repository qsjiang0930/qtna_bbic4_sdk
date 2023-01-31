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
$privilege = get_privilege(2);

?>


<script type="text/javascript">
var privilege="<?php echo $privilege; ?>";
function reload()
{
	window.location.href="status_wds.php";
}
</script>

<?php
$curr_mode=exec("call_qcsapi get_mode wifi0");
$curr_region=trim(shell_exec("call_qcsapi get_regulatory_region wifi0"));
if (strcmp($curr_mode, "Access point" ) == 0)
{
	confirm("This page is only for the Station Mode.");
	echo "<script language='javascript'>location.href='status_device.php'</script>";
}
?>

<script type="text/javascript">
var nonascii = /[^\x20-\x7E]/;
var nonhex = /[^A-Fa-f0-9]/g;
var curr_region = "<?php echo $curr_region; ?>";
function populate_sta_encryptionlist(sta_pmf_value)
{
	if (sta_pmf_value != "0") {
		cmb_sta_encryption.options.length = 5;
		cmb_sta_encryption.options[0].text = "NONE-OPEN"; cmb_sta_encryption.options[0].value = "NONE";
		cmb_sta_encryption.options[1].text = "WPA2-AES-SHA256 Mixed"; cmb_sta_encryption.options[1].value = "11i_pmf";
		cmb_sta_encryption.options[2].text = "SAE"; cmb_sta_encryption.options[2].value = "SAE";
		cmb_sta_encryption.options[3].text = "SAE + WPA2 (mixed mode)"; cmb_sta_encryption.options[3].value = "SAE-WPA-PSK";
		cmb_sta_encryption.options[4].text = "OWE"; cmb_sta_encryption.options[4].value = "OWE";
	}
	else {
		cmb_sta_encryption.options.length = 2;
		cmb_sta_encryption.options[0].text = "NONE-OPEN"; cmb_sta_encryption.options[0].value = "NONE";
		cmb_sta_encryption.options[1].text = "WPA2-AES"; cmb_sta_encryption.options[1].value = "11i";
		if (curr_region != "us")
		{
			cmb_sta_encryption.options.length = 3;
			cmb_sta_encryption.options[2].text = "WPA2 + WPA (mixed mode)"; cmb_sta_encryption.options[2].value = "WPAand11i";
		}
	}
	document.getElementById("cmb_sta_encryption").value = "NONE";
//	set_control_value("cmb_sta_encryption", "NONE", "combox");
}

function click_ap(ssid,security)
{
	var txt_sta_ssid = document.getElementById("txt_sta_ssid");
	var cmb_sta_encryption = document.getElementById("cmb_sta_encryption");
	var cmb_sta_pmf = document.getElementById("cmb_sta_pmf");
	var txt_sta_passphrase = document.getElementById("txt_sta_passphrase");
	var tr_sta_passphrase = document.getElementById("tr_sta_passphrase");
	var tr_sta_owegroup = document.getElementById("tr_sta_owegroup");
	var tr_sta_saegroup = document.getElementById("tr_sta_saegroup");
	txt_sta_ssid.value = ssid;
	cmb_sta_pmf.value = "0";
	txt_sta_passphrase.value = "";
	tr_sta_passphrase.style.display = "none";
	tr_sta_owegroup.style.display = "none";
	tr_sta_saegroup.style.display = "none";
	cmb_sta_encryption.value = "NONE";
	populate_sta_encryptionlist("0");
}

function validate_sta_psk()
{
	var encryption = document.getElementById("cmb_sta_encryption").value;
	pw = document.getElementById("txt_sta_passphrase");
	pw.value=pw.value.replace(/(\")/g, '\"');
	var t = document.getElementById("sta_is_psk");
	t.value = -1;
	if ((pw.value.length < 8 && pw.value.length >= 0) || pw.value.length > 64)
	{
		if(encryption != "SAE-WPA-PSK") {
			alert("Allowed Passphrase is 8 to 63 ASCII characters or 64 Hexadecimal digits");
		}
		else {
			alert("Allowed Passphrase is 8 to 63 ASCII characters");
		}
		return false;
	}
	if(pw.value.length == 64 && encryption == "SAE-WPA-PSK") {
		alert("Allowed Passphrase is 8 to 63 ASCII characters");
		return false;
	}
	if ((nonascii.test(pw.value)))
	{
		if(encryption != "SAE-WPA-PSK") {
			alert("Allowed Passphrase is 8 to 63 ASCII characters or 64 Hexadecimal digits");
		}
		else {
			alert("Allowed Passphrase is 8 to 63 ASCII characters");
		}
		return false;
	}
	if (pw.value.length == 64 && (nonhex.test(pw.value)) && encryption != "SAE-WPA-PSK")
	{
		alert("Allowed Passphrase is 8 to 63 ASCII characters or 64 Hexadecimal digits");
		return false;
	}

	if (pw.value.length == 64)
	{
		t.value = 1;
	}
	else
	{
		t.value = 0;
	}

	return true;
}

function connect()
{
	var sta_ssid = document.getElementById("txt_sta_ssid");
	var cmb_sta_encryption_value = document.mainform.cmb_sta_encryption.value;
	if (sta_ssid.value.length > 32 || sta_ssid.value.length < 1)
	{
		alert("SSID must contain between 1 and 32 ASCII characters");
		return false;
	}

	if ((nonascii.test(sta_ssid.value)))
	{
		alert("Only ASCII characters allowed in SSID");
		return false;
	}

	if ((sta_ssid.value[0] == ' ') || (sta_ssid.value[sta_ssid.value.length - 1] == ' '))
	{
		alert("SPACE is not allowed at the start or end of the SSID");
		return false;
	}
	/* Validate Passphrase */
	if (cmb_sta_encryption_value == "11i_pmf" || cmb_sta_encryption_value == "SAE" || cmb_sta_encryption_value == "SAE-WPA-PSK" || cmb_sta_encryption_value == "11i" || cmb_sta_encryption_value == "WPAand11i")
	{
		if (!validate_sta_psk())
			return false;
	}
	document.getElementById("action").value = 1;
	document.getElementById("txt_sta_ssid").disabled=false;
	document.mainform.submit();
}

function rescan()
{
	document.getElementById("action").value = 0;
	document.mainform.submit();
}

function modechange(obj) {
	if(obj.name == 'cmb_sta_pmf')
	{
		var cmb_sta_pmf = document.getElementById("cmb_sta_pmf");
		populate_sta_encryptionlist(cmb_sta_pmf.value);
	}
	else if(obj.name == 'cmb_sta_encryption')
	{
		var sta_proto = document.mainform.cmb_sta_encryption.value;
		set_visible('tr_sta_passphrase', true);
		set_visible('tr_sta_saegroup', false);
		set_visible('tr_sta_owegroup', false);
		if (sta_proto == "NONE" || sta_proto == "" || sta_proto == "OWE") {
			set_visible('tr_sta_passphrase', false);
		}
		if (sta_proto == "SAE" || sta_proto == "SAE-WPA-PSK") {
			set_visible('tr_sta_saegroup', true);
		}
		if (sta_proto == "OWE") {
			set_visible('tr_sta_owegroup', true);
		}
	}
}

function onload_event() {
	populate_sta_encryptionlist("0");
}
</script>

<?php
$curr_ssid="";
$curr_networkid=0;
$supplicant_file = "/mnt/jffs2/wpa_supplicant.conf";

function find_enabled_ssid(&$ssid, &$network_id)
{
	$file_path="/mnt/jffs2/wpa_supplicant.conf";
	$fp = fopen($file_path, 'r');
	$done = 0;
	$network_found = 0;
	$ssid_match = 0;
	$ssid = "";
	$network_id = -1;
	$disabled = 0;
	while(!feof($fp))
	{
		$buffer = stream_get_line($fp, 100, "\n");
		$token = trim(strtok($buffer, '='));
		//ignore comments
		if($token && substr($token, 0) == '#') continue;
		while($token)
		{
			if((strcmp($token, "ssid") == 0) && ($network_found == 1))
			{
				$token = trim(strtok('='));
				$ssid = $token;
				$network_id++;
				$ssid_match = 1;
				break;
			}
			if(strcmp($token, "network") == 0)
			{
				$network_found = 1;
				break;
			}
			if((strcmp($token, "}") == 0) && ($network_found == 1))
			{
				if($disabled != 1)
				{
					$done = 1;
				}
				else
				{
					$disabled = 0;
				}
				$network_found = 0;
				$ssid_match = 0;
				break;
			}
			if((strcmp($token, "disabled") == 0) && $ssid_match == 1)
			{
				$disabled = 1;
				break;
			}
			$token = trim(strtok('='));
		}
		if($done == 1) break;
	}
	fclose($fp);
	$ssid = substr($ssid, 1, strlen($ssid) - 2);
	//if($done != 1) //no network block was enabled -enable the last one
	// or if there are later blocks that are not disabled - select the network that is returned
	/*
		error = 0 (no probms)
		error = -1 (no ssid match)
		error = -2 (ssid found but no such param)
	*/
	$error = ($done == 1)? 0: (($ssid_match == 1)? -2: -1);
	return $error;
}

function disable_rest($file_path, $ssid)
{
	$fp = fopen($file_path, 'r');
	$network_found = 0;
	$ssid_match = 0;
	$ret_val = -1; //ssid not found, enabling the last network
	$supp_contents = "";
	$disable_found = 0;
	$network_id = -1;
	while(!feof($fp))
	{
		$buffer = stream_get_line($fp, 100, "\n");
		$token = trim(strtok($buffer, '='));
		//ignore comments
		if($token && substr($token, 0) == '#') continue;
		while($token)
		{
			if((strcmp($token, "ssid") == 0) && ($network_found == 1))
			{
				$token = trim(strtok('='));
				$network_id++;
				if(strcmp("\"$ssid\"", $token) == 0)
					{ $ssid_match = 1; $ret_val = 1; }
				break;
			}
			if(strcmp($token, "network") == 0)
			{
				$network_found = 1;
				break;
			}
			if((strcmp($token, "}") == 0) && ($network_found == 1))
			{
				if($ssid_match == 0 && $disable_found == 0)
					$buffer = "\tdisabled=1\n}";
				$network_found = 0;
				$ssid_match = 0;
				$disable_found = 0;
				break;
			}
			if((strcmp($token, "disabled") == 0))
			{
				if($ssid_match == 1)
				{
					//if the given ssid is disabled, remove the disabled parameter
					$buffer = "";
				}
				$disable_found = 1;
			}
			$token = trim(strtok('='));
		}
		if($buffer != "") $supp_contents .= "$buffer\n";
	}
	fclose($fp);
	file_put_contents($file_path, $supp_contents);
	return $ret_val;
}

function set_sta_proto($ssid_esc, $proto_esc)
{
	exec("sed -i 's/ctrl_interface=DIR=\/var\/run\/wpa_supplicant/ctrl_interface=\/var\/run\/wpa_supplicant/g' /mnt/jffs2/wpa_supplicant.conf");
	exec("wpa_cli reconfig > /dev/null 2>&1 &");

	if ($proto_esc == "NONE")
		exec("call_qcsapi SSID_set_authentication_mode wifi0 $ssid_esc NONE");
	elseif ($proto_esc == "11i")
	{
		exec("call_qcsapi SSID_set_authentication_mode wifi0 $ssid_esc PSKAuthentication");
		exec("call_qcsapi SSID_set_proto wifi0 $ssid_esc $proto_esc");
		exec("call_qcsapi SSID_set_encryption_modes wifi0 $ssid_esc AESEncryption");
	}
	elseif ($proto_esc == "11i_pmf")
	{
		exec("call_qcsapi SSID_set_authentication_mode wifi0 $ssid_esc SHA256PSKAuthenticationMixed");
		exec("call_qcsapi SSID_set_proto wifi0 $ssid_esc $proto_esc");
		exec("call_qcsapi SSID_set_encryption_modes wifi0 $ssid_esc AESEncryption");
	}
	elseif ($proto_esc == "WPAand11i")
	{
		exec("call_qcsapi SSID_set_authentication_mode wifi0 $ssid_esc PSKAuthentication");
		exec("call_qcsapi SSID_set_proto wifi0 $ssid_esc WPAand11i");
		exec("call_qcsapi SSID_set_encryption_modes wifi0 $ssid_esc TKIPandAESEncryption");
	}
	elseif ($proto_esc == "SAE")
	{
		exec("call_qcsapi SSID_set_authentication_mode wifi0 $ssid_esc SAEAuthentication");
		exec("call_qcsapi SSID_set_proto wifi0 $ssid_esc WPAand11i");
		exec("call_qcsapi SSID_set_encryption_modes wifi0 $ssid_esc AESEncryption");
	}
	elseif ($proto_esc == "SAE-WPA-PSK")
	{
		exec("call_qcsapi SSID_set_authentication_mode wifi0 $ssid_esc SAEandPSKAuthentication");
		exec("call_qcsapi SSID_set_proto wifi0 $ssid_esc WPAand11i");
		exec("call_qcsapi SSID_set_encryption_modes wifi0 $ssid_esc AESEncryption");
	}
	elseif ($proto_esc == "OWE")
	{
		exec("call_qcsapi SSID_set_authentication_mode wifi0 $ssid_esc OPENandOWEAuthentication");
	}
}

if (isset($_POST['action']))
{
	if (!(isset($_POST['csrf_token']) && $_POST['csrf_token'] === get_session_token())) {
		header('Location: login.php');
		exit();
	}
	if ($_POST['action']=="0")
	{
		exec("call_qcsapi start_scan wifi0");
		sleep(3);
	}
	else if ($_POST['action']=="1")
	{
		$p_ssid=$_POST['txt_sta_ssid'];
		$set_ssid=escape_any_characters($p_ssid);
		$set_pmf=$_POST['cmb_sta_pmf'];
		$set_encryption=$_POST['cmb_sta_encryption'];
		$p_pwd=$_POST['txt_sta_passphrase'];
		$set_pwd=escape_any_characters($p_pwd);
		$set_sta_is_psk=$_POST['sta_is_psk'];
		$set_sta_saegroups = $_POST['cmb_sta_saegroup'];
		$set_sta_owegroups = $_POST['cmb_sta_owegroup'];
		//check if the SSID info exist, if not create
		$tmp=exec("call_qcsapi verify_ssid wifi0 $set_ssid");
		if(!(strpos($tmp, "QCS API error") === false))
		{
			$tmp=exec("call_qcsapi create_ssid wifi0 $set_ssid");
		}
		exec("call_qcsapi SSID_set_pmf wifi0 $set_ssid $set_pmf");
		//Set Protocol
		set_sta_proto($set_ssid, $set_encryption);

		//Set Passphrase
		if($set_encryption != "NONE" && $set_encryption != "OWE") {
			if($set_sta_is_psk == 1)
				exec("call_qcsapi SSID_set_pre_shared_key wifi0 $set_ssid 0 $set_pwd");
			else
				exec("call_qcsapi SSID_set_key_passphrase wifi0 $set_ssid 0 $set_pwd");
		}

		if ($set_encryption == "SAE" || $set_encryption == "SAE-WPA-PSK") {
			exec("call_qcsapi SSID_set_params wifi0 $set_ssid sae_groups $set_sta_saegroups");
		}

		if ($set_encryption == "OWE") {
			exec("call_qcsapi SSID_set_params wifi0 $set_ssid owe_group $set_sta_owegroups");
		}
		exec("call_qcsapi associate wifi0 $set_ssid");
		//disable_rest($supplicant_file,$p_ssid);
		//exec("wpa_cli reconfigure");
	}
}
$curr_ssid = trim(shell_exec("call_qcsapi get_SSID wifi0"));
?>

<body class="body" onload="onload_event();">
	<div class="top">
		<a class="logo" href="./status_device.php">
			<img src="./images/logo.png"/>
		</a>
	</div>
<div style="border:6px solid #9FACB7; width:800px; background-color:#fff;">
	<div class="righttop">ACCESS POINT LIST</div>
	<form name="mainform" method="post" action="config_aplist.php">
	<div class="rightmain">
		Current SSID: <?php echo htmlspecialchars($curr_ssid)?>
		<table class="tablemain">
			<tr>
				<td width="10%" align="center" bgcolor="#96E0E2" ></td>
				<td width="30%" align="center" bgcolor="#96E0E2">SSID</td>
				<td width="30%" align="center" bgcolor="#96E0E2">Mac Address</td>
				<td width="10%" align="center" bgcolor="#96E0E2">Channel</td>
				<td width="10%" align="center" bgcolor="#96E0E2">RSSI</td>
				<td width="10%" align="center" bgcolor="#96E0E2">Security</td>
				</tr>
			<?php
				$count=exec("call_qcsapi get_results_AP_scan wifi0");
				for($i=0;$i<$count;$i++)
				{
					$index=$i+1;
					$res=exec("call_qcsapi get_properties_AP wifi0 $i");
					$lenth=strlen($res);
					$ssid_end=0;
					for($n=$lenth-1; $n>0; $n--)
					{
						$tmp=substr($res,$n,1);
						if($tmp=="\"")
						{
							$ssid_end = $n;
							$ssid=substr($res,1,$ssid_end-1);
							$tmp=substr($res,$ssid_end+2,$lenth-$ssid_end);
							break;
						}
					}
					$token = trim(strtok($tmp, " "));
					$mac=$token;

					$token = trim(strtok(" "));
					$channel=$token;

					$token = trim(strtok(" "));
					$rssi=$token;

					$token = trim(strtok(" "));
					$security=$token;

					$token = trim(strtok(" "));
					$protocol=$token;

					$token = trim(strtok(" "));
					$authentication =$token;

					$token = trim(strtok(" "));
					$encryption  =$token;

					$ssid_token=trim(strtok($ssid, "\""));
					if(hexdec($security) & 1)
					{
						$security="Yes";
					}
					else
					{
						$security="No";
					}
					$new_ssid = addslashes($ssid);
					echo "<tr onclick=\"click_ap('".htmlspecialchars($new_ssid)."')\">\n";
					echo "<td width=\"10%\" align=\"center\" >$index</td>\n";
					echo "<td width=\"30%\" align=\"center\" >".htmlspecialchars($ssid)."</td>\n";
					echo "<td width=\"15%\" align=\"center\" >$mac</td>\n";
					echo "<td width=\"15%\" align=\"center\" >$channel</td>\n";
					echo "<td width=\"15%\" align=\"center\" >$rssi</td>\n";
					echo "<td width=\"15%\" align=\"center\" >$security</td>\n";
					echo "</tr>\n";
				}
			?>
				<tr>
					<td class="divline" style="background:url(/images/divline.png);" colspan="6";></td>
				</tr>
				<tr>
					<td width="40%">
						SSID:
					</td>
					<td width="60%">
						<input type="text" id="txt_sta_ssid" name="txt_sta_ssid" class="textbox" value="" disabled/>
					</td>
				</tr>
				<tr>
					<td width="40%">
						PMF:
					</td>
					<td width="60%">
						<select name="cmb_sta_pmf" id="cmb_sta_pmf" class="combox" onchange="modechange(this)">
							<option value="0" selected>Disabled</option>
							<option value="1">Enabled</option>
							<option value="2">Required</option>
						</select>
					</td>
				</tr>
				<tr>
					<td width="40%">
						Encryption:
					</td>
					<td width="60%">
						<select id="cmb_sta_encryption" name="cmb_sta_encryption" class="combox" onchange="modechange(this)">
							<option value="NONE" selected>NONE-OPEN</option>
						</select>
					</td>
				</tr>
				<tr id="tr_sta_passphrase" style="display:none">
					<td width="40%">
						Passphrase:
					</td>
					<td width="60%">
						<input type="text" id="txt_sta_passphrase" name="txt_sta_passphrase" class="textbox" value=""/>
						<input type="hidden" id="sta_is_psk" name="sta_is_psk" />
					</td>
				</tr>
				<tr id="tr_sta_owegroup" style="display:none">
					<td width="40%">OWE Group:</td>
					<td width="60%">
						<select name="cmb_sta_owegroup" id="cmb_sta_owegroup" class="combox">
							<option value="19">Group 19</option>
							<option value="20">Group 20</option>
							<option value="21">Group 21</option>
						</select>
					</td>
				</tr>
				<tr id="tr_sta_saegroup" style="display:none">
					<td width="40%">SAE Group:</td>
					<td width="60%">
						<select name="cmb_sta_saegroup" id="cmb_sta_saegroup" class="combox">
							<option value="19">Group 19</option>
							<option value="20">Group 20</option>
							<option value="21">Group 21</option>
						</select>
					</td>
				</tr>
				<tr>
					<td colspan="6">
						<input type="hidden" id="action" name="action" />
						<button name="btn_assoc" id="btn_assoc" type="button" onclick="connect();"  class="button">Connect</button>
					</td>
				</tr>
				<tr>
					<td class="divline" style="background:url(/images/divline.png);" colspan="6";></td>
				</tr>
			</table>
			<div class="rightbottom">
				<button name="btn_rescan" id="btn_rescan" type="button" onclick="rescan();"  class="button">Rescan</button>
			</div>
		</div>
		<input type="hidden" name="csrf_token" value="<?php echo get_session_token(); ?>" />
		</form>
	</div>
<div class="bottom">
	<a href="help/aboutus.php">About Quantenna</a> |  <a href="help/contactus.php">Contact Us</a> | <a href="help/privacypolicy.php">Privacy Policy</a> | <a href="help/terms.php">Terms of Use</a> <br />
	<div><?php echo $str_copy ?></div>
</div>
</body>
</html>

