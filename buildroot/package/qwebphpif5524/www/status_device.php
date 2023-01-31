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
function reload()
{
	window.location.href="status_device.php";
}
</script>

<?php
$curr_mode=exec("get_qfdr_running_mode");
function read_uptime()
{
	$info=exec("uptime");
	$arraylist=split(",",$info);
	$arraylist=split(" ",$arraylist[0]);
	$res=$arraylist[3].$arraylist[4];
	return $res;
}

function read_mode()
{
	$info=exec("get_qfdr_running_mode");
	if((strpos($info, "API error") === FALSE))
	{
		if($info=="Station")
		{
			$res="[&nbsp;] Access Point (AP)&nbsp;&nbsp;<a style=\"font-weight:bold\">[X] Extender (EXT) </a>";
		}
		else
		{
			$res="<a style=\"font-weight:bold\">[X] Access Point (AP)</a>&nbsp;&nbsp;[&nbsp;] Extender (EXT) ";
		}
	}
	else
	{$res="";}
	return $res;
}
function read_mode24()
{
	$res="<a style=\"font-weight:bold\">[X] Access Point</a>";
	return $res;
}

?>
<body class="body" onload="init_menu();">
	<div class="top">
		<a class="logo" href="./status_device.php">
			<img src="./images/logo.png"/>
		</a>
	</div>
<div class="container">
	<div class="left">
		<script type="text/javascript">
			createMenu('<?php $tmp=exec("get_qfdr_running_mode"); echo $tmp;?>','<?php $tmp=exec("qweconfig get mode.wlan1"); echo $tmp;?>',privilege);
		</script>
	</div>
	<div class="right">
		<div class="righttop">STATUS - DEVICE</div>
		<div class="rightmain">
			<table class="tablemain">
				<tr>
					<td width="40%">Device Name:</td>
					<td width="60%">Quantenna Wireless Adapter</td>
				</tr>
				<tr>
					<td>Software Version:</td>
					<td><?php $tmp = exec("call_qcsapi get_firmware_version"); echo $tmp;?></td>
				</tr>
				<tr>
					<td>Uptime:</td>
					<td><?php $tmp = read_uptime(); echo $tmp;?></td>
				</tr>
				<tr>
					<td class="divline" colspan="2";></td>
				</tr>
				<tr>
					<td>5G WI-FI Mode:</td>
					<td><?php $tmp = read_mode(); echo $tmp;?></td>
				</tr>
				<tr>
					<td>2.4G WI-FI Mode:</td>
					<td><?php $tmp = read_mode24(); echo $tmp;?></td>
				</tr>
				<tr>
					<td class="divline" colspan="2";></td>
				</tr>
			</table>
			<div class="rightbottom">
				<button name="btn_refresh" id="btn_refresh" type="button" onclick="reload();" class="button">Refresh</button>
			</div>
		</div>
	</div>
</div>
<div class="bottom">
	<a href="help/aboutus.php">About Quantenna</a> |  <a href="help/contactus.php">Contact Us</a> | <a href="help/privacypolicy.php">Privacy Policy</a> | <a href="help/terms.php">Terms of Use</a> <br />
	<div>&copy; 2013 Quantenna Communications, Inc. All Rights Reserved.</div>
</div>
</body>
</html>

