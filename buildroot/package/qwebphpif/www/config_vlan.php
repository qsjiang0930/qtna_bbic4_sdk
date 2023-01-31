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


<script language="javascript" type="text/javascript" src="./SpryAssets/SpryTabbedPanels.js"></script>
<script language="javascript" type="text/javascript" src="./js/menu.js"></script>
<script language="javascript" type="text/javascript" src="./js/webif.js"></script>
<?php
include("common.php");
$privilege = get_privilege(1);
?>


<script type="text/javascript">
var privilege="<?php echo $privilege; ?>";
</script>

<?php
$curr_mode=exec("call_qcsapi verify_repeater_mode");
if($curr_mode == 1)
    $curr_mode = "Repeater";
else
    $curr_mode = exec("call_qcsapi get_mode wifi0");
$vlan_enable=1;
$sum_active_interface= "";
$modeeth0="";
$modeeth1="";
$mode0="";
$mode1="";
$mode2="";
$mode3="";
$mode4="";
$mode5="";
$mode6="";
$mode7="";
$vlanideth0="";
$vlanideth1="";
$vlanid0="";
$vlanid1="";
$vlanid2="";
$vlanid3="";
$vlanid4="";
$vlanid5="";
$vlanid6="";
$vlanid7="";
$defaulteth0="";
$defaulteth1="";
$default0="";
$default1="";
$default2="";
$default3="";
$default4="";
$default5="";
$default6="";
$default7="";
$tageth0="";
$tageth1="";
$tag0="";
$tag1="";
$tag2="";
$tag3="";
$tag4="";
$tag5="";
$tag6="";
$tag7="";

function parse_vlan_conf($vlan_conf, &$vlan_option, &$mode, &$default_vlan, &$vlanid, &$tagid)
{

	if (strstr($vlan_conf[0], "VLAN disabled"))
	{
		$vlan_option=0;
	}
	else
	{
		if (strncmp($vlan_conf[0], "Access", 6) == 0)
		{
			sscanf($vlan_conf[0], "%s mode, VLAN %s", $mode, $vlanid);
			$default_vlan=1;
		}
		else if (strncmp($vlan_conf[0], "Trunk", 5) == 0)
		{
			sscanf($vlan_conf[0], "%s mode, default VLAN %d", $mode, $default_vlan);
			/* Skipping the line (Member of VLAN(s):) */
			sscanf($vlan_conf[2], "%s", $vlanid);

		}
		else if (strncmp($vlan_conf[0], "Hybrid", 6) == 0)
		{
			sscanf($vlan_conf[0], "%s mode, default VLAN %d", $mode, $default_vlan);
			/* Skipping the line (Member of VLAN(s):) */
			sscanf($vlan_conf[2], "%s", $vlanid);
			/* Skipping the line (Member of Tag(s):) */
			sscanf($vlan_conf[4], "%s", $tagid);
		}
	}
}

function get_value()
{
	global $curr_mode, $arr_interface, $sum_active_interface, $modeeth0, $modeeth1, $mode0, $mode1, $mode2, $mode3, $mode4, $mode5, $mode6, $mode7, $vlanideth0, $vlanideth1, $vlanid0, $vlanid1, $vlanid2, $vlanid3, $vlanid4, $vlanid5, $vlanid6, $vlanid7, $defaulteth0, $defaulteth1, $default0, $default1, $default2, $default3, $default4, $default5, $default6, $default7, $tageth0, $tageth1, $tag0, $tag1, $tag2, $tag3, $tag4, $tag5, $tag6, $tag7, $vlan_enable;

	$arr_interface="";
	if($curr_mode=="Repeater")
		$sum_active_interface= 2;
	else
		$sum_active_interface= 3;

	$arr_interface[0]="eth1_0";
	$result=shell_exec("call_qcsapi show_vlan_config eth1_0");
	/* Stroring as array in vlan_conf for multiple lines */
	$vlan_conf=explode("\n", $result);
	parse_vlan_conf($vlan_conf, $vlan_enable, $modeeth0, $defaulteth0, $vlanideth0, $tageth0);

	$arr_interface[1]="eth1_1";
	$result=shell_exec("call_qcsapi show_vlan_config eth1_1");
	$vlan_conf=explode("\n", $result);
	parse_vlan_conf($vlan_conf, $vlan_enable, $modeeth1, $defaulteth1, $vlanideth1, $tageth1);

	if($curr_mode!="Repeater"){
		$arr_interface[2]="wifi0";
		$result=shell_exec("call_qcsapi show_vlan_config wifi0");
		$vlan_conf=explode("\n", $result);
		parse_vlan_conf($vlan_conf, $vlan_enable, $mode0, $default0, $vlanid0, $tag0);
	}

	if($curr_mode=="Access point" || $curr_mode=="Repeater")
	{
		$result=shell_exec("call_qcsapi show_vlan_config wifi1");
		if(!is_qcsapi_error($result))
		{
			$vlan_conf=explode("\n", $result);
			$sum_active_interface++;
			$arr_interface[$sum_active_interface-1]="wifi1";
			parse_vlan_conf($vlan_conf, $vlan_enable, $mode1, $default1, $vlanid1, $tag1);
		}

		$result=shell_exec("call_qcsapi show_vlan_config wifi2");
		if(!is_qcsapi_error($result))
		{
			$vlan_conf=explode("\n", $result);
			$sum_active_interface++;
			$arr_interface[$sum_active_interface-1]="wifi2";
			parse_vlan_conf($vlan_conf, $vlan_enable, $mode2, $default2, $vlanid2, $tag2);
		}

		$result=shell_exec("call_qcsapi show_vlan_config wifi3");
		if(!is_qcsapi_error($result))
		{
			$vlan_conf=explode("\n", $result);
			$sum_active_interface++;
			$arr_interface[$sum_active_interface-1]="wifi3";
			parse_vlan_conf($vlan_conf, $vlan_enable, $mode3, $default3, $vlanid3, $tag3);
		}

		$result=shell_exec("call_qcsapi show_vlan_config wifi4");
		if(!is_qcsapi_error($result))
		{
			$vlan_conf=explode("\n", $result);
			$sum_active_interface++;
			$arr_interface[$sum_active_interface-1]="wifi4";
			parse_vlan_conf($vlan_conf, $vlan_enable, $mode4, $default4, $vlanid4, $tag4);
		}

		$result=shell_exec("call_qcsapi show_vlan_config wifi5");
		if(!is_qcsapi_error($result))
		{
			$vlan_conf=explode("\n", $result);
			$sum_active_interface++;
			$arr_interface[$sum_active_interface-1]="wifi5";
			parse_vlan_conf($vlan_conf, $vlan_enable, $mode5, $default5, $vlanid5, $tag5);
		}

		$result=shell_exec("call_qcsapi show_vlan_config wifi6");
		if(!is_qcsapi_error($result))
		{
			$vlan_conf=explode("\n", $result);
			$sum_active_interface++;
			$arr_interface[$sum_active_interface-1]="wifi6";
			parse_vlan_conf($vlan_conf, $vlan_enable, $mode6, $default6, $vlanid6, $tag6);
		}

		$result=shell_exec("call_qcsapi show_vlan_config wifi7");
		if(!is_qcsapi_error($result))
		{
			$vlan_conf=explode("\n", $result);
			$sum_active_interface++;
			$arr_interface[$sum_active_interface-1]="wifi7";
			parse_vlan_conf($vlan_conf, $vlan_enable, $mode7, $default7, $vlanid7, $tag7);
		}
	}
}

function set_value()
{
	global $curr_mode, $arr_interface, $sum_active_interface, $modeeth0, $modeeth1, $mode0, $mode1, $mode2, $mode3, $mode4, $mode5, $mode6, $mode7, $vlanideth0, $vlanideth1, $vlanid0, $vlanid1, $vlanid2, $vlanid3, $vlanid4, $vlanid5, $vlanid6, $vlanid7, $defaulteth0, $defaulteth1, $default0, $default1, $default2, $default3, $default4, $default5, $default6, $default7, $tageth0, $tageth1, $tag0, $tag1, $tag2, $tag3, $tag4, $tag5, $tag6, $tag7, $vlan_enable;

	$vlan_enable_new=$_POST['chk_vlan_enable'];
	$mode_new=$_POST['cmb_vlanmode'];
	$interface_new=$_POST['cmb_interface'];
	$option_new=$_POST['cmb_option'];
	$vlanid_new=$_POST['cmb_vlanid'];
	$default_new=$_POST['chk_default'];
	$tag_new=$_POST['chk_tag'];

	if ($vlan_enable_new != $vlan_enable)
	{
		if ($vlan_enable_new == 0) {
			exec("call_qcsapi vlan_config eth1_0 disable");
			$vlan_enable=0;
		} else {
			exec("call_qcsapi vlan_config eth1_0 enable");
			$vlan_enable=1;
		}
	}
	if ($interface_new == "wifi0")
	{
		$mode_curr="$mode0";
		$vlanid_curr="$vlanid0";
		$default_curr="$default0";
		$tag_curr="$tag0";
	}
	else if ($interface_new == "wifi1")
	{
		$mode_curr="$mode1";
		$vlanid_curr="$vlanid1";
		$default_curr="$default1";
		$tag_curr="$tag1";
	}
	else if ($interface_new == "wifi2")
	{
		$mode_curr="$mode2";
		$vlanid_curr="$vlanid2";
		$default_curr="$default2";
		$tag_curr="$tag2";
	}
	else if ($interface_new == "wifi3")
	{
		$mode_curr="$mode3";
		$vlanid_curr="$vlanid3";
		$default_curr="$default3";
		$tag_curr="$tag3";
	}
	else if ($interface_new == "wifi4")
	{
		$mode_curr="$mode4";
		$vlanid_curr="$vlanid4";
		$default_curr="$default4";
		$tag_curr="$tag4";
	}
	else if ($interface_new == "wifi5")
	{
		$mode_curr="$mode5";
		$vlanid_curr="$vlanid5";
		$default_curr="$default5";
		$tag_curr="$tag5";
	}
	else if ($interface_new == "wifi6")
	{
		$mode_curr="$mode6";
		$vlanid_curr="$vlanid6";
		$default_curr="$default6";
		$tag_curr="$tag6";
	}
	else if ($interface_new == "wifi7")
	{
		$mode_curr="$mode7";
		$vlanid_curr="$vlanid7";
		$default_curr="$default7";
		$tag_curr="$tag7";
	}
	else if ($interface_new == "eth1_0")
	{
		$mode_curr="$modeeth0";
		$vlanid_curr="$vlanideth0";
		$default_curr="$defaulteth0";
		$tag_curr="$tageth0";
	}
	else if ($interface_new == "eth1_1")
	{
		$mode_curr="$modeeth1";
		$vlanid_curr="$vlanideth1";
		$default_curr="$defaulteth1";
		$tag_curr="$tageth1";
	}

	if ($mode_curr == "Access")
	{
		exec("call_qcsapi vlan_config $interface_new $mode_curr $vlanid_new");
	}

	if ($mode_new != $mode_curr)
	{
		exec("call_qcsapi vlan_config $interface_new $mode_new $vlanid_new");
		$mode_curr=$mode_new;
	}

	if ($option_new == "Add")
	{
		exec("call_qcsapi vlan_config $interface_new $mode_curr $vlanid_new");
	}
	else if ($option_new == "Delete")
	{
		exec("call_qcsapi vlan_config $interface_new $mode_curr $vlanid_new delete");
	}

	if ($default_new == 1)
	{
		if ($mode_curr != "Access")
		{
			exec("call_qcsapi vlan_config $interface_new $mode_curr $vlanid_new default");
		}
	}
	if ($tag_new == 1)
	{
		if ($mode_curr == "Hybrid")
		{
			exec("call_qcsapi vlan_config $interface_new $mode_curr $vlanid_new untag");
		}
	}
	else if ($tag_new == 0)
	{
		if ($mode_curr == "Hybrid")
		{
			exec("call_qcsapi vlan_config $interface_new $mode_curr $vlanid_new tag");
		}
	}
}

get_value();
if (isset($_POST['action']))
{
	if (!(isset($_POST['csrf_token']) && $_POST['csrf_token'] === get_session_token())) {
		header('Location: login.php');
		exit();
	}
	set_value();
	get_value();
}
?>

<script type="text/javascript">
var mode = "<?php echo $curr_mode; ?>";
var vlan_enable = "<?php echo $vlan_enable; ?>";

function populate_interface_list()
{
	var cmb_if = document.getElementById("cmb_interface");

	cmb_if.options.length = "<?php echo $sum_active_interface; ?>";
	var tmp_text=new Array();
	tmp_text[0]="<?php echo $arr_interface[0]; ?>";
	tmp_text[1]="<?php echo $arr_interface[1]; ?>";
	tmp_text[2]="<?php echo $arr_interface[2]; ?>";
	tmp_text[3]="<?php echo $arr_interface[3]; ?>";
	tmp_text[4]="<?php echo $arr_interface[4]; ?>";
	tmp_text[5]="<?php echo $arr_interface[5]; ?>";
	tmp_text[6]="<?php echo $arr_interface[6]; ?>";
	tmp_text[7]="<?php echo $arr_interface[7]; ?>";
	tmp_text[8]="<?php echo $arr_interface[8]; ?>";
	tmp_text[9]="<?php echo $arr_interface[9]; ?>";

	for (var i=0; i < cmb_if.options.length; i++)
	{
		cmb_if.options[i].text = tmp_text[i]; cmb_if.options[i].value = tmp_text[i];
	}
}

function populate_vlan_mode_list(vlan_mode)
{
	var cmb_if = document.getElementById("cmb_vlanmode");

	cmb_if.options.length = 3;
	cmb_if.options[0].text = "Access"; cmb_if.options[0].value = "Access";
	cmb_if.options[1].text = "Trunk"; cmb_if.options[1].value = "Trunk";
	cmb_if.options[2].text = "Hybrid"; cmb_if.options[2].value = "Hybrid";

	if (vlan_mode=="Access") {
		cmb_if.options[0].selected=true;
		set_disabled('cmb_option', true);
		set_disabled('chk_default', true);
		set_disabled('chk_tag', true);
	} else if (vlan_mode=="Trunk") {
		cmb_if.options[1].selected=true;
		set_disabled('cmb_option', false);
		set_disabled('chk_default', false);
		set_disabled('chk_tag', true);
	} else {
		cmb_if.options[2].selected=true;
		set_disabled('cmb_option', false);
		set_disabled('chk_default', false);
		set_disabled('chk_tag', false);
	}
}

function populate_option_list()
{
	var cmb_if = document.getElementById("cmb_option");

	cmb_if.options.length = 3;
	cmb_if.options[0].text = "Update"; cmb_if.options[0].value = "Update";
	cmb_if.options[1].text = "Add"; cmb_if.options[1].value = "Add";
	cmb_if.options[2].text = "Delete"; cmb_if.options[2].value = "Delete";

}

function clear_vlanid_list()
{
	var cmb_vlanid_tmp = document.getElementById("cmb_vlanid");

	for (var i=cmb_vlanid_tmp.length;i>0;i--)
	{
		cmb_vlanid_tmp.remove(i-1);
	}
}

function populate_unregister_vlan_id(vlanid, vlan_mode)
{
	var cmb_vlanid_cur = document.getElementById("cmb_vlanid");

	clear_vlanid_list();

	for(var i=0;i<2048;i++)
	{
		cmb_vlanid.options.add(new Option(i, i));
	}
	if (vlan_mode=="Access")
	{
		for (var j=0;j<2048;j++)
		{
			if (cmb_vlanid_cur.options[j].value == vlanid)
			{
				cmb_vlanid_cur.remove(j);
			}
		}
	}
	else
	{
		var id_list=vlanid.split(",");

		for (var j=0;j<2048;j++)
		{
			for (var i=0;i<id_list.length-1;i++)
			{
				if (cmb_vlanid_cur.options[j].value == id_list[i])
				{
					cmb_vlanid_cur.remove(j);
				}
			}
		}
	}
}

function populate_vlan_id_list(vlanid, vlan_mode, default_vlan, tag)
{
	var id_list=vlanid.split(",");
	var tag_list=tag.split(",");

	clear_vlanid_list();
	if (vlan_mode=="Access")
	{
		for(i=0;i<2048;i++)
		{
			cmb_vlanid.options.add(new Option(i, i));
		}
		cmb_vlanid.options[vlanid].selected=true;
	}
	else
	{
		for (var i=0;i<id_list.length-1;i++)
		{
			cmb_vlanid.options.add(new Option(id_list[i], id_list[i]));
		}
		if (id_list[0] == default_vlan)
		{
			set_control_value('chk_default', 1, 'checkbox');
		}
		if (vlan_mode=="Hybrid")
		{
			for (var i=0;i<tag_list.length-1;i++)
			{
				if (tag_list[i] == id_list[0])
				{
					set_control_value('chk_tag', 1, 'checkbox');
					break;
				}
			}
		}
	}
}

function modechange(obj)
{
	var vlan_mode;
	var vlanid;
	var tag;
	var default_id;
	var iface=document.getElementById("cmb_interface");
	var change_mode=document.getElementById("cmb_vlanmode");
	var current_id=document.getElementById("cmb_vlanid");
	var option=document.getElementById("cmb_option");

	if (iface.value == "eth1_0")
	{
		vlan_mode = "<?php echo $modeeth0; ?>";
		vlanid = "<?php echo $vlanideth0; ?>";
		tag = "<?php echo $tageth0; ?>";
		default_id = "<?php echo $defaulteth0; ?>";
	}
	else if (iface.value == "eth1_1")
	{
		vlan_mode = "<?php echo $modeeth1; ?>";
		vlanid = "<?php echo $vlanideth1; ?>";
		tag = "<?php echo $tageth1; ?>";
		default_id = "<?php echo $defaulteth1; ?>";
	}
	else if (iface.value == "wifi0")
	{
		vlan_mode = "<?php echo $mode0; ?>";
		vlanid = "<?php echo $vlanid0; ?>";
		tag = "<?php echo $tag0; ?>";
		default_id = "<?php echo $default0; ?>";
	}
	else if (iface.value == "wifi1")
	{
		vlan_mode = "<?php echo $mode1; ?>";
		vlanid = "<?php echo $vlanid1; ?>";
		tag = "<?php echo $tag1; ?>";
		default_id = "<?php echo $default1; ?>";
	}
	else if (iface.value == "wifi2")
	{
		vlan_mode = "<?php echo $mode2; ?>";
		vlanid = "<?php echo $vlanid2; ?>";
		tag = "<?php echo $tag2; ?>";
		default_id = "<?php echo $default2; ?>";
	}
	else if (iface.value == "wifi3")
	{
		vlan_mode = "<?php echo $mode3; ?>";
		vlanid = "<?php echo $vlanid3; ?>";
		tag = "<?php echo $tag3; ?>";
		default_id = "<?php echo $default3; ?>";
	}
	else if (iface.value == "wifi4")
	{
		vlan_mode = "<?php echo $mode4; ?>";
		vlanid = "<?php echo $vlanid4; ?>";
		tag = "<?php echo $tag4; ?>";
		default_id = "<?php echo $default4; ?>";
	}
	else if (iface.value == "wifi5")
	{
		vlan_mode = "<?php echo $mode5; ?>";
		vlanid = "<?php echo $vlanid5; ?>";
		tag = "<?php echo $tag5; ?>";
		default_id = "<?php echo $default5; ?>";
	}
	else if (iface.value == "wifi6")
	{
		vlan_mode = "<?php echo $mode6; ?>";
		vlanid = "<?php echo $vlanid6; ?>";
		tag = "<?php echo $tag6; ?>";
		default_id = "<?php echo $default6; ?>";
	}
	else if (iface.value == "wifi7")
	{
		vlan_mode = "<?php echo $mode7; ?>";
		vlanid = "<?php echo $vlanid7; ?>";
		tag = "<?php echo $tag7; ?>";
		default_id = "<?php echo $default7; ?>";
	}

	if (obj.name == "chk_vlan_enable")
	{

		set_disabled('cmb_interface', true);
		set_disabled('cmb_vlanmode', true);
		set_disabled('cmb_option', true);
		set_disabled('cmb_vlanid', true);
		set_disabled('chk_default', true);
		set_disabled('chk_tag', true);
	}


	if(obj.name == "cmb_interface")
	{
		populate_vlan_mode_list(vlan_mode);
		populate_vlan_id_list(vlanid, vlan_mode, default_id, tag);
	}

	if(obj.name == "cmb_vlanmode")
	{
		if (change_mode.value==vlan_mode)
		{
			populate_vlan_id_list(vlanid, vlan_mode, default_id, tag);
		}
		else
		{
			populate_unregister_vlan_id("", "");

			set_disabled('cmb_option', true);
			set_disabled('chk_default', true);
			set_disabled('chk_tag', true);

			/* Setting Add option for vlan id */
			cmb_option.options[1].selected=true;
		}
	}

	if(obj.name == "cmb_vlanid")
	{
		if (change_mode.value != "Access" && option.value == "Update")
		{
			set_control_value('chk_default', 0, 'checkbox');
			set_control_value('chk_tag', 0, 'checkbox');
			if(current_id.value == default_id)
			{
				set_control_value('chk_default', 1, 'checkbox');
			}

			if (change_mode.value == "Hybrid")
			{
				var tag_list=tag.split(",");

				for (var i=0;i<tag_list.length-1;i++)
				{
					if (tag_list[i] == current_id.value)
					{
						set_control_value('chk_tag', 1, 'checkbox');
						break;
					}
				}
			}
		}
	}

	if(obj.name == "cmb_option")
	{
		if(option.value == "Add")
		{
			set_disabled('chk_default', true);
			set_disabled('chk_tag', true);
			populate_unregister_vlan_id(vlanid, vlan_mode);
		}
		else if(option.value == "Update")
		{
			populate_vlan_id_list(vlanid, vlan_mode, default_id, tag);
			set_disabled('chk_default', false);
			set_disabled('chk_tag', false);
		}
		else if(option.value == "Delete")
		{
			populate_vlan_id_list(vlanid, vlan_mode, default_id, tag);
			set_disabled('chk_default', true);
			set_disabled('chk_tag', true);
		}
	}

	if (obj.name == "chk_default")
	{
		var default_box = document.getElementById('chk_default').checked;

		if (default_box == false)
		{
			alert("Please set other vlan id as default");
		}
	}
}

function validate(action_name)
{
	var tmp = document.getElementById("action");
	tmp.value = action_name;

	if (action_name==0)//Save Button
	{
		document.mainform.submit();
	}
	else if(action_name==1)//Cancel Button
	{
		window.location.href="config_vlan.php";
	}
}

function onload_event()
{
	var vlan_mode = "<?php echo $modeeth0; ?>";
	var vlanid = "<?php echo $vlanideth0; ?>";
	var tag = "<?php echo $tageth0; ?>";
	var default_id = "<?php echo $defaulteth0; ?>";

	init_menu();

	populate_interface_list();
	populate_vlan_mode_list(vlan_mode);
	populate_option_list();
	populate_vlan_id_list(vlanid, vlan_mode, default_id, tag);

	set_control_value('chk_vlan_enable', vlan_enable, 'checkbox');
	if (vlan_enable=="0") {
		set_disabled('cmb_interface', true);
		set_disabled('cmb_vlanmode', true);
		set_disabled('cmb_option', true);
		set_disabled('cmb_vlanid', true);
		set_disabled('chk_default', true);
		set_disabled('chk_tag', true);
	} else if (vlan_mode=="Access") {
		set_disabled('cmb_option', true);
		set_disabled('chk_default', true);
		set_disabled('chk_tag', true);
	} else if (vlan_mode=="Trunk") {
		set_disabled('chk_tag', true);
	}
}

</script>

<body class="body" onload="onload_event();">
	<div class="top">
		<a class="logo" href="./status_device.php">
			<img src="./images/logo.png"/>
		</a>
	</div>
<form enctype="multipart/form-data" action="config_vlan.php" id="mainform" name="mainform" method="post">
<input type="hidden" name="action" id="action" value="action" />
<div class="container">
	<div class="left">
		<script type="text/javascript">
			createMenu('<?php echo $curr_mode;?>',privilege);
		</script>
	</div>
	<div class="right">
		<div class="righttop">CONFIG - VLAN</div>
		<div class="rightmain">
			<table class="tablemain" style=" height:auto">
				<tr id="tr_vlan_enable">
					<td width="35%">vlan enable:</td>
					<td width="65%">
					 <input name="chk_vlan_enable" id="chk_vlan_enable" type="checkbox" class="checkbox" value="1" onchange="modechange(this)" />
					</td>
				</tr>
				<tr id="tr_l">
					<td class="divline" colspan="2";></td>
				</tr>
				<tr id="tr_interface">
					<td width="35%">Interface:</td>
					<td width="65%">
						<select name="cmb_interface" id="cmb_interface" class="combox" onchange="modechange(this)">
						</select>
					</td>
				</tr>
				<tr id="tr_l">
					<td class="divline" colspan="2";></td>
				</tr>
				<tr id="tr_mode">
					<td>Mode:</td>
					<td>
						<select name="cmb_vlanmode" id="cmb_vlanmode" class="combox" onchange="modechange(this)">
						</select>
					</td>
				</tr>
				<tr>
					<td>Option:</td><td>&nbsp;&nbsp;&nbsp;ID
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
					Default
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				&nbsp;&nbsp;&nbsp;&nbsp;
					Untag </td>
				</tr>
				<tr id="tr_id_tag">
				<td>
						<select name="cmb_option" id="cmb_option" class="combox" style="width:91px;" onchange="modechange(this)">
						</select>
				</td><td>
						<select name="cmb_vlanid" id="cmb_vlanid" class="combox" style="width:71px;" onchange="modechange(this)">
						</select>
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
					<input name="chk_default" id="chk_default" type="checkbox" class="checkbox" value="1" onchange="modechange(this)" />
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
				&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
					 <input name="chk_tag" id="chk_tag" type="checkbox" class="checkbox" value="1" onchange="modechange(this)" />
				</td>
				</tr>
				<tr id="tr_l">
					<td class="divline" colspan="2";></td>
				</tr>
			</table>
			<div class="rightbottom">
				<button name="btn_save_adv" id="btn_save_basic" type="button" onclick="validate(0);" class="button">Save</button>
				<button name="btn_cancel_adv" id="btn_cancel_basic" type="button" onclick="validate(1);" class="button">Cancel</button>
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

