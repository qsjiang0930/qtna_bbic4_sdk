<?php
/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2013 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : common.php                                                 **
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
**  GNU General Public License ("GPL") version 2, or (at your option) any    **
**  later version as published by the Free Software Foundation.              **
**                                                                           **
**  In the case this software is distributed under the GPL license,          **
**  you should have received a copy of the GNU General Public License        **
**  along with this software; if not, write to the Free Software             **
**  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  **
**                                                                           **
**  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR       **
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
$call_header = "call_qcsapi";
//-----------------------------------------------------------------------------------------------------------------------------------------------------------
function is_qcsapi_error($res)
{
	if(strpos($res,"QCS API error") === FALSE)
	{
		return FALSE;
	}
	else
	{
		return TRUE;
	}
}

function get_Enable($wifiX)//$wifiX = > $interface
{
	global $call_header;
	$info=exec("$call_header get_SSID $wifiX");
	if(is_qcsapi_error($info))
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

function validate()
{
	$calstate = exec("get_bootval calstate");
	if($calstate != 3)
	{
		return "device";
	}

	$pid = exec("pidof wpa_supplicant");
	if($pid == "")
	{
		$pid = exec("pidof hostapd");
	}
	$val = exec("ifconfig -a | grep wifi0");
	if($val == "" || $pid == "")
	{
		return "networking";
	}
}

//Make sure the special character won`t be trimed.
function escape_any_characters($str)
{
	$escape_str = "";
	$len = strlen($str);
	for($i = 0; $i < $len; $i+=1)
	{
		switch(ord(substr($str, $i)))
		{
			case 34: //decimal value of ASCII "
			case 96: //decimal value of ASCII `
			case 92: //decimal value of ASCII \
			case 36: //decimal value of ASCII $
				$escape_str = $escape_str."\\";
				break;
		}
		$escape_str = $escape_str.$str[$i];
	}
	return $escape_str;
}

function get_Device_Name()
{
	return "Quantenna Wireless Adapt";
}

function get_Software_Version()
{
	global $call_header;
	$info = exec("$call_header get_firmware_version");
	return $info;
}

function get_Uptime()
{
	$info=exec("uptime");
	$arraylist=split(",",$info);
	$arraylist=split(" ",$arraylist[0]);
	$res=$arraylist[3].$arraylist[4];
	return $res;
}

function get_Device_mode()
{
	global $call_header;
	$info = exec("$call_header get_mmode wifi0_0");
	if($info == "Station")
	{
		$res="Station";
	}
	else
	{
		$res="Access Point";
	}
	return $res;
}

function get_Wireless_Band()
{
	global $call_header;
	$curr_band = exec("$call_header get_802.11 wifi0_0");
	return $curr_band;
}

function get_Bandwidth()
{
	global $call_header;
	$bandwidth = exec("$call_header get_bw wifi0_0");
	if((strpos($bandwidth, "API error") === FALSE))
	{
		$res=$bandwidth;
	}
	else
	{
		$res="";
	}
	return $res;
}

function get_AP_Mac_Address($wifiX)
{
	global $call_header;
	if(get_Enable($wifiX) == 0)
	{
		return "";
	}
	$apmac_addr = exec("$call_header get_BSSID $wifiX");
	if($apmac_addr=="00:00:00:00:00:00")
	{
		$res="Not Associated";
	}
	else
	{
		$res=$apmac_addr;
	}
	return $res;
}

function get_Channel()
{
	global $call_header;
	$channel = exec("$call_header get_channel wifi0_0");
	if(is_qcsapi_error($channel))
	{
		$res="";
	}
	else
	{
		$res=$channel;
	}
	return $res;
}

function read_wireless_conf($param)
{
	$content=trim(shell_exec("cat /mnt/jffs2/wireless_conf.txt"));
	$sections=explode("&",$content);
	foreach($sections as $section)
	{
		$res=explode("=",$section);
		if ($res[0] == $param)
		{
			return $res[1];
		}
	}
	return "";
}

function write_wireless_conf($param,$curr_value,$new_value)
{
	$content=trim(shell_exec("cat /mnt/jffs2/wireless_conf.txt"));
	//Add new parameter, if it is not found in the file
	$found = read_wireless_conf($param);

	if ($found == "")
	{
		$new_str = "&".$param."=".$new_value;
		$content=$content.$new_str;
	}
	//Update parameter
	else
	{
		$curr_str = $param."=".$curr_value;
		$new_str = $param."=".$new_value;
		$content = str_replace($curr_str, $new_str, $content);
	}
	file_put_contents("/mnt/jffs2/wireless_conf.txt", $content);
	return 1;
}

function get_ap_proto()
{
	global $call_header;
	$wifiX=exec("$call_header get_ap_interface_name");
	$tmp=exec("$call_header get_ssid $wifiX");
	if (is_qcsapi_error($tmp))
	{
		return "None";
	}
	$beacon=exec("$call_header get_beacon $wifiX");
	$encryption=exec("$call_header get_WPA_encryption_modes $wifiX");
	$authentication=exec("$call_header get_WPA_authentication_mode $wifiX");
	if($beacon=="Basic")
	{
		return "None";
	}
	else if($authentication=="EAPAuthentication" && $encryption=="AESEncryption")
	{
		return "WPA2-Enterprise";
	}
	else if($beacon=="11i" && $authentication=="PSKAuthentication" && $encryption=="AESEncryption")
	{
		return "WPA2-Personal";
	}
}

function set_ap_proto($value)
{
	global $call_header;
	$wifiX = exec("$call_header get_ap_interface_name");
	if(!(strpos($wifiX, "not found") === false))
	{
		$wifiX="wifi0";
	}
	if($value == "None")
	{
		$info1 = exec("$call_header set_beacon $wifiX Basic");
		$info2 = exec("$call_header set_WPA_authentication_mode $wifiX PSKAuthentication");
		$info3 = exec("$call_header set_WPA_encryption_modes $wifiX AESEncryption");
	}
	else if($value == "WPA2-EAP")
	{
		$info1 = exec("$call_header set_beacon $wifiX 11i");
		$info2 = exec("$call_header set_WPA_authentication_mode $wifiX EAPAuthentication");
		$info3 = exec("$call_header set_WPA_encryption_modes $wifiX AESEncryption");
	}
	else if($value == "11i")
	{
		$info1 = exec("$call_header set_beacon $wifiX 11i");
		$info2 = exec("$call_header set_WPA_authentication_mode $wifiX PSKAuthentication");
		$info3 = exec("$call_header set_WPA_encryption_modes $wifiX AESEncryption");
	}
}
//json_encode()----------------------------------------------------------------------------------------------------------------------------------------------
function __json_encode($data)
{
	if( is_array($data) || is_object($data) )
	{
		$islist = is_array($data) && (empty($data) || array_keys($data) === range(0,count($data)-1));
		if($islist)
		{
			$json = '['.implode(',',array_map('__json_encode',$data)).']';
		}
		else
		{
			$items = Array();
			foreach($data as $key=>$value)
			{
				$items[] = __json_encode("$key").':'. __json_encode($value);
			}
			$json = '{'.implode(',',$items).'}';
		}
	}
	elseif( is_string($data) )
	{
		$string = '"'.addcslashes($data,"\\\"\n\r\t/".chr(8).chr(12)).'"';
		$json   = '';
		$len    = strlen($string);
		for( $i = 0; $i < $len; $i++ )
		{
			$char = $string[$i];
			$c1   = ord($char);
			if($c1 <128)
			{
				$json .= ($c1>31)?$char:sprintf("\\u%04x",$c1);
				continue;
			}
			$c2 = ord($string[++$i]);
            if(($c1 & 32) === 0)
			{
				$json .= sprintf("\\u%04x",($c1 - 192)*64+$c2-128);
				continue;
			}
            $c3 = ord($string[++$i]);
            if(($c1 & 16) === 0)
			{
				$json .= sprintf("\\u%04x", (($c1 - 224) <<12) + (($c2 - 128) << 6) + ($c3 - 128));
				continue;
			}
            $c4 = ord($string[++$i]);
            if(($c1 & 8 ) === 0)
			{
				$u = (($c1 & 15) << 2) + (($c2>>4) & 3) - 1;
                $w1 = (54<<10) + ($u<<6) + (($c2 & 15) << 2) + (($c3>>4) & 3);
                $w2 = (55<<10) + (($c3 & 15)<<6) + ($c4-128);
                $json .= sprintf("\\u%04x\\u%04x", $w1, $w2);
            }
		}
	}
	else
	{
		$json = strtolower(var_export($data,true));
	}
	return $json;
}
//json_encode()----------------------------------------------------------------------------------------------------------------------------------------------
?>
