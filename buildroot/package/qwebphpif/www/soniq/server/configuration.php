#!/usr/lib/cgi-bin/php-cgi
<?php
/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2013 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : configuration.php                                          **
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
include ("common.php");
if(isset($_POST['action']))
{
	$action = $_POST['action'];
	if($action == 'read_config_network')
	{
		$ssid5G = exec("qweb get Device.WiFi.SSID.{0}.SSID");
		$ssid5G = str_replace('"','', $ssid5G);

		$encription5G = exec("qweb get Device.WiFi.AccessPoint.{0}.Security.ModeEnabled");
		$encription5G = str_replace('"','', $encription5G);

		$password5G = exec("qweb get Device.WiFi.AccessPoint.{0}.Security.KeyPassphrase");
		$password5G = str_replace('"','', $password5G);

		$ssid24G = exec("qweb get Device.WiFi.SSID.{8}.SSID");
		$ssid24G = str_replace('"','', $ssid24G);

		$encription24G = exec("qweb get Device.WiFi.AccessPoint.{8}.Security.ModeEnabled");
		$encription24G = str_replace('"','', $encription24G);

		$password24G = exec("qweb get Device.WiFi.AccessPoint.{8}.Security.KeyPassphrase");
		$password24G = str_replace('"','', $password24G);

		if ($ssid5G == $ssid24G && $encription5G == $encription24G && $password5G == $password24G)
		{
			$result = 1 ;
		}else{
			$result = 0 ;
		}


		echo __json_encode(array('ssid5G'=>$ssid5G,'encription5G'=>$encription5G,'password5G'=>$password5G,'ssid24G'=>$ssid24G,'encription24G'=>$encription24G,'password24G'=>$password24G,'result'=>$result));
	}
	else if($action == 'write_config_network')
	{
        echo write_config_network($_POST['data']);
	}
	else if($action == 'cat_config_network')
	{
		exec("cat /tmp/out_fdbk_file");
	}
	else if($action == 'restore_config_network')
	{
		echo restore_config_network();
	}
}

function set_SSID($new_ssid)
{
	$new_ssid_esc = "\"".$new_ssid."\"";
	$new_ssid_esc = escapeshellarg($new_ssid_esc);
	exec("qweb set_inactive Device.WiFi.SSID.{0}.SSID $new_ssid_esc");
	exec("qweb set_inactive Device.WiFi.SSID.{8}.SSID $new_ssid_esc");
}

function set_Encription($new_encription)
{
	$new_encription_esc = "\"".$new_encription."\"";
	$new_encription_esc = escapeshellarg($new_encription_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{0}.Security.ModeEnabled $new_encription_esc");
	exec("qweb set_inactive Device.WiFi.AccessPoint.{8}.Security.ModeEnabled $new_encription_esc");
}

function set_Password($new_password)
{
	$new_password_esc = "\"".$new_password."\"";
	$new_password_esc = escapeshellarg($new_password_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{0}.Security.KeyPassphrase $new_password_esc");
	exec("qweb set_inactive Device.WiFi.AccessPoint.{8}.Security.KeyPassphrase $new_password_esc");
}

function set_SSID24G($new_ssid)
{
	$new_ssid_esc = "\"".$new_ssid."\"";
	$new_ssid_esc = escapeshellarg($new_ssid_esc);
	exec("qweb set_inactive Device.WiFi.SSID.{8}.SSID $new_ssid_esc");

}

function set_Encription24G($new_encription)
{
	$new_encription_esc = "\"".$new_encription."\"";
	$new_encription_esc = escapeshellarg($new_encription_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{8}.Security.ModeEnabled $new_encription_esc");

}

function set_Password24G($new_password)
{
	$new_password_esc = "\"".$new_password."\"";
	$new_password_esc = escapeshellarg($new_password_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{8}.Security.KeyPassphrase $new_password_esc");

}

function set_SSID5G($new_ssid)
{
	$new_ssid_esc = "\"".$new_ssid."\"";
	$new_ssid_esc = escapeshellarg($new_ssid_esc);
	exec("qweb set_inactive Device.WiFi.SSID.{0}.SSID $new_ssid_esc");
}

function set_Encription5G($new_encription)
{
	$new_encription_esc = "\"".$new_encription."\"";
	$new_encription_esc = escapeshellarg($new_encription_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{0}.Security.ModeEnabled $new_encription_esc");
}

function set_Password5G($new_password)
{
	$new_password_esc = "\"".$new_password."\"";
	$new_password_esc = escapeshellarg($new_password_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{0}.Security.KeyPassphrase $new_password_esc");
}

function restore_SSID5G()
{
	$restore_ssid5G = "Quantenna";
	$restore_ssid5G_esc = "\"".$restore_ssid5G."\"";
	$restore_ssid5G_esc = escapeshellarg($restore_ssid5G_esc);
	exec("qweb set_inactive Device.WiFi.SSID.{0}.SSID $restore_ssid5G_esc");
	deploy();
}

function restore_SSID24G()
{
	$restore_ssid24G = "Quantenna";
	$restore_ssid24G_esc = "\"".$restore_ssid24G."\"";
	$restore_ssid24G_esc = escapeshellarg($restore_ssid24G_esc);
	exec("qweb set_inactive Device.WiFi.SSID.{8}.SSID $restore_ssid24G_esc");
	deploy();
}

function restore_Password5G()
{
	$restore_password5G = "qtn01234";
	$restore_password5G_esc = "\"".$restore_password5G."\"";
	$restore_password5G_esc = escapeshellarg($restore_password5G_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{0}.Security.KeyPassphrase $restore_password5G_esc");
	deploy();
}

function restore_Password24G()
{
	$restore_password24G = "qtn01234";
	$restore_password24G_esc = "\"".$restore_password24G."\"";
	$restore_password24G_esc = escapeshellarg($restore_password24G_esc);
	exec("qweb set_inactive Device.WiFi.AccessPoint.{8}.Security.KeyPassphrase $restore_password24G_esc");
	deploy();
}

function deploy()
{
	exec("qwebcfg get_inactive /tmp/new_ap_cfg");
	exec("qcomm_cli update_cfg /tmp/new_ap_cfg");
	exec("qweb clean_inactive");
}

function write_config_network($arr)
{
	$parameter_num = count($arr);
	for($i = 0;$i < $parameter_num;$i++)
	{
		switch($arr[$i][0])
		{
			case 'ESSID':
				set_SSID($arr[$i][1]);
				break;
			case 'Encription':
				set_Encription($arr[$i][1]);
				break;
			case 'Password':
				set_Password($arr[$i][1]);
				break;
			case 'ESSID24G':
				set_SSID24G($arr[$i][1]);
				break;
			case 'Encription24G':
				set_Encription24G($arr[$i][1]);
				break;
			case 'Password24G':
				set_Password24G($arr[$i][1]);
				break;
			case 'ESSID5G':
				set_SSID5G($arr[$i][1]);
				break;
			case 'Encription5G':
				set_Encription5G($arr[$i][1]);
				break;
			case 'Password5G':
				set_Password5G($arr[$i][1]);
				break;
		}
	}
	deploy();
}

function restore_config_network()
{
	restore_SSID5G();
	restore_SSID24G();
	restore_Password5G();
	restore_Password24G();
}
?>