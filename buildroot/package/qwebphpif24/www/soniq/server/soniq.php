#!/usr/lib/cgi-bin/php-cgi
<?php
/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2013 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : soniq.php                                                  **
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
include("common.php");

if(isset($_GET['action']))
{
	$action = $_GET['action'];
	if($action == 'get_device_info')
	{
        class SONIQ_ASSOC_DEVICE
        {
            var $mac,
                $ss,
                $bw,
                $rssi,
                $phy_rate,
                $max_phy_rate,
                $dual_band;
            function SONIQ_ASSOC_DEVICE($mac,
                $ss,
                $bw,
                $rssi,
                $phy_rate,
                $max_phy_rate,
                $dual_band){
                $this->mac          = $mac;
                $this->ss           = $ss;
                $this->bw           = $bw;
                $this->rssi         = $rssi;
                $this->phy_rate     = $phy_rate;
                $this->max_phy_rate = $max_phy_rate;
                $this->dual_band    = $dual_band;
            }
        }
        class SONIQ_BSS
        {
            var $mac,
                $band,
                $channel,
                $fat,
                $assoc;
            function SONIQ_ASSOC($mac,
                $band,
                $channel,
                $fat,
                $assoc
                ){
                $this->mac          = $mac;
                $this->band         = $band;
                $this->channel      = $channel;
                $this->fat          = $fat;
                $this->assoc        = $assoc;
            }
        }

        class SONIQ_STATUS
        {
            var $mac,
                $role,
                $bss;
            function SONIQ_STATUS($mac,
                $role,
                $bss){
                $this->mac          = $mac;
                $this->role         = $role;
                $this->bss          = $bss;
            }
        }

        //$soniq_role = exec("qcomm_cli show_role",$result);
        $output=array();

        /*Get Device List
        "qcomm_cli show_role" Sample:
        quantenna # qcomm_cli show_role
        role: master 00:26:86:F0:27:FF
        known slave:
        00:08:55:41:00:AA*/
        exec("qcomm_cli show_role",$status_result);

        /* Get BSS Information
        "csmd_cli show bss" Sample:
        quantenna # csmd_cli show bss
              BSSID             status  local  band  channel        supported bw  BSSTr   FAT       dev_id
        0001. 00:26:86:f0:29:c1     UP    Yes    5G      108            20,40,80    Yes  1000  00:00:00:00:00:00
        0002. 00:26:86:0c:51:31     UP     No    5G      157            20,40,80    Yes   940  00:08:55:41:00:aa
        Total table entries: 2 of 2*/
        exec("csmd_cli show bss | sed 's/  */ /g'",$bss_result);

        /* Get Association Information
        "csmd_cli show sta assoc" Sample:
        quantenna # csmd_cli show sta assoc
                                 --- STA Max Capabilities ----  ---------- Current Association Info -----------  ----------- Seen by ---------------
              STA                 band  SS  bw  phyrate  BSSTr     AssocWithBSSID  MDID RSSI  MaxPhyR  AvgTX/RX  MDID             BSSID  RSSI   age
        0001. 98:6c:f5:74:31:c8     5G   1  80      433    Yes  00:26:86:0c:51:31  0000  -70      433    0/   0
                                                                                                                 0000 00:26:86:0c:51:31*  -70     1
                                                                                                                 0000 00:26:86:f0:29:c1   -32  6762
        Total table entries: 1 of 467*/
        exec("csmd_cli show sta assoc | sed 's/  */ /g'",$assoc_result);

        //Add the Master MAC address
        $tmp_status_result = split(" ", $status_result[0]);
        $master_mac = $tmp_status_result[2];

        //Master
        $tmp_bss_obj_array = array();
        for ($n = 1;$n<count($bss_result);$n++)
        {
            $bss_result_array = split(" ", $bss_result[$n]);
            //master mac == 00:00:00:00:00:00
            if((count($bss_result_array) >= 9) && (strtoupper($bss_result_array[9]) == "00:00:00:00:00:00"))
            {
                $tmp_assoc_device_obj_array= array();
                for ($i = 2; $i<count($assoc_result); $i++)
                {
                    $assoc_result_array = split(" ", $assoc_result[$i]);
                    if(count($assoc_result_array)>12 && count($assoc_result_array)==13)
                    {
                        //BSSID = AssocWithBSSID
                        //ONLY 5G CASE
                        //OUTPUT SAMPLE: 0001. 98:6c:f5:74:31:c8 5G 1 80 433 Yes 00:26:86:0c:51:31 0000 -68 433 325/ 0
                        if(strtoupper($assoc_result_array[7]) == strtoupper($bss_result_array[1]))
                        {
                            //                                              mac                 ss                  bw                  rssi                    phy_rate                max_phy_rate
                            $tmp_assoc_device_obj = new SONIQ_ASSOC_DEVICE($assoc_result_array[1],intval($assoc_result_array[3]),intval($assoc_result_array[4]),intval($assoc_result_array[9]),intval($assoc_result_array[5]),intval($assoc_result_array[10]),0); 
                            array_push($tmp_assoc_device_obj_array, $tmp_assoc_device_obj);
                        }
                    }
                    elseif(count($assoc_result_array)>12 && count($assoc_result_array)==14)
                    {
                        //BSSID = AssocWithBSSID
                        //2G 5G CASE
                        //OUTPUT SAMPLE: 0001. 98:6c:f5:74:31:c8 2G 5G 1 80 433 Yes 00:26:86:0c:51:31 0000 -68 433 325/ 0
                        if(strtoupper($assoc_result_array[8]) == strtoupper($bss_result_array[1]))
                        {
                            //                                              mac                 ss                  bw                  rssi                    phy_rate                max_phy_rate
                            $tmp_assoc_device_obj = new SONIQ_ASSOC_DEVICE($assoc_result_array[1],intval($assoc_result_array[4]),intval($assoc_result_array[5]),intval($assoc_result_array[10]),intval($assoc_result_array[6]),intval($assoc_result_array[11]),1);
                            array_push($tmp_assoc_device_obj_array, $tmp_assoc_device_obj);
                        }
                    }
                }
                $tmp_bss_obj = array("mac"=>$bss_result_array[1],"band"=>$bss_result_array[4],"channel"=>$bss_result_array[5],"fat"=>$bss_result_array[8],"assoc"=>$tmp_assoc_device_obj_array);
                array_push($tmp_bss_obj_array, $tmp_bss_obj);
            }
        }
        $tmp_status_obj = array("mac"=>strtoupper($master_mac),"role"=>"master","bss"=>$tmp_bss_obj_array);
        array_push($output, $tmp_status_obj);

        //Slave part
        for ($m = 2; $m<count($status_result); $m++)
        {
            $tmp_bss_obj_array = array();
            for ($n = 1;$n<count($bss_result);$n++)
            {
                $bss_result_array = split(" ", $bss_result[$n]);
                //dev_id = slave mac
                if((count($bss_result_array) >= 9) && (strtoupper($bss_result_array[9]) == strtoupper($status_result[$m])))
                {
                    $tmp_assoc_device_obj_array= array();
                    for ($i = 2; $i<count($assoc_result); $i++)
                    {
                        $assoc_result_array = split(" ", $assoc_result[$i]);
                        if(count($assoc_result_array)>12 && count($assoc_result_array)==13)
                        {
                            //BSSID = AssocWithBSSID
                            //ONLY 5G CASE
                            //OUTPUT SAMPLE: 0001. 98:6c:f5:74:31:c8 5G 1 80 433 Yes 00:26:86:0c:51:31 0000 -68 433 325/ 0
                            if(strtoupper($assoc_result_array[7]) == strtoupper($bss_result_array[1]))
                            {
                                //                                              mac                 ss                  bw                  rssi                    phy_rate                max_phy_rate
                                $tmp_assoc_device_obj = new SONIQ_ASSOC_DEVICE($assoc_result_array[1],intval($assoc_result_array[3]),intval($assoc_result_array[4]),intval($assoc_result_array[9]),intval($assoc_result_array[5]),intval($assoc_result_array[10]),0); 
                                array_push($tmp_assoc_device_obj_array, $tmp_assoc_device_obj);
                            }
                        }
                        elseif(count($assoc_result_array)>12 && count($assoc_result_array)==14)
                        {
                            //BSSID = AssocWithBSSID
                            //2G 5G CASE
                            //OUTPUT SAMPLE: 0001. 98:6c:f5:74:31:c8 2G 5G 1 80 433 Yes 00:26:86:0c:51:31 0000 -68 433 325/ 0
                            if(strtoupper($assoc_result_array[8]) == strtoupper($bss_result_array[1]))
                            {
                                //                                              mac                 ss                  bw                  rssi                    phy_rate                max_phy_rate
                                $tmp_assoc_device_obj = new SONIQ_ASSOC_DEVICE($assoc_result_array[1],intval($assoc_result_array[4]),intval($assoc_result_array[5]),intval($assoc_result_array[10]),intval($assoc_result_array[6]),intval($assoc_result_array[11]),1);
                                array_push($tmp_assoc_device_obj_array, $tmp_assoc_device_obj);
                            }
                        }
                    }
                    $tmp_bss_obj = array("mac"=>$bss_result_array[1],"band"=>$bss_result_array[4],"channel"=>$bss_result_array[5],"fat"=>$bss_result_array[8],"assoc"=>$tmp_assoc_device_obj_array);
                    array_push($tmp_bss_obj_array, $tmp_bss_obj);
                }
            }
            $tmp_status_obj = array("mac"=>strtoupper($status_result[$m]),"role"=>"slave","bss"=>$tmp_bss_obj_array);
            array_push($output, $tmp_status_obj);
        }

        echo __json_encode($output);
    }
    else if($action == 'get_bss_fat_info')
    {
        exec("csmd_cli show bss | sed 's/  */ /g'",$bss_result);

         //Master
        $tmp_bss_obj_array = array();
        $count = count($bss_result);
        $count = $count - 1;
        for ($n = 1;$n<$count;$n++)
        {
            $bss_result_array = split(" ", $bss_result[$n]);
            $tmp_bss_obj = array("mac"=>$bss_result_array[1],"fat"=>$bss_result_array[8]);
            array_push($tmp_bss_obj_array, $tmp_bss_obj);
        }
        echo __json_encode($tmp_bss_obj_array);
    }
    else if($action == 'get_assoc_info')
    {
        exec("csmd_cli show sta assoc | sed 's/  */ /g'",$assoc_result);
    }
    else if($action == 'get_csmd_info')
    {
        $process_id = exec("ps | grep \"/usr/sbin/csmd\" | grep -v \"grep\" | awk '{print $1}'");
        echo __json_encode(array('result'=>$process_id));
    }
}
?>