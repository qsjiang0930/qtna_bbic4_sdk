/*SH0
*******************************************************************************
**                                                                           **
**         Copyright (c) 2009 - 2013 Quantenna Communications, Inc.          **
**                                                                           **
**  File        : common.js                                                  **
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
//----------------------------------------------------------------------------------------------------------------------------------
var server_ipaddr = create_server_ipaddr();
var ajax_timeout = creat_ajax_timeout();
var token,username;
function create_server_ipaddr(ipaddr)
{
	return "127.0.0.1";
}

function creat_ajax_timeout()
{
	return 30000;
}

function validate_token()//became a common function
{
	var vars = [],hash;
	var hashes = window.location.href.slice(window.location.href.indexOf('?') + 1).split('&');
	for(var i = 0; i < hashes.length; i++)
	{
		hash = hashes[i].split('=');
		vars.push(hash[1]);
		token = vars[0];
	}
	$.ajax(
	{
		type        : 'POST',
		url         : 'server/validate_token.php',
		dataType    : 'json',
		timeout     : ajax_timeout,
		data        : {token:vars[0]},
		beforeSend  : function(){
			$("#div_shelter").show();
			$("#div_loading").show();
		},
		complete    : function(){
			$("#div_shelter").hide();
			$("#div_loading").hide();
		},
		success     : function(json)
		{
			if(json.result != 1)
			{
				alert("You do not have permission to access");
				window.location.href="login.html";
			}
			else if(json.time == 0)
			{
				alert("It's been a long time from your last operation! Please log in again!");
				window.location.href="login.html";
			}
			username = json.username;
			createMenu();
			$("#div_shelter").hide();
			$("#div_loading").hide();
		},
        error       : function()
		{
			alert("111");
			window.location.href="login.html";
        }
	});
}

function jump_html(html)
{
	window.location.href = html+".html?token="+token;
}

function session_destroy()
{
	$.ajax(
	{
		type		:'POST',
		url			:'server/validate_token.php',
		dataType	:'json',
		timeout		:ajax_timeout,
		data		:{action:"destroy"},
		beforeSend	:function(){},
		complete	:function(){},
		success		:function(json)
		{
			if(json == "1")
			{
				window.location.href = "login.html";
			}
			else
			{
				alert("Session Destroy Failed!");
			}
		},
		error		:function()
		{
			alert("222");
		}
	});
}

function waiting()
{
	$("#div_shelter").hide();
	$("#div_loading").hide();
	jump_html('system_rebooted');
}

function reboot()
{
	$.ajax(
	{
		type			: 'GET',
		url				: 'server/web_api.php',
		dataType		: 'JSONP',
		timeout			: ajax_timeout,
		data			: {action:"reboot"},
		jsonp			: "callback",
        jsonpCallback	: "success_jsonpCallback",
		beforeSend		: function(){},
		complete		: function(){},
		success			: function(){},
		error			: function(){}
	});
	setTimeout(waiting,2000);
}
//----------------------------------------------------------------------------------------------------------------------------------
function createMenuItem(arrItem,arrLink,arrActive)
{
	var strHtml = "",i;

	for(i=0;i<arrItem.length;i++)
	{
		if(arrActive[i]==true){
			strHtml += '<li><a href="'+arrLink[i]+'.html?token='+token+'" id="menu_'+i+'"><img src="img/'+arrLink[i]+'.png" style="margin-right:5px;"><b>'+arrItem[i]+'</b></a></li>\n';
			if(arrItem[i+1]=='NULL'){	break;}
		}
	}

	strHtml += ' <li><a href="#" onClick="session_destroy()"><img src="img/logout.png" style="margin-right:5px;"><b>Logout</b></a></li>';
	return strHtml;
}

function createMenu()
{
	var arrMenuItem = new Array("Network Status","Network Configuration","Association Table","System","NULL");

	var arrMenuLink = new Array("network_status","network_configuration","association_table","system","NULL");

	if(username == "super")
	{
		var arrMenuActive = new Array(true,true,true,true);
	}
	else if(username == "admin")
	{
		var arrMenuActive = new Array(true,true,true,true);
	}
	else
	{
		var arrMenuActive = new Array(false,false,true,false);
	}

	$("#menu").append(createMenuItem(arrMenuItem,arrMenuLink,arrMenuActive));

	/*if(username == "super")
	{
		$("#menu_table").css({"display":"none"});
	}
	else if(username == "admin")
	{
		$("#menu_config").css({"display":"none"});
	}
	else
	{
		$("#menu_system").css({"display":"none"});
	}*/
}
//----------------------------------------------------------------------------------------------------------------------------------