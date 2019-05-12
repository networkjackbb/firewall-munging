<?php

$screenOSFile = trim($argv[1]);

if (!file_exists($screenOSFile) || !is_readable($screenOSFile))
{
	die("unable to locate or read file: $screenOSFile");
}

function cidr2NetmaskAddr($cidr)
{
	$ta = substr ($cidr, strpos ($cidr, '/') + 1) * 1;
	$netmask = str_split (str_pad (str_pad ('', $ta, '1'), 32, '0'), 8);

	foreach ($netmask as &$element)
		$element = bindec ($element);

	return join ('.', $netmask);
}
function createNetmaskAddr($bitcount)
{
	$netmask = str_split (str_pad (str_pad ('', $bitcount, '1'), 32, '0'), 8);

	foreach ($netmask as &$element)
		$element = bindec ($element);

	return join ('.', $netmask);
}
  
$Routes = array();
$Addresses = $AddrGroups = array();
$Services = $SvcGroups = array();
$curVRouter = '';
$Routes = array();

foreach(file($screenOSFile) as $line)
{
	$line = trim($line);
	list($wordOne, $line) = explode(' ', $line, 2);
	if ('set' != $wordOne)			continue;
	
	list($wordTwo, $line) = explode(' ', $line, 2);
	if ('group' == $wordTwo)
	{
		list($wordThree, $line) = explode(' ', $line, 2);
		$groupType = '';
		switch($wordThree)
		{
#set group address "XHub" "XHub VPN Sources"
#set group address "XHub" "XHub VPN Sources" add "SS1 XHub Interface"
			case 'address':
				list($d1, $interface, $d2, $groupName, $line) = explode('"', $line, 5);
				if (!array_key_exists($interface, $AddrGroups))					$AddrGroups[$interface] = array();
				if (!array_key_exists($groupName, $AddrGroups[$interface]))
				{
					$AddrGroups[$interface][$groupName] = array('members' => array(), 'comment' => '', );
				}
				$line = ltrim($line);
				if (!empty($line))
				{		//	 add "AHDS-TPport"
					list($verb, $i1, $d1) = explode('"', $line, 3);
					$verb = trim($verb);
					if ('add' == $verb)
					{
						$AddrGroups[$interface][$groupName]['members'][] = $i1;
					}
					elseif ('comment' == $verb)
					{
						$AddrGroups[$interface][$groupName]['comment'] = $i1;
					}
				}
				break;
#set group service "NS2 OpenSvcs"
#set group service "NS2 OpenSvcs" add "DNS"
#set group service "NS2 OpenSvcs" add "Port42201"
			case 'service':
				list($d1, $groupName, $line) = explode('"', $line, 3);
				if (!array_key_exists($groupName, $SvcGroups))
				{
					$SvcGroups[$groupName] = array('members' => array(), 'comment' => '', );
				}
				$line = ltrim($line);
				if (!empty($line))
				{		//	 add "AHDS-TPport"
					list($verb, $i1, $d1) = explode('"', $line, 3);
					$verb = trim($verb);
					if ('add' == $verb)
					{
						$SvcGroups[$groupName]['members'][] = $i1;
					}
					elseif ('comment' == $verb)
					{
						$SvcGroups[$groupName]['comment'] = $i1;
					}
				}
				break;
		}
	}		// group
	else
	{
		switch($wordTwo)
		{
			case 'vrouter':
				$curVRouter = trim(trim($line), '"');
				continue;
			case 'exit':
				if (!empty($curVRouter))
				{
					$curVRouter = '';
				}
				continue;
				
			case 'address':
				list($d1, $interface, $line) = explode('"', $line, 3);
				$line = ltrim($line, '" ');
				list($addrName, $line) = explode('"', $line, 2);
				$line = ltrim($line);
				list($addrIP, $line) = explode(' ', $line, 2);
				if (strstr($line, ' '))
				{
					list($addrMask, $addrComment) = explode(' ', $line);
					$addrComment = trim($addrComment, '"');
				}
				else
				{
					$addrMask = trim($line);
					$addrComment = '';
				}
				$Addresses[] = array($interface, $addrName, $addrIP, $addrMask, $addrComment);
				break;

			case 'service':
				list($d1, $svcName, $line) = explode('"', $line, 3);
				if (!array_key_exists($svcName, $Services))
				{
					$Services[$svcName] = array('tcp' => array(), 'udp' => array(), 'other' => array(), 'timeout'=>false);	 # array('protocol' => '', 'srcstart' => array(), 'dstrange' => array(), 'timeout' => '', );
				}
				list($wordThree, $line) = explode(' ', ltrim($line, '" '), 2);	## --> protocol		tcp src-port 1000-65535 dst-port 27211-27211 
				switch($wordThree)
				{
					case 'protocol':
					case '+':
						list($protocol, $spLabel, $spRange, $dpLabel, $dpRange, $line) = explode(' ', "$line ", 6);
						$PortDef = array('srcRange' => $spRange, 'dstRange' => $dpRange, );
						$line = trim($line);
						if (!empty($line))
						{
							list($d1, $timeoutVal) = explode(' ', $line, 2);
							if ('timeout' == $d1)			$Services[$svcName]['timeout'] = $timeoutVal;
						}
						if (strstr('tcp,udp', $protocol))
						{
							$Services[$svcName][$protocol][] = $PortDef;
						}
						else
						{
							$PortDef['protocol'] = $protocol;
							$Services[$svcName]['other'][] = $PortDef;						
						}
						break;

					case 'timeout':
						$timeoutVal = trim($line)+0;
						if ($timeoutVal)								$Services[$svcName]['timeout'] = $timeoutVal;
						break;

					case 'session-cache':
						break;
				}

				break;		// service

##set route 0.0.0.0/0 interface ethernet0/1 gateway 72.5.187.254 preference 20 metric 100 permanent description "Default Route"
##set route 192.168.131.0/24 interface tunnel.3 description "BBHome"
##set route 10.255.255.0/24 interface null description "null routed block -- special IPs"
##set route 10.238.17.128/29 interface tunnel.4 gateway 216.52.182.115 description "EQX BKP LAN"
##set route 10.130.0.0/16 gateway 10.74.1.184 description "Emphsys TrustNetwork"
			case 'route':
				list($routeDest, $line) = explode(' ', $line, 2);
				$RouteEntry = array('dest' => $routeDest, 'interface' => false, 'isPerm' => false, );
				while (!empty($line))
				{
#echo "$line\n";
					list($word, $line) = explode(' ', $line, 2);
					switch($word)
					{
						case 'permanent':
							$RouteEntry['isPerm'] = true;
							break;
						case 'description':
							list($d1, $description, $line) = explode('"', $line, 3);
							$RouteEntry['description'] = $description;
							break;
						default:
							list($value, $line) = explode(' ', $line, 2);
							$RouteEntry[$word] = $value;
							break;
					}
					$line = ltrim($line);
				}
				$Routes[$curVRouter][] = $RouteEntry;
				break;

		}		//	wordTwo
	}	//	wordTwo != group

}		// foreach line


##return;
##var_export($Routes);
##var_export($Addresses);
##var_export($AddrGroups);
##var_export($Services);
##var_export($SvcGroups);


### ----------------------------------------------------------------------------------------
define('LF', "\n");

if (!empty($Services))
{
	echo "config firewall service custom\n";
	foreach($Services as $svcName => $SvcCfg)
	{
		if (!empty($SvcCfg['other']))		continue;		// skip these
		if (empty($SvcCfg['tcp']) && empty($SvcCfg['udp']))			continue;

		echo '  edit "'. $svcName .'"'. LF;
		if (!empty($SvcCfg['tcp']))
		{
			$portLine = '    set tcp-portrange';
			foreach($SvcCfg['tcp'] as $PortDef)
			{		##	        set tcp-portrange 0-65535:0-65535
				$portLine .= ' '. $PortDef['dstRange'] .':'. $PortDef['srcRange'];
			}
			echo $portLine .LF;
		}

		if (!empty($SvcCfg['udp']))
		{
			$portLine = '    set udp-portrange';
			foreach($SvcCfg['udp'] as $PortDef)
			{		##	        set tcp-portrange 0-65535:0-65535
				$portLine .= ' '. $PortDef['dstRange'] .':'. $PortDef['srcRange'];
			}
			echo $portLine .LF;
		}

##		if (!empty($SvcCfg['other']))
##		{
##			$portLine = '    set protocol IP'.LF;
##			foreach($SvcCfg['other'] as $PortDef)
##			{		##	        set tcp-portrange 0-65535:0-65535
##				$portLine .= '    set protocol-number '. $PortDef['protocol'].LF;
##				
##				$portLine .= ' '. $PortDef['dstRange'] .':'. $PortDef['srcRange'];
##			}
##			echo $portLine .LF;
##		}
		if (false !== $SvcCfg['timeout'])
		{
			echo '    set session-ttl ' . ($SvcCfg['timeout'] *60) .LF;
		}
		echo '  next' .LF;
	}
	echo 'end' .LF;
}		//	Services

##					$Addresses[] = array($interface, $addrName, $addrIP, $addrMask, $addrComment);
if (!empty($Addresses))
{
	echo 'config firewall address'. LF;
	foreach($Addresses as $AddressCfg)
	{
		list($interface, $addrName, $addrIP, $addrMask, $addrComment) = $AddressCfg;
		
		echo '  edit "'. $addrName .'"'. LF;
		echo '    set associated-interface "'. $interface .'"'. LF;
		echo "    set subnet $addrIP $addrMask". LF;
		if (!empty($addrComment))
		{
			echo '    set comment "'. $addrComment .'"'. LF;
		}
		echo '  next' .LF;
	}
	echo 'end' .LF;
}		//	Addresses


##config firewall service group
##    edit "Email Access"
##        set member "DNS" "IMAP" "IMAPS" "POP3" "POP3S" "SMTP" "SMTPS"
##    next
##end
if (!empty($SvcGroups))
{
	echo 'config firewall service group'. LF;
	foreach($SvcGroups as $groupName => $GroupCfg)
	{
		echo '  edit "'. $groupName .'"'. LF;
		echo '    set member "'. implode('"  "', $GroupCfg['members']) .'"'. LF;
		if (!empty($GroupCfg['comment']))
		{
			echo '    set comment "'. $GroupCfg['comment'] .'"'. LF;
		}
		echo '  next' .LF;
	}
	echo 'end' .LF;
}		// service groups


if (!empty($AddrGroups))
{
	echo 'config firewall addrgrp'. LF;
	foreach($AddrGroups as $interface => $InterfaceGroups)
	{
		foreach($InterfaceGroups as $groupName => $GroupCfg)
		{
			
			echo '  edit "'. $interface .'-'. $groupName .'"'. LF;
			echo '    set member "'. implode('"  "', $GroupCfg['members']) .'"'. LF;
			if (!empty($GroupCfg['comment']))
			{
				echo '    set comment "'. $GroupCfg['comment'] .'"'. LF;
			}
			echo '  next' .LF;
		}
	}
	echo 'end' .LF;
}		// Address groups


foreach($Routes as $tgtRouter => $Entries)
{
	echo "-- Routes for $tgtRouter". LF;
	echo "config router static". LF;
	foreach($Entries as $entryNum => $RouteCfg)
	{
		if (false === $RouteCfg['interface'])		continue;		 ## can't spec route that have no destination interface.

		$entryNum += 1;
		echo "  edit $entryNum" .LF;
		foreach($RouteCfg as $cfgType => $cfgVal)
		{
			switch($cfgType)
			{
				case 'dest':
					list($ip, $bitcount) = explode('/', $cfgVal, 2);
					$netmask = createNetmaskAddr($bitcount);
					echo "    set dst $ip $netmask". LF;
					break;
				case 'description':
					echo '    set comment "'. $cfgVal .'"'. LF;
					break;
				case 'interface':
					if ('null' == $cfgVal)
					{
						echo '    set blackhole enable'. LF;
					}
					else
							echo '    set device "'. $cfgVal .'"'. LF;

					break;
				case 'metric':
					echo "    set distance $cfgVal". LF;
					break;
				case 'preference':
					echo "    set priority $cfgVal". LF;
					break;
				case 'gateway':
					echo "    set gateway $cfgVal". LF;
					break;
			}
		}
		echo '  next' .LF;
	}
	echo 'end' .LF;
	echo "-- End Routes for $tgtRouter" .LF.LF;
}		//	Routes


/*
config system session-ttl
    config port
        edit 24013
            set protocol 6
            set timeout 3600
            set start-port 24013
            set end-port 24013
        next
    end
end
*/

/*


config router static
    edit 1
        set dst 192.168.228.0 255.255.255.0
        set gateway 10.52.182.1
        set distance 1
        set device "port5"
        set comment "RAS subnet"
    next
    edit 2
        set dst 1.1.2.1 255.255.255.255
        set gateway 1.1.2.3
        set priority 4
        set device "port10"
        set comment "what a route"
    next

    edit 2
        set status disable
        set dst 1.1.2.1 255.255.255.255
        set priority 4
        set comment "what a route"
        set blackhole enable
    next
    edit 3
        set gateway 72.5.187.254
        set distance 100
        set device "wan1"
        set comment "Default Route"
    next
end

set address "RAS-XHub" "Noridian TestSFTP MIP-23" 100.64.47.23 255.255.255.255 "MIP to 199.253.134.245 via CMSX"
config firewall address
    edit "AHDS-FW1"
        set uuid 9d3197e0-52b5-51e6-7a44-69757c0ce132
        set associated-interface "XPTrust"
        set subnet 72.5.187.84 255.255.255.255
    next
end
config firewall addrgrp
    edit "Trusted-PublicIPs-AHDS"
        set uuid ce4425b4-52b5-51e6-bc41-4d083dc41bf9
        set member "AHDS-FW1"
    next
end






set service "FTP" timeout 5 
set service "SSH" timeout 360 
set service "AFP" protocol tcp src-port 1000-65535 dst-port 548-548 
set service "AFP" + udp src-port 1000-65535 dst-port 548-548 
set service "Apple Remote Desktop" protocol tcp src-port 1000-65535 dst-port 5900-5900 
set service "Apple Remote Desktop" + tcp src-port 1000-65535 dst-port 3283-3283 
set service "Apple Remote Desktop" + udp src-port 1000-65535 dst-port 3283-3283 
set service "Apple ServerAdmin" protocol tcp src-port 1000-65535 dst-port 311-311 
set service "Apple ServerAdmin" + tcp src-port 1000-65535 dst-port 687-687 
set service "Apple Workgroup Mgr" protocol tcp src-port 1000-65535 dst-port 625-625 
set service "FTP-2021" protocol tcp src-port 1000-65535 dst-port 2021-2021 timeout 10 
set service "MySQL" protocol tcp src-port 1000-65535 dst-port 3306-3306 
set service "SSH-2722" protocol tcp src-port 1000-65535 dst-port 2722-2722 timeout 120 
set service "SSH-27022" protocol tcp src-port 1000-65535 dst-port 27022-27022 timeout 120 
set service "SSH-22122" protocol tcp src-port 1000-65535 dst-port 22122-22122 
set service "SSHALT-11" protocol tcp src-port 1000-65535 dst-port 27211-27211 
set service "SVN-19630" protocol tcp src-port 1000-65535 dst-port 19630-19630 
set service "HETS-8888" protocol tcp src-port 1000-65535 dst-port 8888-8888 
set service "TN3270-23045" protocol tcp src-port 1000-65535 dst-port 23045-23045 timeout 500 
set service "Jabber" protocol tcp src-port 1000-65535 dst-port 5222-5223 
set service "Jabber" + udp src-port 1000-65535 dst-port 5222-5223 
set service "Jabber" timeout 300
set service "TN3270-23010" protocol tcp src-port 1000-65535 dst-port 23010-23010 
set service "TN3270-23027" protocol tcp src-port 1000-65535 dst-port 23027-23027 
set service "SSH-22021" protocol tcp src-port 1000-65535 dst-port 22021-22021 timeout 120 
set service "SFTP-10062" protocol tcp src-port 1000-65535 dst-port 10062-10062 timeout 5 
set service "SFTP-9965" protocol tcp src-port 1000-65535 dst-port 9965-9965 timeout 5 
set service "SFTP-10022" protocol tcp src-port 1000-65535 dst-port 10022-10022 timeout 5 
set service "SFTP-9010" protocol tcp src-port 1000-65535 dst-port 9010-9010 timeout 5 
set service "FTP-5350" protocol tcp src-port 1000-65535 dst-port 5350-5350 
set service "FTP-23456" protocol tcp src-port 1000-65535 dst-port 23456-23456 
set service "TN3270-33027" protocol tcp src-port 1000-65535 dst-port 33027-33027 
set service "TN3270-33028" protocol tcp src-port 1000-65535 dst-port 33028-33028 
set service "Cisco HSRP" protocol udp src-port 1985-1985 dst-port 1985-1985 
set service "HETSv2-9999" protocol tcp src-port 1000-65535 dst-port 9999-9999 
set service "SFTP-2200" protocol tcp src-port 1000-65535 dst-port 2200-2200 
set service "SFTP-9122" protocol tcp src-port 1000-65535 dst-port 9122-9122 timeout 10 
set service "TN3270-23098" protocol tcp src-port 1000-65535 dst-port 23098-23098 
set service "Windows Remote Desktop" protocol tcp src-port 1000-65535 dst-port 3389-3389 
set service "Rsync" protocol tcp src-port 1000-65535 dst-port 873-873 
set service "Rsync-VIP" protocol tcp src-port 1000-65535 dst-port 60873-60873 
set service "FileMaker" protocol tcp src-port 1000-65535 dst-port 5003-5003 
set service "Hasher1" protocol tcp src-port 1000-65535 dst-port 3355-3355 timeout 10 
set service "Hasher1" session-cache
set service "iChat Extras" protocol tcp src-port 1000-65535 dst-port 7777-7777 
set service "iChat Extras" + udp src-port 1000-65535 dst-port 16384-16403 

set group address "Trust" "Allowed to iMaxWS Trust"
set group address "Trust" "Allowed to iMaxWS Trust" add "Gabe"

set group service "NS2 OpenSvcs"
set group service "NS2 OpenSvcs" add "DNS"
set group service "NS2 OpenSvcs" add "Port42201"
set group service "NS2 OpenSvcs" add "QuickDNS"
set group service "NS2 OpenSvcs" add "ICMP-Good"

config firewall service custom
    edit "WINS"
        set category "Remote Access"
        set tcp-portrange 1512
        set udp-portrange 1512
    next
    edit "RADIUS"
        set category "Authentication"
        set udp-portrange 1812 1813
    next
    edit "AFS3"
        set category "File Access"
        set tcp-portrange 7000-7009
        set udp-portrange 7000-7009
    next
    edit "TRACEROUTE"
        set category "Network Services"
        set udp-portrange 33434-33535
    next
    edit "RTSP"
        set category "VoIP, Messaging & Other Applications"
        set tcp-portrange 554 7070 8554
        set udp-portrange 554
    next
    edit "MMS"
        set visibility disable
        set tcp-portrange 1755
        set udp-portrange 1024-5000
    next
    edit "LDAP_UDP"
        set category "Authentication"
        set udp-portrange 389
    next
    edit "SMB"
        set category "File Access"
        set tcp-portrange 445
    next
    edit "NONE"
        set visibility disable
        set tcp-portrange 0
    next
    edit "webproxy"
        set explicit-proxy enable
        set category "Web Proxy"
        set protocol ALL
        set tcp-portrange 0-65535:0-65535
    next
end
config firewall service group
    edit "Email Access"
        set member "DNS" "IMAP" "IMAPS" "POP3" "POP3S" "SMTP" "SMTPS"
    next
end

*/