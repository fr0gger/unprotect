rule hijack_network {
    meta:
        author = "x0r"
        description = "Hijack network configuration"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Classes\\PROTOCOLS\\Handler" nocase
        $p2 = "SOFTWARE\\Classes\\PROTOCOLS\\Filter" nocase
        $p3 = "Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ProxyServer" nocase
        $p4 = "software\\microsoft\\windows\\currentversion\\internet settings\\proxyenable" nocase
        $f1 = "drivers\\etc\\hosts" nocase
    condition:
        any of them
}
rule network_udp_sock {
    meta:
        author = "x0r"
        description = "Communications over UDP network"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
	$f2 = "System.Net" nocase
        $f3 = "wsock32.dll" nocase
        $c0 = "WSAStartup"
        $c1 = "sendto"
        $c2 = "recvfrom"
        $c3 = "WSASendTo"
        $c4 = "WSARecvFrom"
        $c5 = "UdpClient"
    condition:
        (($f1 or $f3) and 2 of ($c*)) or ($f2 and $c5)
}
rule network_tcp_listen {
    meta:
        author = "x0r"
        description = "Listen for incoming communication"
	version = "0.1"
    strings:
        $f1 = "Ws2_32.dll" nocase
        $f2 = "Mswsock.dll" nocase
	    $f3 = "System.Net" nocase
        $f4 = "wsock32.dll" nocase
        $c1 = "bind"
        $c2 = "accept"
        $c3 = "GetAcceptExSockaddrs"
        $c4 = "AcceptEx"
        $c5 = "WSAStartup"
        $c6 = "WSAAccept"
        $c7 = "WSASocket"
        $c8 = "TcpListener"
        $c9 = "AcceptTcpClient"
        $c10 = "listen"
    condition:
        1 of ($f*) and 2 of ($c*)
}
rule network_dyndns {
    meta:
        author = "x0r"
        description = "Communications dyndns network"
	version = "0.1"
    strings:
	$s1 =".no-ip.org"
        $s2 =".publicvm.com"
        $s3 =".linkpc.net"
        $s4 =".dynu.com"
        $s5 =".dynu.net"
        $s6 =".afraid.org"
        $s7 =".chickenkiller.com"
        $s8 =".crabdance.com"
        $s9 =".ignorelist.com"
        $s10 =".jumpingcrab.com"
        $s11 =".moo.com"
        $s12 =".strangled.com"
        $s13 =".twillightparadox.com"
        $s14 =".us.to"
        $s15 =".strangled.net"
        $s16 =".info.tm"
        $s17 =".homenet.org"
        $s18 =".biz.tm"
        $s19 =".continent.kz"
        $s20 =".ax.lt"
        $s21 =".system-ns.com"
        $s22 =".adultdns.com"
        $s23 =".craftx.biz"
        $s24 =".ddns01.com"
        $s25 =".dns53.biz"
        $s26 =".dnsapi.info"
        $s27 =".dnsd.info"
        $s28 =".dnsdynamic.com"
        $s29 =".dnsdynamic.net"
        $s30 =".dnsget.org"
        $s31 =".fe100.net"
        $s32 =".flashserv.net"
        $s33 =".ftp21.net"
    condition:
        any of them
}

rule network_toredo {
    meta:
        author = "x0r"
        description = "Communications over Toredo network"
	      version = "0.1"
    strings:
	      $f1 = "FirewallAPI.dll" nocase
        $p1 = "\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\Interfaces\\" nocase
    condition:
        all of them
}

rule network_smtp_dotNet {
    meta:
        author = "x0r"
        description = "Communications smtp"
	      version = "0.1"
    strings:
	      $f1 = "System.Net.Mail" nocase
        $p1 = "SmtpClient" nocase
    condition:
        all of them
}

rule network_smtp_raw {
  meta:
        author = "x0r"
        description = "Communications smtp"
	      version = "0.1"
  strings:
	      $s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
  condition:
        all of them
}

rule network_smtp_vb {
    meta:
        author = "x0r"
        description = "Communications smtp"
	      version = "0.1"
    strings:
	      $c1 = "CDO.Message" nocase
        $c2 = "cdoSMTPServer" nocase
        $c3 = "cdoSendUsingMethod" nocase
        $c4 = "cdoex.dll" nocase
        $c5 = "/cdo/configuration/smtpserver" nocase
    condition:
        any of them
}

rule network_p2p_win {
    meta:
        author = "x0r"
        description = "Communications over P2P network"
	      version = "0.1"
    strings:
     	$c1 = "PeerCollabExportContact"
     	$c2 = "PeerCollabGetApplicationRegistrationInfo"
     	$c3 = "PeerCollabGetEndpointName"
     	$c4 = "PeerCollabGetEventData"
     	$c5 = "PeerCollabGetInvitationResponse"
     	$c6 = "PeerCollabGetPresenceInfo"
     	$c7 = "PeerCollabGetSigninOptions"
     	$c8 = "PeerCollabInviteContact"
     	$c9 = "PeerCollabInviteEndpoint"
     	$c10 = "PeerCollabParseContact"
     	$c11 = "PeerCollabQueryContactData"
     	$c12 = "PeerCollabRefreshEndpointData"
     	$c13 = "PeerCollabRegisterApplication"
     	$c14 = "PeerCollabRegisterEvent"
     	$c15 = "PeerCollabSetEndpointName"
     	$c16 = "PeerCollabSetObject"
     	$c17 = "PeerCollabSetPresenceInfo"
     	$c18 = "PeerCollabSignout"
     	$c19 = "PeerCollabUnregisterApplication"
     	$c20 = "PeerCollabUpdateContact"
    condition:
        5 of them
}
rule network_tor {
    meta:
        author = "x0r"
        description = "Communications over TOR network"
	      version = "0.1"
    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
    condition:
        any of them
}
rule network_irc {
    meta:
        author = "x0r"
        description = "Communications over IRC network"
	      version = "0.1"
    strings:
        $s1 = "NICK"
        $s2 = "PING"
        $s3 = "JOIN"
        $s4 = "USER"
        $s5 = "PRIVMSG"
    condition:
        all of them
}

rule network_http {
    meta:
        author = "x0r"
        description = "Communications over HTTP"
	      version = "0.1"
    strings:
        $f1 = "wininet.dll" nocase
        $c1 = "InternetConnect"
        $c2 = "InternetOpen"
        $c3 = "InternetOpenUrl"
        $c4 = "InternetReadFile"
        $c5 = "InternetWriteFile"
        $c6 = "HttpOpenRequest"
        $c7 = "HttpSendRequest"
        $c8 = "IdHTTPHeaderInfo"
    condition:
        $f1 and $c1 and ($c2 or $c3) and ($c4 or $c5 or $c6 or $c7 or $c8)
}


rule network_ftp {
    meta:
        author = "x0r"
        description = "Communications over FTP"
	      version = "0.1"
    strings:
	      $f1 = "Wininet.dll" nocase
        $c1 = "FtpGetCurrentDirectory"
        $c2 = "FtpGetFile"
        $c3 = "FtpPutFile"
        $c4 = "FtpSetCurrentDirectory"
        $c5 = "FtpOpenFile"
        $c6 = "FtpGetFileSize"
        $c7 = "FtpDeleteFile"
        $c8 = "FtpCreateDirectory"
        $c9 = "FtpRemoveDirectory"
        $c10 = "FtpRenameFile"
        $c11 = "FtpDownload"
        $c12 = "FtpUpload"
        $c13 = "FtpGetDirectory"
    condition:
        $f1 and (4 of ($c*))
}

rule network_tcp_socket {
    meta:
        author = "x0r"
        description = "Communications over RAW socket"
	      version = "0.1"
    strings:
	      $f1 = "Ws2_32.dll" nocase
        $f2 = "wsock32.dll" nocase
        $c1 = "WSASocket"
        $c2 = "socket"
        $c3 = "send"
        $c4 = "WSASend"
        $c5 = "WSAConnect"
        $c6 = "connect"
        $c7 = "WSAStartup"
        $c8 = "closesocket"
        $c9 = "WSACleanup"
    condition:
        1 of ($f*) and 2 of ($c*)
}

rule network_dns {
    meta:
        author = "x0r"
        description = "Communications use DNS"
	      version = "0.1"
    strings:
        $f1 = "System.Net"
        $f2 = "Ws2_32.dll" nocase
        $f3 = "Dnsapi.dll" nocase
        $f4 = "wsock32.dll" nocase
        $c2 = "GetHostEntry"
	      $c3 = "getaddrinfo"
	      $c4 = "gethostbyname"
	      $c5 = "WSAAsyncGetHostByName"
	      $c6 = "DnsQuery"
    condition:
        1 of ($f*) and  1 of ($c*)
}

rule network_ssl {
    meta:
        author = "x0r"
        description = "Communications over SSL"
        version = "0.1"
    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "IdSSLOpenSSL" nocase
    condition:
        any of them
}

rule network_dga {
    meta:
        author = "x0r"
        description = "Communication using dga"
	      version = "0.1"
    strings:
        $dll1 = "Advapi32.dll" nocase
        $dll2 = "wininet.dll" nocase
	      $dll3 = "Crypt32.dll" nocase
        $time1 = "SystemTimeToFileTime"
        $time2 = "GetSystemTime"
        $time3 = "GetSystemTimeAsFileTime"
        $hash1 = "CryptCreateHash"
        $hash2 = "CryptAcquireContext"
        $hash3 = "CryptHashData"
        $net1 = "InternetOpen"
        $net2 = "InternetOpenUrl"
        $net3 = "gethostbyname"
        $net4 = "getaddrinfo"
    condition:
        all of ($dll*) and 1 of ($time*) and 1 of ($hash*) and 1 of ($net*)
}
rule lookupip {
    meta:
        author = "x0r"
        description = "Lookup external IP"
	      version = "0.1"
    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
    condition:
        any of them
}

rule dyndns {
    meta:
        author = "x0r"
        description = "Dynamic DNS"
	      version = "0.1"
    strings:
        $s1 = "SOFTWARE\\Vitalwerks\\DUC" nocase
    condition:
        any of them
}

rule lookupgeo {
    meta:
        author = "x0r"
        description = "Lookup Geolocation"
      	version = "0.1"
    strings:
        $n1 = "j.maxmind.com" nocase
    condition:
        any of them
}
rule sniff_lan {
    meta:
        author = "x0r"
        description = "Sniff Lan network traffic"
	      version = "0.1"
    strings:
        $f1 = "packet.dll" nocase
        $f2 = "npf.sys" nocase
        $f3 = "wpcap.dll" nocase
        $f4 = "winpcap.dll" nocase
    condition:
        any of them
}
rule spreading_file {
    meta:
        author = "x0r"
        description = "Malware can spread east-west file"
	      version = "0.1"
    strings:
        $f1 = "autorun.inf" nocase
        $f2 = "desktop.ini" nocase
        $f3 = "desktop.lnk" nocase
    condition:
        any of them
}
rule spreading_share {
    meta:
        author = "x0r"
        description = "Malware can spread east-west using share drive"
        version = "0.1"
    strings:
        $f1 = "netapi32.dll" nocase
        $c1 = "NetShareGetInfo"
        $c2 = "NetShareEnum"
    condition:
        $f1 and 1 of ($c*)
}

rule rat_vnc {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit VNC"
	      version = "0.1"
    strings:
        $f1 = "ultravnc.ini" nocase
        $c2 = "StartVNC"
        $c3 = "StopVNC"
    condition:
        any of them
}

rule rat_rdp {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable RDP"
	      version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" nocase
        $p2 = "software\\microsoft\\windows nt\\currentversion\\terminal server" nocase
        $p3 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" nocase
        $r1 = "EnableAdminTSRemote"
        $c1 = "net start termservice"
        $c2 = "sc config termservice start"
    condition:
        any of them
}

rule rat_telnet {
    meta:
        author = "x0r"
        description = "Remote Administration toolkit enable Telnet"
        version = "0.1"
    strings:
        $r1 = "software\\microsoft\\telnetserver" nocase
    condition:
        any of them
}
