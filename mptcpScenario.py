import paramiko
import time
import ftplib
import os
import time

def confRouters(SC):
		USER = 'cisco'
		command = 'conf t\n policy-map mptcp\n class CM.10.1_20.1\n  shape average '+SC[0]+'\n class CM.10.1_21.1\n  shape average '+SC[1]+'\n class CM.11.1_20.1\n  shape average '+SC[2]+'\n class CM.11.1_21.1\n  shape average '+SC[3]+'\n end\n wr\n !\n !\n'
		Routers = ['192.168.10.254','192.168.20.254']
        print("01---BEGIN Configuration of routers---")
		for Router in Routers:
			print("config in router : ",Router)
			ssh = paramiko.SSHClient()
			ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh.connect(hostname=Router,username=USER, password=USER, port=22, look_for_keys=False, allow_agent=False)
			connection = ssh.invoke_shell()
			connection.send(command)
			time.sleep(2)
			output = connection.recv(65535)
			print(output)
			ssh.close
        print("01---END Configuration of routers---")

def ftpFct(FtpHost,FtpUser):
    print("03---BEGIN FTP trasfert")
    ftp_server = ftplib.FTP(FtpHost, FtpUser, FtpUser)
    ftp_server.encoding = "utf-8"
    fileToUpload = "/home/mptcp/5Gbits"
    with open(fileToUpload, "rb") as file:
        ftp_server.storbinary(f"STOR {fileToUpload}", file) 
    print("03---END FTP trasfert")

def senario(Scenario,SCHED,CC):
	schedAndCc = {"balia": 'sudo insmod /home/mptcp/07_balialog/mptcp_balia_log.ko\nsudo sysctl net.ipv4.tcp_congestion_control=balia_log\n',
		      "olia" : 'sudo insmod /home/mptcp/06_olialog/mptcp_olia_log.ko\nsudo sysctl net.ipv4.tcp_congestion_control=olia_log\n',
		      "lia"  : 'sudo insmod /home/mptcp/05_lialog/mptcp_lia_log.ko\nsudo sysctl net.ipv4.tcp_congestion_control=lia_log\n',
	              "ecf"  : 'sudo insmod /home/mptcp/03_ecflog/mptcp_ecf_log.ko\nsudo sysctl net.mptcp.mptcp_scheduler=ecf_log\n',
	              "blest": 'sudo insmod /home/mptcp/04_blestlog/mptcp_blest_log.ko\nsudo sysctl net.mptcp.mptcp_scheduler=blest_log\n',
	              "rr"   : 'sudo insmod /home/mptcp/02_rrlog/mptcp_rr_log.ko\nsudo sysctl net.mptcp.mptcp_scheduler=rr_log\n',
	              "syslog": 'sudo truncate -s 0 /var/log/syslog\nsudo service syslog restart\n',
	      }
	print("02---BEGIN Dataset creation for sched= "+SCHED+" & CC= "+CC+"+ in MPTCP server & Scenario= "+Scenario+"---")
	os.system(schedAndCc[CC])
	os.system(schedAndCc[SCHED])
	os.system(schedAndCc["syslog"])
	ClientsFtp=['192.168.20.1']
	userFtp='mptcp'
	ftpFct(ClientFtp,userFtp)
    time.sleep(600)
    os.system("awk '{print $9}' /var/log/syslog > " + Scenario+"_"+SCHED+"_"+CC+"_.csv")
	print("02---END Dataset creation for sched= "+SCHED+" & CC= "+CC+"+ in MPTCP server & Scenario= "+Scenario+"---")
♯ sc15 : list of Bandwidth of each sub-flow [Bw_Path1, Bw_Path2, Bw_Path3, Bw_Path4]
sc15 = ['100m', '65m', '30m','5m']
♯ confRouters : Apply bandwidths on routers
confRouters(sc15)
♯ confRouters : configure schedules & congestion control algorithms on the server
senario("sc15","rr","lia")
senario("sc15","rr","olia")
senario("sc15","rr","balia")

senario("sc15","ecf","lia")
senario("sc15","ecf","olia")
senario("sc15","ecf","balia")

senario("sc15","blest","lia")
senario("sc15","blest","olia")
senario("sc15","blest","balia")
