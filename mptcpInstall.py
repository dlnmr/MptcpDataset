import os
import time

def conf_ssh():
	search_text0 = "#PermitRootLogin prohibit-password"
	replace_text0 = "PermitRootLogin yes"
	os.system('sudo chmod 777 /etc/ssh/sshd_config')
	with open(r'/etc/ssh/sshd_config', 'r') as file:
		dataSsh = file.read()
		dataSsh = dataSsh.replace(search_text0, replace_text0)
	with open(r'/etc/ssh/sshd_config', 'w') as file:
		file.write(dataSsh)	
	os.system('service ssh restart')
	
def conf_grup():	
	search_text1  = "GRUB_TIMEOUT_STYLE=hidden"
	replace_text1 = "GRUB_TIMEOUT_STYLE=menu"
	search_text2  = "GRUB_TIMEOUT=0"
	replace_text2 = "GRUB_TIMEOUT=5"
	search_text3  = "GRUB_DEFAULT=0"
	replace_text3 = "GRUB_DEFAULT=1"
	os.system('sudo chmod 777 /etc/default/grub')
	with open(r'/etc/default/grub', 'r') as file:
		data = file.read()
		data = data.replace(search_text1, replace_text1)
		data = data.replace(search_text2, replace_text2)
		data = data.replace(search_text3, replace_text3)
	with open(r'/etc/default/grub', 'w') as file:
		file.write(data)	
	os.system('sudo update-grub')

def conf_ftp():	
	search_text4  = "#write_enable=YES"
	replace_text4 = "write_enable=YES"
	os.system('sudo chmod 777 /etc/vsftpd.conf')
	with open(r'/etc/vsftpd.conf', 'r') as file:
		print('/etc/vsftpd.conf')
		dataFtp = file.read()
		dataFtp = dataFtp.replace(search_text4, replace_text4)
	with open(r'/etc/vsftpd.conf', 'w') as file:
		print('/etc/vsftpd.conf')
		file.write(dataFtp)	
	os.system('sudo service vsftpd restart')
	
	
print("choice of installation steps                  ")
print("0-Install tool & config mptcp user & root     ")
print("1-Install Mptcp kernel v-96                   ")
print("2-config grub ssh ftp tcp                     ")
print("3-Download and compil all source code         ")
choix = input()
if choix == '0' :
	os.system('sudo apt-get update')
	os.system('sudo apt-get install openssh-server vsftpd apache2 make gcc python3-pip')
	os.system('pip install paramiko')	
	time.sleep(10)
	print('***creating new user "mptcp"***\n We recommend the mptcp password for mptcp user\n to facilitate the reproduction of the dataset \nfor future deployment and testing \n')
	time.sleep(10)
	os.system('sudo adduser mptcp\n')
	os.system('sudo passwd\n')
	time.sleep(10)
	print('***enter the new password for the root***\n We recommend the "root" password for root\n to facilitate the reproduction of the dataset \nfor future deployment and testing \n')
	time.sleep(10)
	os.system('sudo passwd root\n')
if choix == '1' :
	os.system('sudo chmod -R 777  /home/mptcp/')
	os.chdir('/home/mptcp')
	print("Current working directory:", os.getcwd() )
	time.sleep(10)
	os.mkdir('01_debFiles96')
	os.chdir('01_debFiles96')
	os.system('wget https://github.com/multipath-tcp/mptcp/releases/download/v0.96/linux-headers-5.4.230.mptcp_20230203134326-1_amd64.deb')
	os.system('wget https://github.com/multipath-tcp/mptcp/releases/download/v0.96/linux-image-5.4.230.mptcp-dbg_20230203134326-1_amd64.deb')
	os.system('wget https://github.com/multipath-tcp/mptcp/releases/download/v0.96/linux-image-5.4.230.mptcp_20230203134326-1_amd64.deb')
	os.system('wget https://github.com/multipath-tcp/mptcp/releases/download/v0.96/linux-libc-dev_20230203134326-1_amd64.deb')
	os.system('wget https://github.com/multipath-tcp/mptcp/releases/download/v0.96/linux-mptcp_v0.96_20230203134326-1_all.deb ')
	os.system('sudo dpkg -i *.deb')
	os.chdir('../')
if choix == '2' :
	conf_grup()
	conf_ftp()
	conf_ssh()
	os.system('sudo chmod 777  /etc/sysctl.conf')
	os.system('sudo echo net.ipv4.tcp_no_metrics_save = 1 >> /etc/sysctl.conf\n')
	os.system('sudo echo net.core.wmem_max=131072 >> /etc/sysctl.conf\n')
	os.system('sudo echo net.core.rmem_max=131072 >> /etc/sysctl.conf\n')
	os.system('sudo echo net.ipv4.tcp_rmem= 131072 131072 131072 >> /etc/sysctl.conf\n')
	os.system('sudo echo net.ipv4.tcp_wmem= 131072 131072 131072 >> /etc/sysctl.conf\n')
	os.system('dd if=/dev/zero of=5Gbits bs=1024 count=625000\n')
	os.system('sudo mv 5Gbits /home/mptcp/5Gbits\n')
	os.system('sudo chmod 777  /home/mptcp/5Gbits')
	print(' !!!!!  !!!!!  !!!!! warning !!!!!  !!!!!  !!!!! \n now we have two kernels, to be able to start the system with the mptcp kernel we must click on:\n *Advanced options for Ubuntu\nthen on:\n *Ubuntu, with Linux 5.4.230.mptcp')
	time.sleep(10)
	os.system('sudo reboot')
if choix == '3' :
	os.chdir('/home/mptcp')
	listCode = ["rr","ecf","blest","lia","olia","balia"]
	i=2
	for code in listCode:
		filecode="0"+str(i)+"_"+code+"log"
		os.mkdir(filecode)
		os.chdir(filecode)
		wgetUrl='wget https://raw.githubusercontent.com/dlnmr/MptcpDataset/main/'+code+'/Makefile'
		os.system(wgetUrl)
		wgetUrl='wget https://raw.githubusercontent.com/dlnmr/MptcpDataset/main/'+code+'/mptcp_'+code+'_log.c'
		os.system(wgetUrl)
		os.system('make')
		os.chdir('../')
		i+=1
	os.system('sudo chmod -R 777  /home/mptcp/')
