- Set up the environment:
python setup_environment.py --dependencies

-Install system dependencies:
sudo apt update
sudo apt install -y python3-dev python3-pip nmap nikto aircrack-ng sqlmap masscan metasploit-framework john lynis chkrootkit macchanger net-tools tor tor-geoipdb proxychains netcat-openbsd curl build-essential libssl-dev libffi-dev libxml2-dev libxslt1-dev libz-dev libreadline-dev

- Install dependencies:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

- Start the interactive tester:
sudo systemctl enable tor
sudo systemctl start tor
sudo python interactive_system_tester.py


======= AUTOMATE INSTALL PACKAGE AND RUN APP =======

1. Make the setup script executable:

chmod +x setup.sh
chmod +x run.sh

2. Run the setup script with root privileges:

sudo ./setup.sh
./run.sh

