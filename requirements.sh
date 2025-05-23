echo "OS suposto UBUNTU"

sudo apt-get update

sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev gcc libxml2-dev libxslt1-dev -y

# install python3.8
wget https://www.python.org/ftp/python/3.8.0/Python-3.8.0.tgz
tar -xf Python-3.8.0.tgz
cd Python-3.8.0
./configure --enable-optimizations
make -j 8
sudo make altinstall
cd ..

sudo apt-get install openvswitch-switch openvswitch-switch-dpdk openvswitch-common -y

# dependencias
sudo apt-get install tcptrace -y

sudo pip3.8 install pip==25.0.1
sudo pip3.8 install wheel==0.44.0
sudo pip3.8 install Cython==3.0.12
sudo pip3.8 install toml==0.10.2
sudo pip3.8 install beautifulsoup4==4.13.3
sudo pip3.8 install certifi==2024.12.14
sudo pip3.8 install cffi==1.17.1
sudo pip3.8 install charset-normalizer==3.4.1
sudo pip3.8 install colorlog==6.9.0
sudo pip3.8 install debtcollector==3.0.0
sudo pip3.8 install dnspython==1.16.0
sudo pip3.8 install docker==7.1.0
sudo pip3.8 install eventlet==0.30.2
sudo pip3.8 install google==3.0.0
sudo pip3.8 install greenlet==3.1.1
sudo pip3.8 install idna==3.10
sudo pip3.8 install joblib==1.4.2
# sudo pip3.8 install mininet==2.3.0.dev6
sudo pip3.8 install netaddr==1.3.0
sudo pip3.8 install netifaces==0.11.0
sudo pip3.8 install numpy==1.24.4
sudo pip3.8 install oslo.config==9.6.0
sudo pip3.8 install oslo.i18n==6.4.0
sudo pip3.8 install pbr==6.1.0
sudo pip3.8 install protobuf==3.19.0
sudo pip3.8 install psutil==7.0.0
sudo pip3.8 install pycparser==2.22
sudo pip3.8 install PyYAML==6.0.2
sudo pip3.8 install pyzmq==26.2.1
sudo pip3.8 install repoze.lru==0.7
sudo pip3.8 install requests==2.32.3
sudo pip3.8 install rfc3986==2.0.0
sudo pip3.8 install Routes==2.5.1
sudo pip3.8 install sawtooth-sdk==1.2.5
sudo pip3.8 install sawtooth-signing==1.1.5
sudo pip3.8 install scapy==2.6.1
sudo pip3.8 install scikit-learn==1.3.2
sudo pip3.8 install scipy==1.10.1
sudo pip3.8 install secp256k1==0.14.0
sudo pip3.8 install setuptools==67.6.1
sudo pip3.8 install six==1.17.0
sudo pip3.8 install sortedcontainers==2.4.0
sudo pip3.8 install soupsieve==2.6
sudo pip3.8 install stevedore==5.3.0
sudo pip3.8 install threadpoolctl==3.5.0
sudo pip3.8 install tinyrpc==1.1.7
sudo pip3.8 install typing_extensions==4.12.2
sudo pip3.8 install urllib3==2.2.3
sudo pip3.8 install WebOb==1.8.9
sudo pip3.8 install wrapt==1.17.2
sudo pip3.8 install msgpack==1.1.0 # deu erro instalando, mas no fim achou com o ryu
sudo pip3.8 install ryu==4.34
sudo pip3.8 install ovs==3.4.1
sudo apt-get install libpcap-dev -y
sudo pip3.8 install python-libpcap
sudo apt-get install iperf -y # para testes
sudo pip3.8 install httpx
# sudo pip3.8 install wsgi # deu erro, deixamos fora, só era usado pela GUI, que não sera ativada agora

# wget -o- https://github.com/NiltonMocelin/FLOWPRI-SDN2/archive/refs/heads/main.zip
# mv FLOWPRI-SDN2-main FLOWPRI-SDN2

sudo cp secp256k1.py /usr/local/lib/python3.8/site-packages/sawtooth_signing/secp256k1.py # conferir se eh aqui que foi instalado mesmo ou se é site-packages, algo assim

# install docker-compose
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# criando a imagem qosblockchainv1
cd qosblockchain/one_container/; sudo docker build --debug --tag 'qosblockchainv1' .
cd ../../

# erros com ryu --> module 'setuptools.command.easy_install' has no attribute 'get_script_args' e wsgi