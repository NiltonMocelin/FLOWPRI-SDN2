sudo apt-get update

sudo apt update
sudo apt install build-essential zlib1g-dev libncurses5-dev libgdbm-dev libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev wget libbz2-dev gcc python-dev  libxml2-dev libxslt1-dev -y

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
pip install beautifulsoup4==4.13.3
pip install certifi==2024.12.14
pip install cffi==1.17.1
pip install charset-normalizer==3.4.1
pip install colorlog==6.9.0
pip install Cython==3.0.12
pip install debtcollector==3.0.0
pip install dnspython==1.16.0
pip install docker==7.1.0
pip install eventlet==0.30.2
pip install google==3.0.0
pip install greenlet==3.1.1
pip install idna==3.10
pip install joblib==1.4.2
pip install mininet==2.3.0.dev6
pip install msgpack==1.1.0
pip install netaddr==1.3.0
pip install netifaces==0.11.0
pip install numpy==1.24.4
pip install oslo.config==9.6.0
pip install oslo.i18n==6.4.0
pip install ovs==3.4.1
pip install pbr==6.1.0
pip install pip==25.0.1
pip install protobuf==3.19.0
pip install psutil==7.0.0
pip install pycparser==2.22
pip install python-libpcap==0.5.2
pip install PyYAML==6.0.2
pip install pyzmq==26.2.1
pip install repoze.lru==0.7
pip install requests==2.32.3
pip install rfc3986==2.0.0
pip install Routes==2.5.1
pip install ryu==4.34
pip install wsgi
pip install sawtooth-sdk==1.2.5
pip install sawtooth-signing==1.1.5
pip install scapy==2.6.1
pip install scikit-learn==1.3.2
pip install scipy==1.10.1
pip install secp256k1==0.14.0
pip install setuptools==67.6.1
pip install six==1.17.0
pip install sortedcontainers==2.4.0
pip install soupsieve==2.6
pip install stevedore==5.3.0
pip install threadpoolctl==3.5.0
pip install tinyrpc==1.1.7
pip install toml==0.10.2
pip install typing_extensions==4.12.2
pip install urllib3==2.2.3
pip install WebOb==1.8.9
pip install wheel==0.44.0
pip install wrapt==1.17.2


# wget -o- https://github.com/NiltonMocelin/FLOWPRI-SDN2/archive/refs/heads/main.zip
# mv FLOWPRI-SDN2-main FLOWPRI-SDN2

sudo cp secp256k1.py /usr/lib/python3/dist-packages/sawtooth_signing/secp256k1.py # conferir se eh aqui que foi instalado mesmo ou se é site-packages, algo assim
