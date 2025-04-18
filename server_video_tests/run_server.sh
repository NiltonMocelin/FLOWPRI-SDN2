if [ ! -e mediamtx ]; then
	wget -o- https://github.com/bluenviron/mediamtx/releases/download/v1.12.0/mediamtx_v1.12.0_linux_amd64.tar.gz]]
	tar -xvf mediamtx_v1.12.0_linux_amd64.tar.gz
fi
./mediamtx
