#echo "Abrindo stream com vlc"
#vlc --network-caching=50 rtsp://localhost:8554/mystream

echo "Abrindo stream com ffmpeg"
ffplay -rtsp_transport tcp rtsp://localhost:8554/mystream
