echo "publicando um video no server de video"
#ffmpeg -re -stream_loop -1 -i grav1.webm -c:v copy -c:a copy -f rtsp rtsp://localhost:8554/mystream
ffmpeg -re -stream_loop -1 -i vid.mp4 -f rtsp -rtsp_transport tcp rtsp://localhost:8554/mystream

