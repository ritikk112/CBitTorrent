This is a Torrent Client built in C++ and facilitated through CMake.

Following are the supported commands from the get-go for the included sample.torrent file




1) ./your_bittorrent.sh decode <bencoded string>                                 :->     For decoding the bencoded string passed as an argument 
2) ./your_bittorrent.sh info sample.torrent                                      :->     For extracting the information from the torrent file and displaying the output on the terminal
3) ./your_bittorrent.sh peers sample.torrent                                     :->     For extracting available peers information of the given torrent file.
4) ./your_bittorrent.sh handshake sample.torrent <peer_ip>:<peer_port>           :->     For obtaining the PeerId
5) ./your_bittorrent.sh download_piece -o /tmp/test-piece-0 sample.torrent 0     :->     For downloading the piece 0 from the available hashed pieces
6) ./your_bittorrent.sh download -o /tmp/test.txt sample.torrent                 :->     For downloading the whole file through sample.torrent

