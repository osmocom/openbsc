"
Simple UDP replay from the state files
"

PackageLoader fileInPackage: #Sockets.
FileStream fileIn: 'rtp_replay_shared.st'.


Eval [
    | replay |


    replay := RTPReplay on: 'rtp_ssrc6976010.240.240.1_to_10.240.240.50.state'.

    Transcript nextPutAll: 'Going to stream now'; nl.
    replay streamAudio: '127.0.0.1' port: 4000.
]
