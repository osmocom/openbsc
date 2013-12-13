"
Simple UDP replay from the state files
"

PackageLoader fileInPackage: #Sockets.
FileStream fileIn: 'rtp_replay_shared.st'.


Eval [
    | replay file host dport |

    file := Smalltalk arguments at: 1 ifAbsent: [ 'rtpstream.state' ].
    host := Smalltalk arguments at: 2 ifAbsent: [ '127.0.0.1' ].
    dport := (Smalltalk arguments at: 3 ifAbsent: [ '4000' ]) asInteger.
    sport := (Smalltalk arguments at: 4 ifAbsent: [ '0' ]) asInteger.

    replay := RTPReplay on: file fromPort: sport.

    Transcript nextPutAll: 'Going to stream now'; nl.
    replay streamAudio: host port: dport.
]
