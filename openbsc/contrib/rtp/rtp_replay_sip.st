"""
Create a SIP connection and then stream...
"""

PackageLoader
    fileInPackage: #OsmoSIP.

"Load for the replay code"
FileStream fileIn: 'rtp_replay_shared.st'.


Osmo.SIPCall subclass: StreamCall [
    | sem stream |

    createCall: aSDP [
        | sdp |
        stream := RTPReplay on: 'rtp_ssrc6976010.240.240.1_to_10.240.240.50.state'.
        sdp := aSDP % {stream localPort}.
        ^ super createCall: sdp.
    ]

    sem: aSemaphore [
          sem := aSemaphore
    ]

    sessionNew [
        | host port |
        Transcript nextPutAll: 'The call has started'; nl.
        Transcript nextPutAll: sdp_result; nl.

        host := SDPUtils findHost: sdp_result.
        port := SDPUtils findPort: sdp_result.

        [
            stream streamAudio: host port: port.
            Transcript nextPutAll: 'Streaming has finished.'; nl.
        ] fork.
    ]

    sessionFailed [
        sem signal
    ]

    sessionEnd [
        sem signal
    ]
]

Eval [
    | transport agent call sem sdp_fr sdp_amr |


    sdp_fr := (WriteStream on: String new)
        nextPutAll: 'v=0'; cr; nl;
        nextPutAll: 'o=twinkle 1739517580 1043400482 IN IP4 127.0.0.1'; cr; nl;
        nextPutAll: 's=-'; cr; nl;
        nextPutAll: 'c=IN IP4 127.0.0.1'; cr; nl;
        nextPutAll: 't=0 0'; cr; nl;
        nextPutAll: 'm=audio %1 RTP/AVP 0 101'; cr; nl;
        nextPutAll: 'a=rtpmap:0 PCMU/8000'; cr; nl;
        nextPutAll: 'a=rtpmap:101 telephone-event/8000'; cr; nl;
        nextPutAll: 'a=fmtp:101 0-15'; cr; nl;
        nextPutAll: 'a=ptime:20'; cr; nl;
        contents.

    sem := Semaphore new.
    transport := Osmo.SIPUdpTransport
          startOn: '0.0.0.0' port: 5066.
    agent := Osmo.SIPUserAgent createOn: transport.
    transport start.

    call := (StreamCall
              fromUser: 'sip:1000@sip.zecke.osmocom.org'
              host: '127.0.0.1'
              port: 5060
              to: 'sip:123456@127.0.0.1'
              on: agent)
              sem: sem; yourself.

    call createCall: sdp_fr.


    "Wait for the stream to have ended"
    sem wait.

    (Delay forSeconds: 4) wait.
]
