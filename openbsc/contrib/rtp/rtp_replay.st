"
Simple UDP replay from the state files
"

PackageLoader fileInPackage: #Sockets.

Eval [
    | last_time last_image udp_send socket dest |

    last_time := nil.
    last_image := nil.
    file := FileStream open: 'rtp_ssrc13529910.240.240.1_to_10.240.240.50.state'.

    "Send the payload"
    dest := Sockets.SocketAddress byName: '127.0.0.1'.
    socket := Sockets.DatagramSocket new.
    udp_send := [:payload | | datagram |
        datagram := Sockets.Datagram data: payload contents address: dest port: 4000.
        socket nextPut: datagram
    ].

    [file atEnd] whileFalse: [
        | lineStream time data now_image |
        lineStream := file nextLine readStream.

        "Read the time, skip the blank, parse the data"
        time := Number readFrom: lineStream.
        lineStream skip: 1.

        data := WriteStream on: (ByteArray new: 30).
        [lineStream atEnd] whileFalse: [
            | hex |
            hex := lineStream next: 2.
             data nextPut: (Number readFrom: hex readStream radix: 16).
        ].

        last_time isNil
            ifTrue: [
                "First time, send it right now"
                last_time := time.
                last_image := Time millisecondClockValue.
                udp_send value: data.
            ]
            ifFalse: [
                | wait_image new_image_time |

                "How long to wait?"
                wait_image := last_image + ((time - last_time) * 1000).
                [ wait_image > Time millisecondClockValue ] whileTrue: [].

                udp_send value: data.
                last_time := time.
                last_image := wait_image.
            ]
    ].
]
