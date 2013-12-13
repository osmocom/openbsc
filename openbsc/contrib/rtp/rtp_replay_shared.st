"
Simple UDP replay from the state files
"

PackageLoader fileInPackage: #Sockets.

Object subclass: SDPUtils [
    "Look into using PetitParser."
    SDPUtils class >> findPort: aSDP [
        aSDP linesDo: [:line |
            (line startsWith: 'm=audio ') ifTrue: [
                | stream |
                stream := line readStream
                            skip: 'm=audio ' size;
                            yourself.
                ^ Number readFrom: stream.
            ]
        ].

        ^ self error: 'Not found'.
    ]

    SDPUtils class >> findHost: aSDP [
        aSDP linesDo: [:line |
            (line startsWith: 'c=IN IP4 ') ifTrue: [
                | stream |
                ^ stream := line readStream
                            skip: 'c=IN IP4 ' size;
                            upToEnd.
            ]
        ].

        ^ self error: 'Not found'.
    ]
]

Object subclass: RTPReplay [
    | filename socket |
    RTPReplay class >> on: aFile [
        ^ self new
            initialize;
            file: aFile; yourself
    ]

    RTPReplay class >> on: aFile fromPort: aPort [
        ^ self new
            initialize: aPort;
            file: aFile; yourself
    ]

    initialize [
        self initialize: 0.
    ]

    initialize: aPort [
        socket := Sockets.DatagramSocket local: '0.0.0.0' port: aPort.
    ]

    file: aFile [ 
        filename := aFile
    ]

    localPort [
        ^ socket port
    ]

    streamAudio: aHost port: aPort [
        | file last_time last_image udp_send dest |

        last_time := nil.
        last_image := nil.
        file := FileStream open: filename mode: #read.

        "Send the payload"
        dest := Sockets.SocketAddress byName: aHost.
        udp_send := [:payload | | datagram |
            datagram := Sockets.Datagram data: payload contents address: dest port: aPort.
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
                    [ wait_image > Time millisecondClockValue ]
                        whileTrue: [Processor yield].

                    udp_send value: data.
                    last_time := time.
                    last_image := wait_image.
                ]
        ]
    ]
]

