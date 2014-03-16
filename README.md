python-pop3server
=================

a python based POP3 Server implementation

due to the lack of pure python based POP3 Servers without mass of dependencies (twisted, ...) I've created 
this POP3 Protocol based implementation. The initial need for it was to get an application ported which was 
only able to use POP3 a mechanism. As Microsofts Exchange POP3 implementation isn't really Cluster able the idea
to have some kind of proxy/translater as perdition but with protocol change (for example POP3 to IMAP4).

so don't expect to much from this Proof-of-concept as the focus is only to have a single Application transparently 
talking to an IMAP server even though it's implementation is POP3 only.

==================

currently implemented:

    * POP3 Server accepting requestes forwarding to one (start up parameter based) IMAP Server
    * POP3 Protocol types:
        * QUIT
        * STAT
        * LIST
        * RETR
        * DELE
        * NOOP
        * RSET
        * TOP
        * UIDL
        * USER
        * PASS


==================

known limitations:

    POP3 is an ASCII only protocol so what ever is stored on the IMAP side is converted to ascii with flag 'ignore'. In principal 
    this shouldn't be a problem as your current implementation isn't able to read UTF8 mails too but I didn't have time to test
    all possibilities to avoid exceptions if convert doesn't work.

    seen as:
        UnicodeDecodeError: 'utf8' codec can't decode byte 0xfc in position 1847: invalid start byte

    fix assumed for 1.1


==================

Example usage:

    Terminal 1 (server):
        $ ./pop3server.py -b IMAP --backend_address=192.168.192.13 --backend_port=143 -p 10110
        serving POP3 service at 127.0.0.1:10110
        2014-03-16 17:50:03,180 [POP3Server.DEBUG 240]: S: +OK POP3 server ready
        2014-03-16 17:50:05,935 [POP3Server.DEBUG 382]: C: USER
        2014-03-16 17:50:05,936 [POP3Server.DEBUG 396]: S: +OK
        2014-03-16 17:50:09,589 [POP3Server.DEBUG 382]: C: PASS
        2014-03-16 17:50:09,589 [POP3Server.DEBUG 338]: trying to acquire Lock for michi
        2014-03-16 17:50:09,590 [POP3Server.DEBUG 342]: stating imap connection
        2014-03-16 17:50:09,590 [POP3Server.DEBUG 66]: IMAP: connecting to 192.168.192.13:143
        2014-03-16 17:50:12,281 [POP3Server.DEBUG 396]: S: +OK maildrop locked and ready
        2014-03-16 17:50:15,259 [POP3Server.DEBUG 382]: C: STAT
        2014-03-16 17:50:15,278 [POP3Server.DEBUG 99]: IMAP: fetching INBOX ['2']
        2014-03-16 17:50:15,279 [POP3Server.DEBUG 106]: IMAP: retrieve 1
        2014-03-16 17:50:15,348 [POP3Server.DEBUG 392]: S: +OK 1 81679
        2014-03-16 17:50:22,523 [POP3Server.DEBUG 382]: C: TOP
        2014-03-16 17:50:22,530 [POP3Server.DEBUG 388]: S: +OK
        2014-03-16 17:53:47,893 [POP3Server.DEBUG 382]: C: QUIT
        2014-03-16 17:53:47,894 [POP3Server.DEBUG 137]: IMAP: expunge
        2014-03-16 17:53:47,910 [POP3Server.DEBUG 392]: S: +OK POP3 server signing off

    Terminal 2 (client):
        $ telnet localhost 10110
        Trying 127.0.0.1...
        Connected to localhost.
        Escape character is '^]'.
        +OK POP3 server ready
        USER michi
        +OK
        PASS xxxxxxxx
        STAT
        +OK maildrop locked and ready
        TOP 1 10
        +OK
        ...
        Header + 10 Lines Body supressed ... 
        QUIT
        +OK POP3 server signing off
