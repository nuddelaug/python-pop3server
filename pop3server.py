#!/usr/bin/python
import email
from email.Utils import formatdate, make_msgid
from uuid import uuid5, NAMESPACE_DNS
from time import time
from hashlib import md5
from imaplib import IMAP4, IMAP4_SSL
import socket
import SocketServer
import threading
import logging
import sys

OK  = u'+OK'
ERR = u'-ERR'

logger  = logging.getLogger('POP3Server')
logger.addHandler(logging.StreamHandler(sys.stderr))
logger.addHandler(logging.FileHandler('/tmp/pop3server.log'))
for h in logger.handlers:
    h.setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s.%(levelname)s %(lineno)d]: %(message)s'))
logger.setLevel(logging.DEBUG)

monitormessage = """Message-ID: %s
Date: %s
MIME-Version: 1.0
User-Agent: Monitor Application
From: Monitor
To: Monitor
Subject: monitoring test %s

monitoring test %s
"""

class POP3Backend(object):
    """POP3 Backend Interface Class
        this class defines the methods your Backend implementation should provide
    """
    def __init__(self, protocol=None):
        """self.protocol represents handle to POP3Protocol attributes and methods"""
        self.protocol = protocol
    def authenticate(self, username=None, password=None):
        """authenticate the user with given credentials"""
        raise POP3BackendException(u'overwrite class methods with implementation')
    def fetch(self):
        """populate self.protocol.messages with what ever is in the POP3Backend maildrop for the user"""
        raise POP3BackendException(u'overwrite class methods with implementation')
    def delete(self, num=None):
        """remove given item identifier fro the POP3Backend maildrop"""
        raise POP3BackendException(u'overwrite class methods with implementation')
    def cleanup(self):
        """cleanup the POP3Backend maildrop for the user (eq. remove files, delete tables, expunge ..."""
        raise POP3BackendException(u'overwrite class methods with implementation')
    def revert(self):
        """revert already marked items for deletion/rollback  transactions, ..."""
        raise POP3BackendException(u'overwrite class methods with implementation')
    def destroy(self):
        """close handles for POP3Backend"""
        raise POP3BackendException(u'overwrite class methods with implementation')
    
class POP3Backend_IMAP(POP3Backend):
    """IMAP based Backend
    this backend provides the "translation" between POP3 and IMAP details as follows:
    
    * IMAP message -> converted -> ascii (flag ignore=just leave the character out of the Unicode result)
    * IMAP INBOX messages only (if you filter move messages to subfolders they are not recognized by the Backend)
    * POP3 -> plain text authentication only (as this is proxied to the remote)
    * IMAP special user monitor, the user monitor with pwd monitor is used for unittesting and monitoring purpose
    """
    def __init__(self, protocol=None, host=None, port=143, timeout=5.0):
        super(POP3Backend_IMAP, self).__init__(protocol)
        self.host   = host
        self.port   = int(port)
        self._imap  = None
        self.state  = None
        self.timeout= float(timeout)
    def __connect__(self):
        try:
            logger.debug(u'IMAP: connecting to %s:%s' % (self.host, self.port))
            self._imap  = IMAP4(self.host, self.port)
            self._imap.socket().settimeout(self.timeout)
        except Exception, e:
            logger.error(u'%s' % str(e))
            self.state = str(e)
            return False
        return True
    def authenticate(self, username=None, password=None):
        """try to proxy authenticate agains IMAP with POP3 given values"""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor':
            return True
        try:
            if not self.__connect__():
                return False
            rsp = self._imap.login(self.protocol._pop3user, self.protocol._pop3pass) 
            if rsp[0] != 'OK':
                logger.debug(u'IMAP: response: %s' % str(rsp))
                return False
            return True
        except Exception, e:
            logger.error(u'IMAP: authenticate: %s' % str(e))
            self.state = str(e)
            self._imap = None
    def fetch(self):
        """retrieve all messages from IMAP spool limited to 10 for testing"""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor':
            id = uuid5(NAMESPACE_DNS, str(time()))
            self.messages = [ POP3Message(content=monitormessage % (make_msgid(), formatdate(), id, id)) ] 
            return True
        try:
            if self._imap == None:
                if not self.authenticate():
                    return False
            r, n = self._imap.select('INBOX')
            logger.debug(u'IMAP: fetching INBOX %s' % n)
            n   = int(n[0])
            if n == 0:  return True
            # limit for now
            #if n > 10:  n = 10
            if n == 1:  n = 2
            for n in range(1, n):
                logger.debug(u'IMAP: retrieve %s' % n)
                r, c = self._imap.fetch(n, '(RFC822)')
                self.protocol.messages.append(POP3Message(content=c[0][1]))
            return True
        except Exception, e:
            logger.error(u'IMAP: fetch: %s' % str(e))
            self._imap = None
            self.state = str(e)
            return False
    def delete(self, num=None):
        """delete (==flag) message (num=xx) from IMAP spool"""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor': return True
        try:
            if self._imap == None:
                if not self.authenticate():
                    return False
            logger.debug(u'IMAP: setting +FLAGS: %s' % num)
            self._imap.store(num, '+FLAGS', '\\Seen \\Deleted')
            self.protocol._deleted.append(num)
            del self.protocol.messages[num]
            return True
        except Exception, e:
            logger.error(u'IMAP: delete: %s' % str(e))
            self._imap = None
            self.state = str(e)
            return False
    def cleanup(self):
        """purge all marked message from IMAP spool"""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor': return True
        try:
            if self._imap == None:
                if not self.authenticate():
                    return False
            logger.debug(u'IMAP: expunge')
            self._imap.expunge()
            return True
        except Exception, e:
            logger.error(u'IMAP: cleanup: %s' % str(e))
            self._imap = None
            self.state = str(e)
            return False
    def revert(self):
        """revert deleted (==flaged) message from IMAP spool"""
        if self.protocol._pop3user == 'monitor' and self.protocol._pop3pass == 'monitor': return True
        try:
            if self._imap == None:
                if not self.authenticate():
                    return False
            for num in self.protocol._deleted:
                logger.debug(u'IMAP: setting -FLAGS: %s' % num)
                self._imap.store(num, '-FLAGS', '\\Seen \\Deleted')
        except Exception, e:
            logger.error(u'IMAP: revert: %s' % str(e))
            self._imap = None
            self.state = str(e)
            return False

class POP3Backend_IMAPS(POP3Backend_IMAP):
    """IMAP based Backend using SSL as transport
    currently no certificate hanlding is done, silently ignored
    """
    def __init__(self, protocol=None, host=None, port=993, timeout=5.0):
        super(POP3Backend_IMAPS, self).__init__(protocol)
        self.host   = host
        self.port   = int(port)
        self._imap  = None
        self.state  = None
        self.timeout= float(timeout)
    def __connect__(self):
        try:
            logger.debug(u'IMAP: connecting to %s:%s' % (self.host, self.port))
            self._imap  = IMAP4_SSL(self.host, self.port)
            self._imap.socket().settimeout(self.timeout)
        except Exception, e:
            logger.error(u'%s' % str(e))
            self.state = str(e)
            return False
        return True

class MailboxLocker(object):
    """POP3 Mailboxes are single connected, meaning if a user already authenticated successful all others
    using the same credentials are not allowed to access the same spool. (this would be possible through the
    backend but breaks POP3 protocol).
    
    """
    def __init__(self):
        self.mailboxes  = {}
        self._lock      = threading.Lock()
    def is_locked(self, name=None):
        """return lock status of name=xx"""
        return self.mailboxes.get(name, False)
    def acquire(self):
        """inline function to unique locking through all the threads"""
        return self._lock.acquire()
    def release(self):
        """inline function to unique locking through all the threads"""
        try:    self._lock.release()
        except ThreadError: return False
        return True
    def acquire_mailbox(self, name=None):
        """retrieve a lock for a specific mailbox name=xx"""
        self.acquire()
        m   = self.mailboxes.get(name, False)
        if m != False:  
            self.release()
            return False
        self.mailboxes[name] = True
        self.release()
        return True
    def release_mailbox(self, name=None):
        """release the lock for a specific mailbox name=xx"""
        self.acquire()
        m   = self.mailboxes.get(name, False)
        if m == False:  
            self.release()
            return False
        self.mailboxes[name] = False
        self.release()
        return True

class POP3Message(object):
    """represents a POP3 Message to be displayed on the User MUA"""
    def __init__(self, content=None):
        if content != None:
            self.content = email.message_from_string(content)
        else:
            self.content    = None
    def get_headers(self):
        """return only the headers of the messages"""
        return '\n'.join(self.content.values())
    def get_body(self):
        """return the body of the message"""
        content = ''
        for payload in self.content.get_payload():
            content += str(payload)
        return content
    def as_string(self):
        """return the complete message"""
        return self.content.as_string()
    def unique_id(self):
        """return a unique ID (based upon POP3 impl. md5 sum of message content)"""
        return md5(str(self.content)).hexdigest()
    def __len__(self):
        return len(self.content.as_string())

class POP3ServerProtocol(SocketServer.BaseRequestHandler):
    """the POP3 Server protocol implementation
        http://tools.ietf.org/html/rfc1081 and http://www.ietf.org/rfc/rfc1939.txt
    """
    def setup(self):
        global Backend
        self.state      = u'authorization'
        self.messages   = []
        self._pop3user  = False
        self._pop3pass  = False
        self._deleted   = []
        self.backend    = Backend
        self.backend.protocol = self
        logger.debug(u'S: %s POP3 server ready' % OK)
        self.request.sendall(u'%s\r\n' % self.AUTHORIZATION())
    def AUTHORIZATION(self):
        """the authorization or welcome banner"""
        return u'%s POP3 server ready' % OK
    def QUIT(self):
        """quit transaction and session command"""
        global MLock
        if self.state not in (u'authorization', 'transaction', 'update'):  return u'%s POP3 invalid state for command %s' % (ERR, u'QUIT')
        if self.state == u'transaction':
            self.state = u'update'
            self.__backend_cleanup__()
        self.state = u'closed'
        if self._pop3user != False:
            MLock.release_mailbox(self._pop3user)
        return u'%s POP3 server signing off' % OK
    def STAT(self):
        """stat command returns count and size of messages to the MUA"""
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'STAT')
        if not self.__backend_fetch__():
            return u'%s %s' % (ERR, self.backend.state)
        return u'%s %d %d' % (OK, len(self.messages), self.__get_messagesize__())
    def LIST(self, msg=None):
        """list command returns either one specific or without arguments a list of all messages enumerated and size
        Examples::
            C:    LIST
            S:    +OK 2 messages (320 octets)
            S:    1 120
            S:    2 200
            S:    .
                  ...
            C:    LIST 2
            S:    +OK 2 200
        
        """
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'LIST')
        if self.messages == []:
            if not self.__backend_fetch__():
                return u'%s %s' % (ERR, self.backend.state)
        if msg != None:
            try:    content = self.__get_msg__(msg)
            except IndexError:      return u'%s no such message, only %s messages in maildrop' % (ERR, len(self.messages))
            return u'%s %s %s' % (OK, msg, len(content))
        else:
            msg = []
            for n, m in enumerate(self.messages):
                n += 1
                msg.append(u'%s %s' % (n, len(m))) 
            return u'%s %s (%s octets)\r\n%s\r\n.' % (OK, len(self.messages), self.__get_messagesize__(), '\r\n'.join(msg))
    def RETR(self, msg=None):
        """retr command returns a complete specific message"""
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'RETR')
        if self.messages == []:
            if not self.__backend_fetch__():
                return u'%s %s' % (ERR, self.backend.state)
        try:    content = self.__get_msg__(msg)
        except IndexError:
            return u'%s no such message, only %s messages in maildrop' % (ERR, len(self.messages))
        return u'%s %s octets\r\n%s\r\n.' % (OK, len(content), unicode(content.as_string(), 'utf8').encode('ascii', 'ignore'))
    def DELE(self, msg=None):
        """dele command removes a specific message from the spool"""
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'DELE')
        if self.messages == []:
            if not self.__backend_fetch__():
                return u'%s %s' % (ERR, self.backend.state)
        try:
            content = self.__get_msg__(msg)
            if not self.__backend_delete__(msg):
                return u'%s %s' % (ERR, self.backend.state)
        except IndexError:
            return u'%s message %s already deleted' % (ERR, msg)
        return u'%s message %s deleted' % (OK, msg)
    def NOOP(self):
        """noop command for idle connections to avoid tcp timeouts on firewalls or similar"""
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'NOOP')
        return u'%s' % OK
    def RSET(self):
        """rset command resets all actions taken by the MUA (dele os messages is reverted)"""
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'RSET')
        if not self.__backend_revert__():
            return u'%s %s' % (ERR, self.backend.state)
        self.messages = []
        if not self.__backend_fetch__():
            return u'%s %s' % (ERR, self.backend.state)
        return u'%s maildrop has %s messages (%s octets)' % (OK, len(self.messages), self.__get_messagesize__())
    def TOP(self, msg=None, lines=None):
        """top command returns from a specific message all headers plus n lines of the body"""
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'TOP')
        if self.messages == []:
            if not self.__backend_fetch__():
                return u'%s %s' % (ERR, self.backend.state)
        msg, lines = int(msg), int(lines)
        try:    content = self.__get_msg__(msg)
        except IndexError:
            return u'%s no such message %s' % (ERR, msg)
        return u'%s\r\n%s\r\n%s\r\n.' % (OK, content.get_headers(), '\r\n'.join(content.get_body().split('\n')[:lines]))
    def UIDL(self, msg=None):
        """uidl command returns a spool unique message id based upon the md5 hashdigest of the message"""
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'UIDL')
        if self.messages == []:
            if not self.__backend_fetch__():
                return u'%s %s' % (ERR, self.backend.state)
        if msg == None:
            l   = []
            for n, m in enumerate(self.messages):
                l.append('%s %s' % (n, m.unique_id()))
            return u'%s\r\n%s\r\n.' % (OK, '\r\n'.join(l))
        else:
            content = self.__get_msg__(msg)
            return u'%s %s %s' % (OK, msg, content.unique_id())
    def USER(self, name=None):
        """user command sets the user credentials part"""
        if self.state not in (u'authorization', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'USER')
        self._pop3user = name
        return u'%s' % OK
    def PASS(self, credentials=None):
        """pass command sets the password credentials part"""
        global MLock
        if self.state not in (u'authorization', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'PASS')
        if credentials == None:
            return u'%s invalid password' % ERR
        logger.debug(u'trying to acquire Lock for %s' % self._pop3user)
        if MLock.is_locked(self._pop3user) == True:
            return u'%s maildrop already locked' % ERR
        self._pop3pass = credentials
        logger.debug(u'stating imap connection')
        if not self.__backend_init__():
            return u'%s invalid password' % ERR
        if MLock.acquire_mailbox(self._pop3user):
            self.state = u'transaction'
        else:
            return u'%s unable to lock maildrop' % ERR
        return u'%s maildrop locked and ready' % OK
    def APOP(self, digest=None):
        """apop command An alternate method of authentication is required which
             provides for both origin authentication and replay
             protection, but which does not involve sending a password
             in the clear over the network.
             
             NOT implemented """
        if self.state not in (u'authorization', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'APOP')
        return u'%s not implemented' % ERR
    def __get_msg__(self, num=None):
        num = int(num) - 1
        return self.messages[num]
    def __get_messagesize__(self):
        c = 0
        for m in self.messages: c += len(m)
        return c
    def __backend_init__(self):
        return self.backend.authenticate(self._pop3user, self._pop3pass)
    def __backend_fetch__(self):
        return self.backend.fetch()
    def __backend_delete__(self, num=None):
        return self.backend.delete(num)
    def __backend_cleanup__(self):
        return self.backend.cleanup()
    def __backend_revert__(self):
        return self.backend.revert()
    def handle(self):
        """core routing to handle the MUA command requests"""
        while True:
            self.data   = self.request.recv(1024).strip()
            try:    
                cmd, options = self.data.split(None, 1)
                cmd = cmd.upper()
            except ValueError:
                try:    cmd = self.data.split()[0].upper()
                except IndexError:
                    cmd = 'QUIT'
                options = False
            call    = getattr(self, cmd, False)
            try:    logger.debug(u'C: %s' % unicode(cmd, 'utf8').encode('ascii', 'ignore'))
            except: logger.error(u'cannot decode client output')
            if call != False:
                if cmd in ('TOP', ):
                    opt1, opt2 = options.split(None, 1)
                    rsp = call(opt1, opt2)
                    logger.debug(u'S: %s' % str(rsp))
                    self.request.sendall(u'%s\r\n' % str(rsp))
                elif options == False:
                    rsp = call()
                    logger.debug(u'S: %s' % str(rsp))
                    self.request.sendall(u'%s\r\n' % str(rsp))
                else:
                    rsp = call(options)
                    if cmd in ('RETR', ):
                        logger.debug(u'S: %s' % str(rsp).split('\r\n')[0])
                    else:
                        logger.debug(u'S: %s' % str(rsp))
                    self.request.sendall(u'%s\r\n' % str(rsp))
                if cmd == 'QUIT':   break
            else:
                try:    logger.debug(u'%s POP3 doesn\'t support command %s\r\n' % (ERR, unicode(cmd, 'utf8').encode('ascii', 'ignore')))
                except: logger.error(u'%s POP3 doesn\'t support command output cannot be decoded' % ERR)
                self.request.sendall(u'%s POP3 doesn\'t support command\r\n' % (ERR))

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

def main(options):
    global Backend, MLock
    MLock   = MailboxLocker()
    if not options.backend.upper() in ('IMAP', 'IMAPS'):
        print u'supported Backends IMAP, IMAPS'
        sys.exit(1)
    if options.backend.upper() == 'IMAP':
        BInterface = POP3Backend_IMAP
    else:
        BInterface = POP3Backend_IMAPS
    logger.debug(u'using backend %s' % BInterface)
    Backend = BInterface(host=options.backend_address, port=options.backend_port)
    try:
        logger.debug(u'using ThreadedTCPServer(%s:%s)' % (options.listen, options.port))    
        server = ThreadedTCPServer((options.listen, options.port), POP3ServerProtocol)
    except IndexError:
        server = ThreadedTCPServer((options.listen, options.port), POP3ServerProtocol)
    logger.info(u'serving POP3 service at %s:%s' % server.server_address)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    logger.debug(u'serving forever')
    try:    server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.shutdown()
    
if __name__ == '__main__':
    import sys
    import optparse
    import daemon
    import lockfile
    
    Backend, MLock = None, None
    parser  = optparse.OptionParser()
    parser.add_option('-b', '--backend', action='store', default='IMAP')
    parser.add_option('--backend_address', action='store')
    parser.add_option('--backend_port', action='store', type=int, default=143)
    parser.add_option('-l', '--listen', action='store', default='127.0.0.1')
    parser.add_option('-p', '--port', action='store', type=int, default=110)
    parser.add_option('-d', '--debug', action='store_true', default=False)
    parser.add_option('--daemon', action='store_true', default=False)

    options, remainings = parser.parse_args()
    if options.debug:
        logger.setLevel(logging.DEBUG)
    
    if options.daemon:
        loghandlers = []
        for h in logger.handlers:
            loghandlers.append(h.stream)
        with daemon.DaemonContext(working_directory='/tmp/',
                                  pidfile=lockfile.FileLock(path='/tmp/pop3server.lock'),
                                  files_preserve=loghandlers,
                                  uid=99, gid=99,
                                  ):
            main(options)
        logger.info(u'shutting down on request')
    else:
        main(options)
