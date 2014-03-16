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
logger.handlers[0].setFormatter(logging.Formatter(fmt='%(asctime)s [%(name)s.%(levelname)s %(lineno)d]: %(message)s'))
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
            if n > 10:  n = 10
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
    def __init__(self):
        self.mailboxes  = {}
        self._lock      = threading.Lock()
    def is_locked(self, name=None):
        return self.mailboxes.get(name, False)
    def acquire(self):
        return self._lock.acquire()
    def release(self):
        try:    self._lock.release()
        except ThreadError: return False
        return True
    def acquire_mailbox(self, name=None):
        self.acquire()
        m   = self.mailboxes.get(name, False)
        if m != False:  
            self.release()
            return False
        self.mailboxes[name] = True
        self.release()
        return True
    def release_mailbox(self, name=None):
        self.acquire()
        m   = self.mailboxes.get(name, False)
        if m == False:  
            self.release()
            return False
        self.mailboxes[name] = False
        self.release()
        return True

class POP3Message(object):
    def __init__(self, content=None):
        if content != None:
            self.content = email.message_from_string(content)
        else:
            self.content    = None
    def get_headers(self):
        return '\n'.join(self.content.values())
    def get_body(self):
        content = ''
        for payload in self.content.get_payload():
            content += str(payload)
        return content
    def as_string(self):
        return self.content.as_string()
    def unique_id(self):
        return md5(str(self.content)).hexdigest()
    def __len__(self):
        return len(self.content.as_string())

class POP3ServerProtocol(SocketServer.BaseRequestHandler):
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
        return u'%s POP3 server ready' % OK
    def QUIT(self):
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
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'STAT')
        if not self.__backend_fetch__():
            return u'%s %s' % (ERR, self.backend.state)
        return u'%s %d %d' % (OK, len(self.messages), self.__get_messagesize__())
    def LIST(self, msg=None):
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
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'RETR')
        if self.messages == []:
            if not self.__backend_fetch__():
                return u'%s %s' % (ERR, self.backend.state)
        try:    content = self.__get_msg__(msg)
        except IndexError:
            return u'%s no such message, only %s messages in maildrop' % (ERR, len(self.messages))
        return u'%s %s octets\r\n%s\r\n.' % (OK, len(content), unicode(content.as_string(), 'utf8').encode('ascii', 'ignore'))
    def DELE(self, msg=None):
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
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'NOOP')
        return u'%s' % OK
    def RSET(self):
        if self.state not in (u'transaction', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'RSET')
        if not self.__backend_revert__():
            return u'%s %s' % (ERR, self.backend.state)
        self.messages = []
        if not self.__backend_fetch__():
            return u'%s %s' % (ERR, self.backend.state)
        return u'%s maildrop has %s messages (%s octets)' % (OK, len(self.messages), self.__get_messagesize__())
    def TOP(self, msg=None, lines=None):
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
        if self.state not in (u'authorization', ):  return u'%s POP3 invalid state for command %s' % (ERR, u'USER')
        self._pop3user = name
        return u'%s' % OK
    def PASS(self, credentials=None):
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
                    logger.debug(u'S: %s' % str(rsp))
                    self.request.sendall(u'%s\r\n' % str(rsp))
                if cmd == 'QUIT':   break
            else:
                try:    logger.debug(u'%s POP3 doesn\'t support command %s\r\n' % (ERR, unicode(cmd, 'utf8').encode('ascii', 'ignore')))
                except: logger.error(u'%s POP3 doesn\'t support command output cannot be decoded' % ERR)
                self.request.sendall(u'%s POP3 doesn\'t support command\r\n' % (ERR))

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

if __name__ == '__main__':
    import sys
    import optparse
    parser  = optparse.OptionParser()
    parser.add_option('-b', '--backend', action='store', default='IMAP')
    parser.add_option('--backend_address', action='store')
    parser.add_option('--backend_port', action='store', type=int, default=143)
    parser.add_option('-l', '--listen', action='store', default='127.0.0.1')
    parser.add_option('-p', '--port', action='store', type=int, default=110)
    parser.add_option('-d', '--debug', action='store_true', default=False)

    options, remainings = parser.parse_args()
    if options.debug:
        logger.setLevel(logging.DEBUG)
    
    MLock   = MailboxLocker()
    if not options.backend.upper() in ('IMAP', 'IMAPS'):
        print u'supported Backends IMAP, IMAPS'
        sys.exit(1)
    if options.backend.upper() == 'IMAP':
        BInterface = POP3Backend_IMAP
    else:
        BInterface = POP3Backend_IMAPS
    Backend = BInterface(host=options.backend_address, port=options.backend_port)
    try:    server = ThreadedTCPServer((options.listen, options.port), POP3ServerProtocol)
    except IndexError:
        server = ThreadedTCPServer((options.listen, options.port), POP3ServerProtocol)
    print u'serving POP3 service at %s:%s' % server.server_address
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    try:    server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.shutdown()
