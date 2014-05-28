from imaplib import IMAP4, IMAP4_SSL

from .base import EmailTransport, MessageParseError
from django.conf import settings

MAX_MESSAGE_SIZE = getattr(
    settings,
    'DJANGO_MAILBOX_MAX_MESSAGE_SIZE',
    False
)


class GmailTransport(EmailTransport):
    def __init__(self, hostname, port=None, ssl=True):
        self.hostname = hostname
        self.port = port
        self.exclusive = False
        self.MAX_MSG_SIZE = MAX_MESSAGE_SIZE
        if ssl:
            self.transport = IMAP4_SSL
            if not self.port:
                self.port = 993
        else:
            self.transport = IMAP4
            if not self.port:
                self.port = 143

    def connect(self, username, password):
        # Try to use oauth2 first.  It's much safer
        try:
            self._connect_oauth(username)
        except (TypeError, ValueError), e:
            print " Couldn't do oauth2", e
            self.server = self.transport(self.hostname, self.port)
            typ, msg = self.server.login(username, password)
            self.server.select()

    def _connect_oauth(self, username):
        # username should be an email address that has already been authorized
        # for gmail access
        try:
            from django_mailbox.google_utils import (
                get_google_access_token,
                fetch_user_info,
                AccessTokenNotFound,
            )
        except ImportError:
            raise ValueError(
                "Install python-social-auth to use oauth2 auth for gmail"
            )

        access_token = None
        while access_token is None:
            try:
                access_token = get_google_access_token(username)
                google_email_address = fetch_user_info(username)['email']
            except TypeError:
                # This means that the google process took too long
                # Trying again is the right thing to do
                pass
            except AccessTokenNotFound:
                raise ValueError(
                    "No Token available in python-social-auth for %s" % username
                )

        auth_string = 'user=%s\1auth=Bearer %s\1\1' % (
            google_email_address,
            access_token
        )
        self.server = self.transport(self.hostname, self.port)
        self.server.authenticate('XOAUTH2', lambda x: auth_string)
        self.server.select()

    def _get_all_message_ids(self):
        response, message_ids = self.server.search(None, 'ALL', )
        return message_ids[0].split(' ')

    def _get_unread_message_ids(self):
        response, message_ids = self.server.uid('search', None, 'UNSEEN', )
        return message_ids[0].split(' ')

    def _delete_message(self, uid):
        # add Deleted Flag
        self.server.store(uid, "+FLAGS", "\\Deleted")

    def _get_small_message_ids(self, message_ids):
        safe_message_ids = []

        status, data = self.server.uid(
            'fetch',
            ','.join(message_ids),
            '(BODY.PEEK[HEADER] RFC822.SIZE BODYSTRUCTURE)'
        )

        for each_msg in data:
            if isinstance(each_msg, tuple):
                try:
                    metadata, structure = each_msg[0].split(' BODYSTRUCTURE ')
                    uid = metadata.split('(')[1].split(' ')[1]
                    size = metadata.split('(')[1].split(' ')[3]
                    if int(size) <= int(self.MAX_MSG_SIZE):
                        safe_message_ids.append(uid)
                except ValueError, e:
                    print "ValueError: %s working on %s" % (e, each_msg[0])
                    print each_msg
                    pass
        return safe_message_ids

    def get_message(self):
        # Fetch a list of message uids to process
        # If we're the exclusive handlers of the mailbox,
        # we can assume that all messages are ours.
        # If not, we should only pull the unread ones
        if self.exclusive:
            message_ids = self._get_all_message_ids()
        else:
            message_ids = self._get_unread_message_ids()

        if self.MAX_MSG_SIZE:
            message_ids = self._get_small_message_ids(message_ids)

        #print "There are %s messages: %s" % (len(message_ids), message_ids)

        if not message_ids:
            return

        for uid in message_ids:
            try:
                typ, msg_contents = self.server.uid('fetch', uid, '(RFC822)')
                message = self.get_email_from_bytes(msg_contents[0][1])
                yield message
            except MessageParseError:
                continue
            # Only delete them if we're the only ones who care
            if self.exclusive:
                self.server.store(uid, "+FLAGS", "\\Deleted")
        self.server.expunge()
        return
