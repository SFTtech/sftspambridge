sftspambridge
=============

Transfers E-Mails from **Dovecot** to **rspamd** for spamlearning.

This is useful if Dovecot is running on a *different machine* than rspamd.


Idea
----
* Main goal: let `rspamd` learn if a mail is spam/ham when a user moves it to a folder

* Dovecot user moves spam mail to a folder
  * e.g. from INBOX to Junk means "new spam mail"
  * from Junk to somewhere else except the Trash means "new ham mail"
* The mail is stored in the psql database
* The rspamd host gets notified that there's a new mail to learn
* The mail is fed into rspamd as spam or ham


HowTo
-----

Components:
* Dovecot sieve configuration
* Dovecot sieve scripts
* PostgreSQL database for mail transfer
* Python script executed by sieve to grab mail
* Python daemon that receives the mail and feeds it into rspamd


### Database config

* Create psql database (I used `spamlearn`) on whatever host (either the rspamdhost, dovecothost, a third one, doesn't matter..)
* Create two users, e.g. `spamlearn` and `spamlearn_vmail` (you can change the names of course).
  * `spamlearn` is the 'trusted' user, `spamlearn_vmail` is the untrusted one
  * Dovecot will feed mails to the database with `spamlearn_vmail` (shared among all Dovecot users),
    and rspamd will use `spamlearn` to get the mails for learning.
* Initialize the database as user `spamlearn`:
  * `./sftspambridge.py dbsetup | sudo -u postgresql psql spamlearn spamlearn`
  * allow user `spamlearn_vmail` to add new mail:
    * `grant execute on function add_mail to spamlearn_vmail;`

* allow connections to the database from other hosts
  * grant access in `pg_hba.conf` (ideally use a VPN network or something, then you don't need psql's ssl anyway)
  * to secure the connection to the database with ssl, set in `postgresql.conf`:
```
ssl = on
ssl_cert_file = '/etc/letsencrypt/live/yourhost.lol/current.pem'
ssl_key_file = '/etc/letsencrypt/live/yourhost.lol/current.key'
ssl_ciphers = '!aNULL:!eNULL:!CAMELLIA:HIGH:@STRENGTH'
```


### Dovecot config

* Install and activate sieve

* Among many other things in `conf.d/90-sieve.conf`, ensure there is something like:
```
sieve_global_extensions = +vnd.dovecot.pipe +vnd.dovecot.environment
sieve_plugins = sieve_imapsieve sieve_extprograms

# sft spam filtering (tm)
# if a message was moved to Spam folder
# (or a flag changed in the Spam dir, e.g. by forwarding/replying)
imapsieve_mailbox1_name = Junk
imapsieve_mailbox1_causes = COPY FLAG
imapsieve_mailbox1_before = file:/etc/dovecot/sieve/report-spam.sieve

# From Spam folder to elsewhere
imapsieve_mailbox2_name = *
imapsieve_mailbox2_from = Junk
imapsieve_mailbox2_causes = COPY
imapsieve_mailbox2_before = file:/etc/dovecot/sieve/report-ham.sieve

# pipe executables are in here
sieve_pipe_bin_dir = /etc/dovecot/pipe
```

* `mkdir /etc/dovecot/pipe/` and place `sftspambridge.py` in there. It will be executed by sieve under user `vmail`
* `mkdir /etc/dovecot/sieve/` and the `report-spam` and `ham` scripts there (and compile them with the `Makefile`)


### Spambridge config

Configure `sftspambridge` in `/etc/sftspambridge.cfg`.

Store the passwords for the right user accounts:

* On the Dovecot host:
  * Store the `spamlearn_vmail`-database-user and password under `[database]`
  * Store your host identifier under `[dovecot]`: If the database is filled by multiple dovecots, we then know which one it was
  * `chown vmail:vmail /etc/sftspambridge.cfg`
  * `chmod 600 /etc/sftspambridge.cfg`
* On the rspamd-host:
  * Store the `spamlearn`-database-user and password under `[database]`
  * Store the rspamd controller password under `[rspamd]`
  * Create user `sftspambridge`
  * `chown sftspambridge:sftspambridge /etc/sftspambridge.cfg`
  * `chmod 600 /etc/sftspambridge.cfg`

### systemd service

Needed on the rspamd-host:

* Add the Linux-user `sftspambridge`
* Place `sftspambridgereceiver.service` in `/etc/systemd/system`
* Enable and start the service: `systemctl enable --now sftspambridgereceiver.service`


Future Ideas
------------

* Delayed learning: Currently the mail is fed into rspamd quite instantly (it's a feature).
  But if a mail was moved to Junk by mistake, it will be learned as Junk so quickly you can't undo the move.
  Thus, there could be a configurable delay timer after which the message will be fed to rspamd.
* There could be a WebUI listing "proposed" spam messages from untrusted
  mail users (that have consented to participate in spam learning). In the UI,
  messages are 'activated' for actual learning (i.e. a confirmation that it's really spam/ham).


License
-------

**GNU GPLv3** or later; see [copying.md](copying.md) and [legal/GPLv3](/legal/GPLv3).
