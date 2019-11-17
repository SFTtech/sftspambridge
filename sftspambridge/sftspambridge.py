#!/usr/bin/env python3

"""
rspamd spam/ham relay

(c) 2019 Jonas Jelten <jj@sft.mx>
GPLv3 or any later version

gets a mail from stdin
either as spam or ham
which is then recorded in a postgresql database where it can then be further processed

this is usually executed from a sieve script by dovecot.

"important" permission stuff:

/etc/sftspambridge.cfg:
    on the rspamd-host, needs the `[database]` and `[rspamd]` password
    on the dovecot-host, only needs the `[database]` password:
        should be a less-privileged db account just for vmail (see below)!

as dovecot runs the sievescript (and hence this script) as user `vmail`,
you should have **two** database users:
    * user 1 that actually has permissions on the `mails` table etc.
    * user 2 that can just call the `add_mail` function
        * `grant execute on function add_mail to user_2_for_vmail;`
        * the user should do nothing else!

the `learnmsg` mode should use the user **2** so if `vmail` is hacked,
the mail table remains secured:
    * `/etc/sftspambridge.cfg` on that host should store the user **2** password
      and be readable by `vmail`
    * if you need user 1 and 2 on the same host, you can use 2 config files:
        * run `$0 --cfg /etc/sftspambridge_vmail.cfg learnmsg ...` in sieve

the `dbsetup` script should be fed into postgresql under user **1**
so the tables and functions belong to it.
"""

import argparse
import asyncio
import configparser
import datetime
import getpass
import json
import os
import sys
import subprocess
import tempfile

import asyncpg



# database setup script
DB_SETUP = """

do $$ begin
    create type mail_kind as enum ('spam', 'ham');
exception
    when duplicate_object then null;
end $$;

create table if not exists mails (
    id bigserial primary key not null,
    username text not null,
    kind mail_kind not null,
    hash bytea not null,
    data bytea not null,
    added timestamp with time zone not null,
    learned timestamp with time zone
);
create index if not exists hash_idx on mails (hash);

-- this function run with 'setuid' privileges ('security definer')!
create or replace function add_mail(mkind mail_kind, username text, message bytea)
returns void as $$
declare now_time timestamp with time zone;
declare msghash bytea;
declare prevmsg mails%ROWTYPE;
declare new_mail_id bigint;
begin
    select now() into now_time;
    select sha256(message) into msghash;

    select * into prevmsg from mails where hash = msghash and learned is null;

    if prevmsg is null then
        -- new entry that needs to be fed into the spam tool
        insert into mails (kind, username, data, hash, added)
            values (mkind, username, message, msghash, now_time)
        returning id into new_mail_id;

    else
        -- the message is known and not yet learned, so we update the unlearned one.
        update mails set
            kind = mkind,
            added = now_time
        where mails.id = prevmsg.id;

        select prevmsg.id into new_mail_id;
    end if;

    perform pg_notify('learn_new_mail', json_build_object('mail_id', new_mail_id)::text);
end;
$$ language plpgsql
security definer;
"""


def main():
    """
    parse args and launch the tool
    """

    cli = argparse.ArgumentParser()
    cli.add_argument("--cfg", default="/etc/sftspambridge.cfg")
    sp = cli.add_subparsers(dest="mode", required=True)

    learnmsgcli = sp.add_parser("learnmsg")
    learnmsgcli.add_argument("kind", choices=["spam", "ham"])
    learnmsgcli.add_argument("username")

    sp.add_parser("receive")

    sp.add_parser("dbsetup")

    cleanupcli = sp.add_parser("cleanup")
    cleanupcli.add_argument("--keep", type=int, default=(60 * 60 * 24 * 31),
                            help=("keep messages that are younger"
                                  " than this time, in seconds (default: 31 days)"))

    args = cli.parse_args()

    if args.mode in ("learnmsg", "receive"):
        cfg = configparser.ConfigParser()
        with open(args.cfg) as cfgfd:
            cfg.read_file(cfgfd)

    loop = asyncio.get_event_loop()

    if args.mode == "learnmsg":
        loop.run_until_complete(record_message(cfg, args.username, args.kind))

    elif args.mode == "receive":
        loop.run_until_complete(receive_messages(cfg))

    elif args.mode == "dbsetup":
        print("-- please pipe this into psql:")
        print()

        print(DB_SETUP)

    elif args.mode == "cleanup":
        raise NotImplementedError("TODO")


async def db_connect(cfg):
    """
    get a connection to the database
    """
    if not (cfg.has_section('database') and
            cfg['database'].get('user') and
            cfg['database'].get('password') and
            cfg['database'].get('name')):
        raise Exception("config file needs [database] section with user, password and name")

    use_ssl = None
    ssl_cfg = cfg['database'].get('ssl')
    if ssl_cfg and ssl_cfg.lower() == "true":
        use_ssl = True

    return await asyncpg.connect(user=cfg['database']['user'],
                                 password=cfg['database']['password'],
                                 database=cfg['database']['name'],
                                 host=cfg['database'].get('host'),
                                 ssl=use_ssl)


async def record_message(cfg, user, kind):
    """
    record a new mail in the database
    """
    conn = await db_connect(cfg)
    if not (cfg.has_section('dovecot') and
            cfg['dovecot'].get('hostname')):
        raise Exception("config file needs [dovecot] section with hostname")

    # append the server name
    user = "%s@%s" % (user, cfg['dovecot']['hostname'])

    # read the message from stdin until eof
    message = sys.stdin.buffer.read()

    await conn.execute('select add_mail($1, $2, $3);',
                       kind, user, message)
    await conn.close()


async def receive_messages(cfg):
    """
    process all mails in the database
    """
    conn = await db_connect(cfg)

    if not (cfg.has_section('rspamd') and
            cfg['rspamd'].get('controllerpassword')):
        raise Exception("config file needs [rspamd] section with controllerpassword")

    to_learn = asyncio.Queue()

    # this will add new to-learn entries in "real time"
    def handle_notification(connection, pid, channel, payload_raw):
        if channel == "learn_new_mail":
            payload = json.loads(payload_raw)
            new_msgid = payload.get('mail_id')

            if not new_msgid:
                raise Exception("got unknown notification payload")

            to_learn.put_nowait(int(new_msgid))

    await conn.add_listener("learn_new_mail", handle_notification)

    # add all to-learn messages into the todo list
    rows = await conn.fetch('select id from mails where learned is null;')
    for msg in rows:
        await to_learn.put(int(msg['id']))

    default_rspamc = '/usr/bin/rspamc'
    rspamc = cfg['rspamd'].get('rspamc', default_rspamc)

    if not os.path.isfile(rspamc):
        raise Exception(
            "rspamc executable could not be found (%s). "
            "are you executing this script on the host where rspamd is running?"
            % rspamc
        )

    while True:
        learn_id = await to_learn.get()
        msg = await conn.fetchrow('select * from mails where id = $1', learn_id)

        op_mode = "learn_ham" if msg['kind'] == 'ham' else "learn_spam"

        rspamdpasswd = cfg['rspamd']['controllerpassword']
        ctrlsocket = cfg['rspamd'].get('controllersocket')

        with tempfile.NamedTemporaryFile() as passwdfile:
            passwdfile.write(rspamdpasswd.encode())
            passwdfile.flush()

            cmd = [
                rspamc,
            ]

            if ctrlsocket:
                cmd.extend(['-h', cfg['rspamd']['controllersocket']])

            cmd.extend(['-P', passwdfile.name])
            cmd.append(op_mode)

            print("$", " ".join(cmd))
            proc = await asyncio.create_subprocess_exec(*cmd, stdin=subprocess.PIPE)

            # transfer the mail
            proc.stdin.write(msg['data'])
            proc.stdin.close()

            ret = await proc.wait()

            if ret == 0:
                await conn.execute('update mails set learned = now() where id = $1', learn_id)
            else:
                print("rspamc returned %d, message probably not learned" % ret)

    await conn.close()


if __name__ == "__main__":
    try:
        main()
    except PermissionError as exc:
        raise Exception("my permissions (uid=%s, name=%s) couldn't do it :(" % (os.geteuid(), getpass.getuser())) from exc
