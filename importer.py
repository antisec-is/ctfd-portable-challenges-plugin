#!/usr/bin/env python

from flask import Flask
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy.engine.url import make_url
from sqlalchemy.exc import OperationalError
from werkzeug.utils import secure_filename

import yaml
import shutil
import os
import secrets
import sys
import hashlib
import argparse
from pathlib import Path

REQ_FIELDS = {'name', 'description', 'value', 'category', 'flags'}


def parse_args():
    parser = argparse.ArgumentParser(
        description='Import CTFd challenges and their attachments to a DB from a YAML formated specification file and an associated attachment directory')
    parser.add_argument('--app-root', dest='app_root', type=str,
                        help="app_root directory for the CTFd Flask app (default: 2 directories up from this script)",
                        default=None)
    parser.add_argument('-d', dest='db_uri', type=str, help="URI of the database where the challenges should be stored")
    parser.add_argument('-F', dest='dst_attachments', type=str,
                        help="directory where challenge attachment files should be stored")
    parser.add_argument('-i', dest='in_file', type=str, help="name of the input YAML file (default: export.yaml)",
                        default="export.yaml")
    parser.add_argument('--skip-on-error', dest="exit_on_error", action='store_false',
                        help="If set, the importer will skip the importing challenges which have errors rather than halt.",
                        default=True)
    parser.add_argument('--move', dest="move", action='store_true',
                        help="if set the import proccess will move files rather than copy them", default=False)
    return parser.parse_args()


def process_args(args):
    if not (args.db_uri and args.dst_attachments):
        if args.app_root:
            app.root_path = os.path.abspath(args.app_root)
        else:
            abs_filepath = os.path.abspath(__file__)
            grandparent_dir = os.path.dirname(os.path.dirname(os.path.dirname(abs_filepath)))
            app.root_path = grandparent_dir
        sys.path.append(os.path.dirname(app.root_path))
        app.config.from_object("CTFd.config.Config")

    if args.db_uri:
        app.config['SQLALCHEMY_DATABASE_URI'] = args.db_uri
    if not args.dst_attachments:
        args.dst_attachments = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])

    return args


class MissingFieldError(Exception):
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "Error: Missing field '{}'".format(self.name)

class Event:
    class Type:
        info = 'info'
        warn = 'warn'
        error = 'error'

    def __init__(self, etype, msg):
        print(f'[{etype}] {msg}')
        self.type = etype
        self.msg = msg

def find_all_challenges(in_dir):
    yaml_files = in_dir.rglob('meta.y*ml')
    for y in yaml_files:
        chals = yaml.safe_load_all(y.read_text())
        for c in chals:
            yield y, c

def missing_fileds(chal):
    return REQ_FIELDS - set(chal.keys())


def get_flags(chal):
    flags = chal.get('flags')
    if not flags:
        return []

    if isinstance(flags, str):
        return [{'flag': flags, 'type': 'static', 'case_insensitive': False}]

    res = []
    for f in flags:
        if flag := f.get('flag'):
            res.append({
                'flag': flag,
                'type': f.get('type', 'static'),
                'case_insensitive': f.get('case_insensitive', False)
            })

    return res

def get_files(root_dir, yaml_file, chal):
    res = []

    directory = yaml_file.parent
    for f in chal.get('files', []):
        file = (directory / f).resolve()
        try:
            file.relative_to(root_dir)
        except ValueError:
            # File is outside of root directory, ignore
            continue
        res.append(file)

    return res

def update_hints(chal, chal_dbobj):
    from CTFd.models import db, Hints
    old_hints = Hints.query.filter_by(challenge_id=chal_dbobj.id).all()
    for hint in old_hints:
        db.session.delete(hint)

    for hint in chal.get('hints', []):
        hint_db = Hints(challenge_id=chal_dbobj.id, content=hint['hint'], type=hint['type'],
                        cost=int(hint['cost']))
        db.session.add(hint_db)

    return []

def update_tags(chal, chal_dbobj):
    from CTFd.models import db, Tags
    events = []

    db_tag_objects = {tag.value: tag for tag in Tags.query.filter_by(challenge_id=chal_dbobj.id).all()}
    chal_tags = set(chal.get('tags', []))

    tags_db = set(db_tag_objects.keys())
    new_tags = chal_tags - tags_db
    del_tags = tags_db - chal_tags

    for tag in new_tags:
        tag_dbobj = Tags(challenge_id=chal_dbobj.id, value=tag)
        db.session.add(tag_dbobj)

        events.append(Event(Event.Type.info,
            f"Challenge {chal_dbobj.name}: Adding new tag {tag}"))

    for tag in del_tags:
        db.session.delete(db_tag_objects[tag])

        events.append(Event(Event.Type.warn,
            f"Challenge {chal_dbobj.name}: Deleting tag {tag}"))

    return events

def update_flags(flags, chal_dbobj):
    from CTFd.models import db, Flags

    events = []

    db_flag_objects = {flag.content:flag for flag in Flags.query.filter_by(challenge_id=chal_dbobj.id).all()}
    chal_flags = {flag['flag']:flag for flag in flags}

    tags_db = set(db_flag_objects.keys())
    tags_in = set(chal_flags.keys())

    new_flags = tags_in - tags_db
    del_flags = tags_db - tags_in
    upd_flags = tags_in & tags_db

    for flag in new_flags:
        fl_obj = chal_flags[flag]
        fl_type = fl_obj['type']
        fl_data = 'case_insensitive' if fl_obj.get('case_insensitive') else None
        flag_db = Flags(challenge_id=chal_dbobj.id, content=flag, type=fl_type, data=fl_data)
        db.session.add(flag_db)

        events.append(Event(Event.Type.info,
            f"Challenge {chal_dbobj.name}: Adding new flag {flag}"))

    for flag in del_flags:
        db.session.delete(db_flag_objects[flag])

        events.append(Event(Event.Type.warn,
            f"Challenge {chal_dbobj.name}: Deleting flag {flag}"))

    for flag in upd_flags:
        fl_obj = chal_flags[flag]

        flag_db = db_flag_objects[flag]
        flag_db.type = fl_obj['type']
        flag_db.data = 'case_insensitive' if fl_obj.get('case_insensitive') else None

    return events

def get_random_dir(dst_attachments):
    while True:
        md5hash = hashlib.md5(secrets.token_bytes(64)).hexdigest()
        dst_dir = Path(dst_attachments) / md5hash
        if not dst_dir.exists():
            return dst_dir

def file_md5(path):
    sig = hashlib.md5()
    with path.open('rb') as f:
        while data := f.read(1024):
            sig.update(data)

    return sig.hexdigest()

def update_files(files, chal_dbobj, dst_attachments):
    events = []
    from CTFd.models import db, ChallengeFiles

    db_file_objects = {Path(file.location).name:file for file in ChallengeFiles.query.filter_by(challenge_id=chal_dbobj.id).all()}
    chal_files = {secure_filename(Path(file).name):file for file in files}

    files_db = set(db_file_objects.keys())
    files_in = set(chal_files.keys())

    new_files = files_in - files_db
    del_files = files_db - files_in
    upd_files = files_in & files_db

    for file in upd_files:
        file_db = db_file_objects[file]
        old = Path(dst_attachments) / file_db.location
        new = chal_files[file]

        if file_md5(old) != file_md5(new):
            events.append(Event(Event.Type.info,
                f"Challenge {chal_dbobj.name}: Updating existing file {new.name}"))
            shutil.copy(new, old)


    for file in del_files:
        file_db = db_file_objects[file]
        path = Path(dst_attachments) / file_db.location
        path.unlink(missing_ok=True)
        # Delete containing directory if it is not emtpy
        try:
            path.parent.rmdir()
        except OSError:
            # Directory was not empty, ignore
            pass
        db.session.delete(file_db)

        events.append(Event(Event.Type.warn,
            f"Challenge {chal_dbobj.name}: Deleting file {path.name}"))

    for file in new_files:
        path = chal_files[file]
        safe_name = secure_filename(path.name)
        out = get_random_dir(dst_attachments) / safe_name

        out.parent.mkdir(exist_ok=True)
        shutil.copy(path, out)

        file_db = ChallengeFiles(challenge_id=chal_dbobj.id, location=str(out.relative_to(dst_attachments)))
        db.session.add(file_db)

        events.append(Event(Event.Type.info,
            f"Challenge {chal_dbobj.name}: Adding new file {safe_name}"))

    return events

def import_challenges(in_dir, dst_attachments, exit_on_error=True, move=False):
    from CTFd.models import db, Challenges
    from CTFd.plugins.dynamic_challenges import DynamicChallenge

    in_dir = Path(in_dir).resolve()

    events = []

    challenges_by_name = {}
    requirements = []
    for file, chal in find_all_challenges(in_dir):
        if missing := missing_fileds(chal):
            events.append(Event(Event.Type.warn,
                f"Skipping challenge in {file}: Missing fields {missing}"))
            continue

        name = chal['name'].strip()
        description = chal['description'].strip()
        category = chal['category'].strip()
        try:
            value = int(chal['value'])
        except ValueError:
            events.append(Event(Event.Type.error,
                f"Skipping challenge {name}: Challenge value is not integer"))
            continue

        flags = get_flags(chal)
        if not flags:
            events.append(Event(Event.Type.error,
                f"Skipping challenge {name}: No valid flags specified"))
            continue

        files = get_files(in_dir, file, chal)

        for hint in chal.get('hints', []):
            if 'type' not in hint:
                hint['type'] = "standard"

        to_update = []
        if old_name := chal.get('old_name'):
            to_update = Challenges.query.filter_by(name=old_name).all()

        if not to_update:
            to_update = Challenges.query.filter_by(name=name).all()

        if not to_update:
            events.append(Event(Event.Type.info,
                f"Creating new challenge {name}"))
            if chal.get('type') == 'dynamic':
                chal_dbobj = DynamicChallenge(value=value)
            else:
                chal_dbobj = Challenges()
        # No challenge found with specified name, this is a new challenge
        else:
            if len(to_update) > 1:
                events.append(Event(Event.Type.warn,
                    f"Challenge {name}: Found more than one challenge with the same name. Only the first one will be updated."))
            events.append(Event(Event.Type.info,
                f"Updating challenge {name}"))
            chal_dbobj = to_update[0]

        chal_dbobj.name=name
        chal_dbobj.description=description
        chal_dbobj.value=value
        chal_dbobj.category=category
        chal_dbobj.connection_info = chal.get('connection_info')
        chal_dbobj.state = 'hidden' if chal.get('hidden') else 'visible'
        chal_dbobj.type = chal.get('type', 'standard')

        requirements.append( (chal_dbobj,  chal.get('requires', [])) )

        if chal_dbobj.type == 'dynamic':
            chal_dbobj.initial=int(chal.get('initial', value))
            chal_dbobj.decay=int(chal.get('decay', 0))
            chal_dbobj.minimum=int(chal.get('minimum', 0))


        db.session.add(chal_dbobj)
        db.session.commit()

        challenges_by_name[name] = chal_dbobj

        # Update complex attributes

        events.extend(update_tags(chal, chal_dbobj))
        events.extend(update_hints(chal, chal_dbobj))
        events.extend(update_flags(flags, chal_dbobj))
        events.extend(update_files(files, chal_dbobj, dst_attachments))


        db.session.commit()


    for chal_db, req in requirements:
        req_id = []
        for r in req:
            if c := challenges_by_name.get(r):
                if c is None:
                    events.append(Event(Event.Type.error,
                        f"Challenge {chal_db.name}: Required challenge with name '{r}' has ID None."))
                    continue
                req_id.append(c.id)
            else:
                events.append(Event(Event.Type.error,
                    f"Challenge {chal_db.name}: Required challenge with name '{r}' does not exist."))
        chal_db.requirements = {'prerequisites': req_id}
        db.session.commit()

    db.session.close()

    return events


if __name__ == "__main__":
    args = parse_args()

    app = Flask(__name__)

    with app.app_context():
        args = process_args(args)
        from CTFd.models import db

        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        url = make_url(app.config['SQLALCHEMY_DATABASE_URI'])
        if url.drivername == 'postgres':
            url.drivername = 'postgresql'

        db.init_app(app)

        try:
            if not (url.drivername.startswith('sqlite') or database_exists(url)):
                create_database(url)
            db.create_all()
        except OperationalError:
            db.create_all()
        else:
            db.create_all()

        app.db = db
        import_challenges(args.in_file, args.dst_attachments, args.exit_on_error, move=args.move)
