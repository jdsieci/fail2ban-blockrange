import sys
import sqlite3
from functools import wraps
from threading import RLock



def commitandrollback(f):
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            with self._db:
                return f(self, self._db.cursor(), *args, **kwargs)
    return wrapper

class RangeBlockDb(object):
    """Cache database for block ip range, keeps track of whois data"""

    __version__ = 1
    _TABLE_rangeblockDb = "CREATE TABLE rangeblockDb (version INTEGER);"
    _TABLE_whois = "CREATE TABLE whois (" \
                   "as INTEGER, " \
                   "cidr TEXT, " \
                   "country TEXT, " \
                   "netname TEXT, " \
                   "cached TEXT" \
                   ");"

    def __init__(self, filename):
        try:
            self._lock = Rlock()
            self._db = sqlite3.connect(
                filename, check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES)
            self._dbFilename = filename
        except sqlite3.OperationalError as e:
            print("Error connecting to persistent database '%s': %s", filename, e.args[0], file=sys.stderr)
            raise

        cur = self._db.cursor()
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("PRAGMA synchronous = OFF")
        cur.execute("PRAGMA journal_mode = MEMORY")
        cur.execute("PRAGMA temp_store = MEMORY")

        try:
            cur.execute("SELECT version from rangeblockDb LIMIT 1")
        except sqlite3.OperationalError:
            self.createDb()


    @commitandrollback
    def createDb(self, cur):
        """Creates new database"""
        cur.executescript(RangeBlockDb._TABLE_rangeblockDb)
        cur.execute("INSERT INTO rangeblockDb(version) VALUES(?)",
                    (RangeBlockDb.__version__, ))
        cur.executescript(RangeBlockDb._TABLE_whois)
        cur.execute("SELECT version from rangeblockDb LIMIT 1")
        return cur.fetchone()[0]

    @commitandrollback
    def updateDb(self, cur):
        pass