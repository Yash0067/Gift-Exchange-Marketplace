#!/usr/bin/env python3
"""Local operator-only report review. Access to the database is administrative access."""
import argparse
from datetime import datetime, timezone
from server import connect

parser=argparse.ArgumentParser(description='Review marketplace reports on the server itself')
sub=parser.add_subparsers(dest='command',required=True)
sub.add_parser('list',help='List open reports')
s=sub.add_parser('show',help='Show a report and related content');s.add_argument('id',type=int)
s=sub.add_parser('resolve',help='Mark a report resolved');s.add_argument('id',type=int)
a=parser.parse_args()
with connect() as c:
    if a.command=='list':
        rows=c.execute("SELECT id,reporter_id,listing_id,conversation_id,created,reason FROM reports WHERE status='open' ORDER BY id DESC").fetchall()
        if not rows: print('No open reports.')
        for r in rows:
            target=f"listing #{r['listing_id']}" if r['listing_id'] else f"conversation #{r['conversation_id']}"
            print(f"#{r['id']} | {target} | reporter user #{r['reporter_id']} | {datetime.fromtimestamp(r['created'],timezone.utc).isoformat()}\n  {r['reason']}")
    elif a.command=='show':
        r=c.execute('SELECT * FROM reports WHERE id=?',(a.id,)).fetchone()
        if not r: raise SystemExit('Report not found')
        print(f"Report #{r['id']} ({r['status']}) by user #{r['reporter_id']}\nReason: {r['reason']}")
        if r['listing_id']:
            obj=c.execute('SELECT name,category,note,status FROM listings WHERE id=?',(r['listing_id'],)).fetchone()
            if obj: print(f"Listing: {obj['name']} | {obj['category']} | {obj['status']}\nDetails: {obj['note']}")
        if r['conversation_id']:
            print('Recent conversation messages (sensitive; protect this output):')
            rows=c.execute('SELECT sender_id,created,body FROM (SELECT sender_id,created,body,id FROM messages WHERE conversation_id=? ORDER BY id DESC LIMIT 100) ORDER BY id',(r['conversation_id'],)).fetchall()
            for m in rows: print(f"[{datetime.fromtimestamp(m['created'],timezone.utc).isoformat()}] user #{m['sender_id']}: {m['body']}")
    else:
        cur=c.execute("UPDATE reports SET status='resolved' WHERE id=? AND status='open'",(a.id,))
        if not cur.rowcount: raise SystemExit('No open report with that ID')
        c.commit();print('Report marked resolved. This does not automatically remove content or sanction users.')
