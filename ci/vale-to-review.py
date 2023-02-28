#!/usr/bin/env python

import sys
import os
import json

data = json.loads(sys.stdin.read())

comments = []

for file_name, remarks in data.items():
    for remark in remarks:
        comments.append({
            'old_position': 0,
            'new_position': remark['Line'],
            'path': file_name,
            'body': remark['Message']
            })

review = {
    'commit_id': os.environ.get('CI_COMMIT_SHA'),
    'event': len(comments) == 0 and 'APPROVED' or 'REQUEST_CHANGES',
    'comments': comments,
    'body': len(comments) == 0 and 'Vale found no issues :+1:' or 'Please take a look at these...',
    }

print(json.dumps(review))
