FROM mongo

COPY admins.json /admins.json
COPY participants.json /participants.json
COPY speakers.json /speakers.json
CMD ls -1 *.json | sed 's/.json$//' | while read col; do mongoimport --host mongo --username root --password password123 -d vulnerable -c $col --type json --jsonArray < $col.json; done
