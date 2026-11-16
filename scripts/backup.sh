#!/bin/bash
set -euo pipefail
BASE=/home/kamesh62/nhost
cd $BASE
TS=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BASE/backups/appdb-$TS.dump"
# Run as the postgres container user so dumps are owned 70:70 (not root).
# kamesh62 cannot chown/chmod these (dir is 70:70); rotation uses:
#   docker compose exec -T postgres rm /backups/<file>
if ! docker compose -f $BASE/compose.yml exec -u postgres -T postgres pg_dump -U backup_worker -d appdb -Fc -f /backups/$(basename $BACKUP_FILE); then
  docker compose -f $BASE/compose.yml exec -T postgres rm -f /backups/$(basename $BACKUP_FILE)
  echo "BACKUP_FAIL stale file removed" >&2
  exit 1
fi
ls -lh $BACKUP_FILE
echo "BACKUP_OK $BACKUP_FILE"
