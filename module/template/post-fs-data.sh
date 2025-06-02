MODDIR=${0%/*}

if [ ! -f /data/adb/post-fs-data.d/.traceless_cleanup.sh ]; then
  mkdir -p /data/adb/post-fs-data.d
  cat "$MODDIR/cleanup.sh" > /data/adb/post-fs-data.d/.traceless_cleanup.sh
  chmod +x /data/adb/post-fs-data.d/.traceless_cleanup.sh
fi
