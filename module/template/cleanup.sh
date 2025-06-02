# shellcheck disable=SC2016
sed -i "s/^description=.*/description=$(cat /data/adb/modules/zygisk_traceless/description)/" /data/adb/modules/zygisk_traceless/module.prop
