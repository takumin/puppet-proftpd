define proftpd::groups (
  $gid,
) {
  exec { "ProFTPD Group: $name":
    command => "ftpasswd --group --file=$::proftpd::_AuthGroupFile --name=$name --gid=$gid 2>/dev/null",
    path    => [
      '/usr/local/bin',
      '/usr/bin',
    ],
    require => [
      File["$::proftpd::pw_dir"],
    ],
    before => [
      File["$::proftpd::config"],
      Service["$::proftpd::service_name"],
    ],
    unless => "grep $name $::proftpd::_AuthGroupFile 2>/dev/null",
  }
}
