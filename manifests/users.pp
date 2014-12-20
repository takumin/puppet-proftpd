define proftpd::users (
  $pass,
  $uid,
  $gid,
  $home,
  $shell,
) {
  exec { "ProFTPD User: $name":
    command => "echo -n $pass | ftpasswd --passwd --file=$::proftpd::_AuthUserFile --name=$name --uid=$uid --gid=$gid --home=$home --shell=$shell --stdin 2>/dev/null",
    path    => [
      '/usr/local/bin',
      '/usr/bin',
      '/bin',
    ],
    require => [
      File["$::proftpd::pw_dir"],
    ],
    before => [
      File["$::proftpd::config"],
      Service["$::proftpd::service_name"],
    ],
    unless => "grep $name $::proftpd::_AuthUserFile 2>/dev/null",
  }
}
