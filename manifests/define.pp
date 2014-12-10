define proftpd_users (
  $uid,
  $gid,
  $home,
  $shell,
) {
  exec { "ProFTPD Group: $name":
    command => [
      'ftpasswd',
      '--group',
      "--file=$::proftpd::AuthGroupFile",
      "--name=$name",
      "--gid=$gid",
    ],
    path    => [
      '/usr/local/bin',
      '/usr/bin',
    ],
  }

  exec { "ProFTPD User: $name":
    command => [
      'ftpasswd',
      '--passwd',
      "--file=$::proftpd::AuthUserFile",
      "--name=$name",
      "--uid=$uid",
      "--gid=$gid",
      "--home=$home",
      "--shell=$shell",
    ],
    path    => [
      '/usr/local/bin',
      '/usr/bin',
    ],
  }
}
