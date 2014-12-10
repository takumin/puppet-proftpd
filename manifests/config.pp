# == Class proftpd::config
#
# This class is called from proftpd for service config.
#
class proftpd::config {

  file { "$::proftpd::config":
    ensure       => file,
    owner        => 0,
    group        => 0,
    mode         => '0644',
    content      => template($::proftpd::config_template),
    validate_cmd => "$::proftpd::prefix/sbin/proftpd -t -c %",
  }

  if $::proftpd::managed_users != undef {
    file { "$::proftpd::pw_dir":
      ensure => directory,
      owner => 0,
      group => 0,
      mode => '0700',
    }

    create_resources(proftpd_users, $::proftpd::managed_users)

    file {[
      "$::proftpd::AuthGroupFile",
      "$::proftpd::AuthUserFile",
    ]:
      ensure       => file,
      owner        => 0,
      group        => 0,
      mode         => '0600',
    }
  }

  if $::proftpd::self_signed == true {
    file { "$::proftpd::ca_dir":
      ensure  => directory,
      owner   => 0,
      group   => 0,
      mode    => '0700',
    }

    exec { 'OpenSslGenrsa: proftpd':
      command => 'openssl genrsa -out server.key 2048',
      path    => [
        '/usr/local/bin',
        '/usr/bin',
      ],
      cwd     => [
        "$::proftpd::ca_dir",
      ],
      creates => [
        "$::proftpd::ca_dir/server.key",
      ],
      require => [
        File["$::proftpd::ca_dir"],
      ],
    }

    $subj_args = "/C=$::proftpd::ca_C/ST=$::proftpd::ca_ST/L=$::proftpd::ca_L/O=$::proftpd::ca_O/OU=$::proftpd::ca_OU/CN=$::proftpd::ca_CN/E=$::proftpd::ca_E/"

    exec { 'OpenSslReq: proftpd':
      command => "openssl req -out server.csr -new -key server.key -subj $subj_args -batch",
      path    => [
        '/usr/local/bin',
        '/usr/bin',
      ],
      cwd     => [
        "$::proftpd::ca_dir",
      ],
      creates => [
        "$::proftpd::ca_dir/server.csr",
      ],
      require => [
        File["$::proftpd::ca_dir"],
        Exec['OpenSslGenrsa: proftpd'],
      ],
    }

    exec { 'OpenSslX509: proftpd':
      command => 'openssl x509 -out server.crt -in server.csr -days 365 -req -signkey server.key',
      path    => [
        '/usr/local/bin',
        '/usr/bin',
      ],
      cwd     => [
        "$::proftpd::ca_dir",
      ],
      creates => [
        "$::proftpd::ca_dir/server.crt",
      ],
      require => [
        File["$::proftpd::ca_dir"],
        Exec['OpenSslGenrsa: proftpd'],
        Exec['OpenSslReq: proftpd'],
      ],
    }
  }

  if $operatingsystem == 'freebsd' {
    include freebsd_newsyslog

    file { '/usr/local/etc/newsyslog.conf.d/proftpd.conf':
      ensure  => file,
      content => template('proftpd/newsyslog.conf.erb'),
    }
  }

}
