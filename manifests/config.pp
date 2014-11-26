# == Class proftpd::config
#
# This class is called from proftpd for service config.
#
class proftpd::config {

  file { "$config":
    ensure       => file,
    owner        => 0,
    group        => 0,
    mode         => '0644',
    content      => template($config_template),
    validate_cmd => "$prefix/sbin/proftpd -t -c %",
  }

  if $AuthGroupFile != undef {
    file { "$AuthGroupFile":
      ensure       => file,
      owner        => 0,
      group        => 0,
      mode         => '0440',
    }
  }

  if $AuthUserFile != undef {
    file { "$AuthUserFile":
      ensure       => file,
      owner        => 0,
      group        => 0,
      mode         => '0440',
    }
  }

  if $self_signed == true {
    file { "$ca_dir":
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
        "$ca_dir",
      ],
      creates => [
        "$ca_dir/server.key",
      ],
      require => [
        File["$ca_dir"],
      ],
    }

    $subj_args = "/C=$ca_C/ST=$ca_ST/L=$ca_L/O=$ca_O/OU=$ca_OU/CN=$ca_CN/E=$ca_E/"

    exec { 'OpenSslReq: proftpd':
      command => "openssl req -out server.csr -new -key server.key -subj $subj_args -batch",
      path    => [
        '/usr/local/bin',
        '/usr/bin',
      ],
      cwd     => [
        "$ca_dir",
      ],
      creates => [
        "$ca_dir/server.csr",
      ],
      require => [
        File["$ca_dir"],
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
        "$ca_dir",
      ],
      creates => [
        "$ca_dir/server.crt",
      ],
      require => [
        File["$ca_dir"],
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
