# == Class proftpd::install
#
# This class is called from proftpd for install.
#
class proftpd::install {

  package { $::proftpd::package_name:
    ensure => $::proftpd::package_ensure,
  }

}
