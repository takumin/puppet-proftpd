# == Class proftpd::service
#
# This class is meant to be called from proftpd.
# It ensure the service is running.
#
class proftpd::service {

  service { $::proftpd::service_name:
    ensure     => $::proftpd::service_ensure,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
  }

}
