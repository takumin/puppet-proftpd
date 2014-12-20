# == Class proftpd::params
#
# This class is meant to be called from proftpd.
# It sets variables according to platform.
#
class proftpd::params {
  case $::osfamily {
    'Debian', 'RedHat', 'Amazon': {
      # Module Configuration
      $prefix       = undef
      $config       = '/etc/proftpd.conf'
      $base_dir     = '/etc/proftpd'
      $pw_dir       = '/etc/proftpd/pw'
      $ca_dir       = '/etc/proftpd/ca'
      $package_name = [ 'proftpd' ]
      $service_name = 'proftpd'
      # mod_core.c
      $PidFile        = '/var/run/proftpd.pid'
      $ScoreboardFile = '/var/run/proftpd.scoreboard'
      # mod_delay.c
      $DelayTable     = '/var/run/proftpd.delay'
    }
    'FreeBSD': {
      # Module Configuration
      $prefix       = '/usr/local'
      $config       = "$prefix/etc/proftpd.conf"
      $pw_dir       = "$prefix/etc/proftpd/pw"
      $ca_dir       = "$prefix/etc/proftpd/ca"
      $package_name = [ 'ftp/proftpd' ]
      $service_name = 'proftpd'
      # mod_core.c
      $PidFile        = '/var/run/proftpd.pid'
      $ScoreboardFile = '/var/run/proftpd.scoreboard'
      # mod_delay.c
      $DelayTable     = '/var/run/proftpd.delay'
    }
    default: {
      fail("${::operatingsystem} not supported")
    }
  }

  ###################################################################
  # Module Configuration
  ###################################################################
  $config_template = 'proftpd/proftpd.conf.erb'
  $package_ensure  = 'present'
  $service_ensure  = 'running'

  # ProFTPD only Authentication
  $managed_users  = undef
  $managed_groups = undef

  # Self-Signed Configuration
  $self_signed = false
  $self_ca_C   = undef
  $self_ca_ST  = undef
  $self_ca_L   = undef
  $self_ca_O   = "${::domain}"
  $self_ca_OU  = "${::hostname}"
  $self_ca_CN  = "${::fqdn}"
  $self_ca_E   = "postmaster@${::domain}"

  ###################################################################
  # ProFTPD Core Module
  ###################################################################

  # mod_auth.c
  $AccessDenyMsg           = undef
  $AccessGrantMsg          = undef
  $AllowChrootSymlinks     = undef
  $AnonRequirePassword     = undef
  $AnonRejectPasswords     = undef
  $AuthAliasOnly           = undef
  $AuthUsingAlias          = undef
  $CreateHome              = undef
  $DefaultChdir            = undef
  $DefaultRoot             = undef
  $DisplayLogin            = undef
  $GroupPassword           = undef
  $LoginPasswordPrompt     = undef
  $MaxClients              = undef
  $MaxClientsPerClass      = undef
  $MaxClientsPerHost       = undef
  $MaxClientsPerUser       = undef
  $MaxConnectionsPerHost   = undef
  $MaxHostsPerUser         = undef
  $MaxLoginAttempts        = undef
  $RequireValidShell       = undef
  $RewriteHome             = undef
  $RootLogin               = undef
  $RootRevoke              = undef
  $TimeoutLogin            = undef
  $TimeoutSession          = undef
  $UseFtpUsers             = undef
  $UseLastlog              = undef
  $UserAlias               = undef
  $UserDirRoot             = undef
  $UserPassword            = undef

  # mod_auth_file.c
  $AuthGroupFile           = undef
  $AuthUserFile            = undef

  # mod_auth_pam.c
  $AuthPAM                 = undef
  $AuthPAMConfig           = undef
  $AuthPAMOptions          = undef

  # mod_auth_unix.c
  $AuthUnixOptions         = undef
  $PersistentPasswd        = undef

  # mod_cap.c
  $CapabilitiesEngine      = undef
  $CapabilitiesRootRevoke  = undef
  $CapabilitiesSet         = undef

  # mod_core.c
  $Anonymous               = undef
  $Class                   = undef
  $Directory               = undef
  $Global                  = undef
  $IfDefine                = undef
  $IfModule                = undef
  $Limit                   = undef
  $VirtualHost             = undef
  $Allow                   = undef
  $AllowAll                = undef
  $AllowClass              = undef
  $AllowFilter             = undef
  $AllowForeignAddress     = undef
  $AllowGroup              = undef
  $AllowOverride           = undef
  $AllowUser               = undef
  $AuthOrder               = undef
  $CDPath                  = undef
  $CommandBufferSize       = undef
  $DebugLevel              = undef
  $DefaultAddress          = undef
  $DefaultServer           = undef
  $DefaultTransferMode     = undef
  $DeferWelcome            = undef
  $Define                  = undef
  $Deny                    = undef
  $DenyAll                 = undef
  $DenyClass               = undef
  $DenyFilter              = undef
  $DenyGroup               = undef
  $DenyUser                = undef
  $DisplayChdir            = undef
  $DisplayConnect          = undef
  $DisplayQuit             = undef
  $From                    = undef
  $Group                   = undef
  $GroupOwner              = undef
  $HideFiles               = undef
  $HideGroup               = undef
  $HideNoAccess            = undef
  $HideUser                = undef
  $IgnoreHidden            = undef
  $Include                 = undef
  $MasqueradeAddress       = undef
  $MaxCommandRate          = undef
  $MaxConnectionRate       = undef
  $MaxInstances            = undef
  $MultilineRFC2228        = undef
  $Order                   = undef
  $PassivePorts            = undef
  $PathAllowFilter         = undef
  $PathDenyFilter          = undef
  $Port                    = undef
  $ProcessTitles           = undef
  $Protocols               = undef
  $RegexOptions            = undef
  $Satisfy                 = undef
  $ScoreboardMutex         = undef
  $ScoreboardScrub         = undef
  $ServerAdmin             = undef
  $ServerAlias             = undef
  $ServerIdent             = undef
  $ServerName              = undef
  $ServerType              = undef
  $SetEnv                  = undef
  $SocketBindTight         = undef
  $SocketOptions           = undef
  $SyslogFacility          = undef
  $SyslogLevel             = undef
  $TimeoutIdle             = undef
  $TimeoutLinger           = undef
  $TimesGMT                = undef
  $Trace                   = undef
  $TraceLog                = undef
  $TraceOptions            = undef
  $TransferLog             = undef
  $Umask                   = undef
  $UnsetEnv                = undef
  $UseIPv6                 = undef
  $UseReverseDNS           = undef
  $User                    = undef
  $UserOwner               = undef
  $WtmpLog                 = undef
  $tcpBackLog              = undef
  $tcpNoDelay              = undef

  # mod_ctrls.c
  $ControlsACLs            = undef
  $ControlsAuthFreshness   = undef
  $ControlsEngine          = undef
  $ControlsInterval        = undef
  $ControlsLog             = undef
  $ControlsMaxClients      = undef
  $ControlsSocket          = undef
  $ControlsSocketACL       = undef
  $ControlsSocketOwner     = undef

  # mod_delay.c
  $DelayControlsACLs       = undef
  $DelayEngine             = undef
  $DelayOnEvent            = undef

  # mod_dso.c
  $LoadFile                = undef
  $LoadModule              = undef
  $ModuleControlsACLs      = undef
  $ModuleOrder             = undef
  $ModulePath              = undef

  # mod_facl.c
  $FACLEngine              = undef

  # mod_facts.c
  $FactsAdvertise          = undef
  $FactsOptions            = undef

  # mod_ident.c
  $IdentLookups            = undef

  # mod_lang.c
  $LangDefault             = undef
  $LangEngine              = undef
  $LangPath                = undef
  $UseEncoding             = undef

  # mod_log.c
  $AllowLogSymlinks        = undef
  $ExtendedLog             = undef
  $LogFormat               = undef
  $ServerLog               = undef
  $SystemLog               = undef

  # mod_ls.c
  $DirFakeUser             = undef
  $DirFakeGroup            = undef
  $DirFakeMode             = undef
  $ListOptions             = undef
  $ShowSymlinks            = undef
  $UseGlobbing             = undef

  # mod_memcache.c
  $MemcacheConnectFailures = undef
  $MemcacheEngine          = undef
  $MemcacheLog             = undef
  $MemcacheOptions         = undef
  $MemcacheReplicas        = undef
  $MemcacheServers         = undef
  $MemcacheTimeouts        = undef

  # mod_rlimit.c
  $RLimitChroot            = undef
  $RLimitCPU               = undef
  $RLimitMemory            = undef
  $RLimitOpenFiles         = undef

  # mod_site.c
  # none...

  # mod_xfer.c
  $AllowOverwrite          = undef
  $AllowRetrieveRestart    = undef
  $AllowStoreRestart       = undef
  $DeleteAbortedStores     = undef
  $DisplayFileTransfer     = undef
  $HiddenStores            = undef
  $MaxRetrieveFileSize     = undef
  $MaxStoreFileSize        = undef
  $MaxTransfersPerHost     = undef
  $MaxTransfersPerUser     = undef
  $StoreUniquePrefix       = undef
  $TimeoutNoTransfer       = undef
  $TimeoutStalled          = undef
  $TransferPriority        = undef
  $TransferRate            = undef
  $UseSendfile             = undef

  ###################################################################
  # ProFTPD Contrib Module
  ###################################################################

  # mod_ban.c
  $BanCache                            = undef
  $BanCacheOptions                     = undef
  $BanControlsACLs                     = undef
  $BanEngine                           = undef
  $BanLog                              = undef
  $BanMessage                          = undef
  $BanOnEvent                          = undef
  $BanTable                            = undef

  # mod_copy.c
  # none...

  # mod_ctrls_admin.c
  $AdminControlsACLs                   = undef
  $AdminControlsEngine                 = undef

  # mod_deflate.c
  $DeflateEngine                       = undef
  $DeflateLog                          = undef

  # mod_dnsbl.c
  $DNSBLDomain                         = undef
  $DNSBLEngine                         = undef
  $DNSBLLog                            = undef
  $DNSBLPolicy                         = undef

  # mod_dynmasq.c
  $DynMasqControlsACLs                 = undef
  $DynMasqRefresh                      = undef

  # mod_exec.c
  $ExecBeforeCommand                   = undef
  $ExecEnable                          = undef
  $ExecEngine                          = undef
  $ExecEnviron                         = undef
  $ExecLog                             = undef
  $ExecOnCommand                       = undef
  $ExecOnConnect                       = undef
  $ExecOnError                         = undef
  $ExecOnEvent                         = undef
  $ExecOnExit                          = undef
  $ExecOnRestart                       = undef
  $ExecOptions                         = undef
  $ExecTimeout                         = undef

  # mod_geoip.c
  $GeoIPAllowFilter                    = undef
  $GeoIPDenyFilter                     = undef
  $GeoIPEngine                         = undef
  $GeoIPLog                            = undef
  $GeoIPPolicy                         = undef
  $GeoIPTable                          = undef

  # mod_ifsession.c
  $IfAuthenticated                     = undef
  $IfClass                             = undef
  $IfGroup                             = undef
  $IfUser                              = undef

  # mod_ifversion.c
  $IfVersion                           = undef

  # mod_ldap.c
  $LDAPAliasDereference                = undef
  $LDAPAttr                            = undef
  $LDAPAuthBinds                       = undef
  $LDAPBindDN                          = undef
  $LDAPDefaultAuthScheme               = undef
  $LDAPDefaultGID                      = undef
  $LDAPDefaultQuota                    = undef
  $LDAPDefaultUID                      = undef
  $LDAPForceDefaultGID                 = undef
  $LDAPForceDefaultUID                 = undef
  $LDAPForceGeneratedHomedir           = undef
  $LDAPGenerateHomedir                 = undef
  $LDAPGenerateHomedirPrefix           = undef
  $LDAPGenerateHomedirPrefixNoUsername = undef
  $LDAPGroups                          = undef
  $LDAPLog                             = undef
  $LDAPProtocolVersion                 = undef
  $LDAPQueryTimeout                    = undef
  $LDAPSearchScope                     = undef
  $LDAPServer                          = undef
  $LDAPUsers                           = undef
  $LDAPUseTLS                          = undef

  # mod_load.c
  $MaxLoad                             = undef

  # mod_log_forensic.c
  $ForensicLogBufferSize               = undef
  $ForensicLogCapture                  = undef
  $ForensicLogCriteria                 = undef
  $ForensicLogEngine                   = undef
  $ForensicLogFile                     = undef

  # mod_qos.c
  $QoSOptions                          = undef

  # mod_quotatab.c
  $QuotaDefault                        = undef
  $QuotaDirectoryTally                 = undef
  $QuotaDisplayUnits                   = undef
  $QuotaEngine                         = undef
  $QuotaExcludeFilter                  = undef
  $QuotaLimitTable                     = undef
  $QuotaLock                           = undef
  $QuotaLog                            = undef
  $QuotaOptions                        = undef
  $QuotaShowQuotas                     = undef
  $QuotaTallyTable                     = undef

  # mod_quotatab_file.c
  # none...

  # mod_quotatab_ldap.c
  # none...

  # mod_quotatab_radius.c
  # none...

  # mod_quotatab_sql.c
  # none...

  # mod_radius.c
  $RadiusAcctServer                    = undef
  $RadiusAuthServer                    = undef
  $RadiusEngine                        = undef
  $RadiusGroupInfo                     = undef
  $RadiusLog                           = undef
  $RadiusNASIdentifier                 = undef
  $RadiusQuotaInfo                     = undef
  $RadiusRealm                         = undef
  $RadiusUserInfo                      = undef
  $RadiusVendor                        = undef

  # mod_ratio.c
  $UserRatio                           = undef
  $GroupRatio                          = undef
  $AnonRatio                           = undef
  $HostRatio                           = undef
  $Ratios                              = undef
  $FileRatioErrMsg                     = undef
  $ByteRatioErrMsg                     = undef
  $LeechRatioMsg                       = undef
  $CwdRatioMsg                         = undef
  $SaveRatios                          = undef
  $RatioFile                           = undef
  $RatioTempFile                       = undef

  # mod_readme.c
  $DisplayReadme                       = undef

  # mod_rewrite.c
  $RewriteCondition                    = undef
  $RewriteEngine                       = undef
  $RewriteLock                         = undef
  $RewriteMaxReplace                   = undef
  $RewriteLog                          = undef
  $RewriteMap                          = undef
  $RewriteRule                         = undef

  # mod_sftp.c
  $SFTPAcceptEnv                       = undef
  $SFTPAuthMethods                     = undef
  $SFTPAuthorizedHostKeys              = undef
  $SFTPAuthorizedUserKeys              = undef
  $SFTPCiphers                         = undef
  $SFTPClientAlive                     = undef
  $SFTPClientMatch                     = undef
  $SFTPCompression                     = undef
  $SFTPCryptoDevice                    = undef
  $SFTPDHParamFile                     = undef
  $SFTPDigests                         = undef
  $SFTPDisplayBanner                   = undef
  $SFTPEngine                          = undef
  $SFTPExtensions                      = undef
  $SFTPHostKey                         = undef
  $SFTPKeyBlacklist                    = undef
  $SFTPKeyExchanges                    = undef
  $SFTPLog                             = undef
  $SFTPMaxChannels                     = undef
  $SFTPOptions                         = undef
  $SFTPPassPhraseProvider              = undef
  $SFTPRekey                           = undef
  $SFTPTrafficPolicy                   = undef

  # mod_sftp_pam.c
  $SFTPPAMEngine                       = undef
  $SFTPPAMOptions                      = undef
  $SFTPPAMServiceName                  = undef

  # mod_sftp_sql.c
  # none...

  # mod_shaper.c
  $ShaperAll                           = undef
  $ShaperControlsACLs                  = undef
  $ShaperEngine                        = undef
  $ShaperLog                           = undef
  $ShaperSession                       = undef
  $ShaperTable                         = undef

  # mod_site_misc.c
  $SiteMiscEngine                      = undef

  # mod_snmp.c
  $SNMPAgent                           = undef
  $SNMPCommunity                       = undef
  $SNMPEnable                          = undef
  $SNMPEngine                          = undef
  $SNMPLog                             = undef
  $SNMPMaxVariables                    = undef
  $SNMPNotify                          = undef
  $SNMPOptions                         = undef
  $SNMPTables                          = undef

  # mod_sql.c
  $SQLConnectInfo                      = undef
  $SQLNamedConnectInfo                 = undef
  $SQLAuthenticate                     = undef
  $SQLAuthTypes                        = undef
  $SQLBackend                          = undef
  $SQLEngine                           = undef
  $SQLOptions                          = undef
  $SQLUserInfo                         = undef
  $SQLUserPrimaryKey                   = undef
  $SQLUserWhereClause                  = undef
  $SQLGroupInfo                        = undef
  $SQLGroupPrimaryKey                  = undef
  $SQLGroupWhereClause                 = undef
  $SQLMinID                            = undef
  $SQLMinUserUID                       = undef
  $SQLMinUserGID                       = undef
  $SQLDefaultUID                       = undef
  $SQLDefaultGID                       = undef
  $SQLNegativeCache                    = undef
  $SQLRatios                           = undef
  $SQLRatioStats                       = undef
  $SQLDefaultHomedir                   = undef
  $SQLLog                              = undef
  $SQLLogFile                          = undef
  $SQLLogOnEvent                       = undef
  $SQLNamedQuery                       = undef
  $SQLShowInfo                         = undef

  # mod_sql_mysql.c
  # none...

  # mod_sql_odbc.c
  # none...

  # mod_sql_passwd.c
  $SQLPasswordEncoding                 = undef
  $SQLPasswordEngine                   = undef
  $SQLPasswordOptions                  = undef
  $SQLPasswordPBKDF2                   = undef
  $SQLPasswordRounds                   = undef
  $SQLPasswordSaltFile                 = undef
  $SQLPasswordUserSalt                 = undef

  # mod_sql_postgres.c
  # none...

  # mod_sql_sqlite.c
  # none...

  # mod_tls.c
  $TLSCACertificateFile                = undef
  $TLSCACertificatePath                = undef
  $TLSCARevocationFile                 = undef
  $TLSCARevocationPath                 = undef
  $TLSCertificateChainFile             = undef
  $TLSCipherSuite                      = undef
  $TLSControlsACLs                     = undef
  $TLSCryptoDevice                     = undef
  $TLSDHParamFile                      = undef
  $TLSDSACertificateFile               = undef
  $TLSDSACertificateKeyFile            = undef
  $TLSECCertificateFile                = undef
  $TLSECCertificateKeyFile             = undef
  $TLSEngine                           = undef
  $TLSLog                              = undef
  $TLSMasqueradeAddress                = undef
  $TLSOptions                          = undef
  $TLSPassPhraseProvider               = undef
  $TLSPKCS12File                       = undef
  $TLSProtocol                         = undef
  $TLSRandomSeed                       = undef
  $TLSRenegotiate                      = undef
  $TLSRequired                         = undef
  $TLSRSACertificateFile               = undef
  $TLSRSACertificateKeyFile            = undef
  $TLSServerCipherPreference           = undef
  $TLSSessionCache                     = undef
  $TLSTimeoutHandshake                 = undef
  $TLSUserName                         = undef
  $TLSVerifyClient                     = undef
  $TLSVerifyDepth                      = undef
  $TLSVerifyOrder                      = undef
  $TLSVerifyServer                     = undef

  # mod_tls_memcache.c
  # none...

  # mod_tls_shmcache.c
  # none

  # mod_unique_id.c
  $UniqueIDEngine                      = undef

  # mod_wrap.c
  $TCPAccessFiles                      = undef
  $TCPAccessSyslogLevels               = undef
  $TCPGroupAccessFiles                 = undef
  $TCPServiceName                      = undef
  $TCPUserAccessFiles                  = undef

  # mod_wrap2.c
  $WrapAllowMsg                        = undef
  $WrapDenyMsg                         = undef
  $WrapEngine                          = undef
  $WrapGroupTables                     = undef
  $WrapLog                             = undef
  $WrapOptions                         = undef
  $WrapServiceName                     = undef
  $WrapTables                          = undef
  $WrapUserTables                      = undef

  # mod_wrap2_file.c
  # none...

  # mod_wrap2_sql.c
  # none...

}
