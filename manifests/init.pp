# == Class: proftpd
#
# Full description of class proftpd here.
#
# === Parameters
#
# [*sample_parameter*]
#   Explanation of what this parameter affects and what it defaults to.
#
class proftpd (
  $config                              = $::proftpd::params::config,
  $config_template                     = $::proftpd::params::config_template,
  $package_name                        = $::proftpd::params::package_name,
  $package_ensure                      = $::proftpd::params::package_ensure,
  $service_name                        = $::proftpd::params::service_name,
  $service_ensure                      = $::proftpd::params::service_ensure,
  $prefix                              = $::proftpd::params::prefix,
  $managed_users                       = $::proftpd::params::managed_users,
  $pw_dir                              = $::proftpd::params::pw_dir,
  $self_signed                         = $::proftpd::params::self_signed,
  $ca_dir                              = $::proftpd::params::ca_dir,
  $self_ca_C                           = $::proftpd::params::self_ca_C,
  $self_ca_ST                          = $::proftpd::params::self_ca_ST,
  $self_ca_L                           = $::proftpd::params::self_ca_L,
  $self_ca_O                           = $::proftpd::params::self_ca_O,
  $self_ca_OU                          = $::proftpd::params::self_ca_OU,
  $self_ca_CN                          = $::proftpd::params::self_ca_CN,
  $self_ca_E                           = $::proftpd::params::self_ca_E,
  #######################
  # ProFTPD Core Module #
  #######################
  # mod_auth.c
  $AccessDenyMsg                       = $::proftpd::params::AccessDenyMsg,
  $AccessGrantMsg                      = $::proftpd::params::AccessGrantMsg,
  $AllowChrootSymlinks                 = $::proftpd::params::AllowChrootSymlinks,
  $AnonRequirePassword                 = $::proftpd::params::AnonRequirePassword,
  $AnonRejectPasswords                 = $::proftpd::params::AnonRejectPasswords,
  $AuthAliasOnly                       = $::proftpd::params::AuthAliasOnly,
  $AuthUsingAlias                      = $::proftpd::params::AuthUsingAlias,
  $CreateHome                          = $::proftpd::params::CreateHome,
  $DefaultChdir                        = $::proftpd::params::DefaultChdir,
  $DefaultRoot                         = $::proftpd::params::DefaultRoot,
  $DisplayLogin                        = $::proftpd::params::DisplayLogin,
  $GroupPassword                       = $::proftpd::params::GroupPassword,
  $LoginPasswordPrompt                 = $::proftpd::params::LoginPasswordPrompt,
  $MaxClients                          = $::proftpd::params::MaxClients,
  $MaxClientsPerClass                  = $::proftpd::params::MaxClientsPerClass,
  $MaxClientsPerHost                   = $::proftpd::params::MaxClientsPerHost,
  $MaxClientsPerUser                   = $::proftpd::params::MaxClientsPerUser,
  $MaxConnectionsPerHost               = $::proftpd::params::MaxConnectionsPerHost,
  $MaxHostsPerUser                     = $::proftpd::params::MaxHostsPerUser,
  $MaxLoginAttempts                    = $::proftpd::params::MaxLoginAttempts,
  $RequireValidShell                   = $::proftpd::params::RequireValidShell,
  $RewriteHome                         = $::proftpd::params::RewriteHome,
  $RootLogin                           = $::proftpd::params::RootLogin,
  $RootRevoke                          = $::proftpd::params::RootRevoke,
  $TimeoutLogin                        = $::proftpd::params::TimeoutLogin,
  $TimeoutSession                      = $::proftpd::params::TimeoutSession,
  $UseFtpUsers                         = $::proftpd::params::UseFtpUsers,
  $UseLastlog                          = $::proftpd::params::UseLastlog,
  $UserAlias                           = $::proftpd::params::UserAlias,
  $UserDirRoot                         = $::proftpd::params::UserDirRoot,
  $UserPassword                        = $::proftpd::params::UserPassword,
  # mod_auth_file.c
  $AuthGroupFile                       = $::proftpd::params::AuthGroupFile,
  $AuthUserFile                        = $::proftpd::params::AuthUserFile,
  # mod_auth_pam.c
  $AuthPAM                             = $::proftpd::params::AuthPAM,
  $AuthPAMConfig                       = $::proftpd::params::AuthPAMConfig,
  $AuthPAMOptions                      = $::proftpd::params::AuthPAMOptions,
  # mod_auth_unix.c
  $AuthUnixOptions                     = $::proftpd::params::AuthUnixOptions,
  $PersistentPasswd                    = $::proftpd::params::PersistentPasswd,
  # mod_cap.c
  $CapabilitiesEngine                  = $::proftpd::params::CapabilitiesEngine,
  $CapabilitiesRootRevoke              = $::proftpd::params::CapabilitiesRootRevoke,
  $CapabilitiesSet                     = $::proftpd::params::CapabilitiesSet,
  # mod_core.c
  $Anonymous                           = $::proftpd::params::Anonymous,
  $Class                               = $::proftpd::params::Class,
  $Directory                           = $::proftpd::params::Directory,
  $Global                              = $::proftpd::params::Global,
  $IfDefine                            = $::proftpd::params::IfDefine,
  $IfModule                            = $::proftpd::params::IfModule,
  $Limit                               = $::proftpd::params::Limit,
  $VirtualHost                         = $::proftpd::params::VirtualHost,
  $Allow                               = $::proftpd::params::Allow,
  $AllowAll                            = $::proftpd::params::AllowAll,
  $AllowClass                          = $::proftpd::params::AllowClass,
  $AllowFilter                         = $::proftpd::params::AllowFilter,
  $AllowForeignAddress                 = $::proftpd::params::AllowForeignAddress,
  $AllowGroup                          = $::proftpd::params::AllowGroup,
  $AllowOverride                       = $::proftpd::params::AllowOverride,
  $AllowUser                           = $::proftpd::params::AllowUser,
  $AuthOrder                           = $::proftpd::params::AuthOrder,
  $CDPath                              = $::proftpd::params::CDPath,
  $CommandBufferSize                   = $::proftpd::params::CommandBufferSize,
  $DebugLevel                          = $::proftpd::params::DebugLevel,
  $DefaultAddress                      = $::proftpd::params::DefaultAddress,
  $DefaultServer                       = $::proftpd::params::DefaultServer,
  $DefaultTransferMode                 = $::proftpd::params::DefaultTransferMode,
  $DeferWelcome                        = $::proftpd::params::DeferWelcome,
  $Define                              = $::proftpd::params::Define,
  $Deny                                = $::proftpd::params::Deny,
  $DenyAll                             = $::proftpd::params::DenyAll,
  $DenyClass                           = $::proftpd::params::DenyClass,
  $DenyFilter                          = $::proftpd::params::DenyFilter,
  $DenyGroup                           = $::proftpd::params::DenyGroup,
  $DenyUser                            = $::proftpd::params::DenyUser,
  $DisplayChdir                        = $::proftpd::params::DisplayChdir,
  $DisplayConnect                      = $::proftpd::params::DisplayConnect,
  $DisplayQuit                         = $::proftpd::params::DisplayQuit,
  $From                                = $::proftpd::params::From,
  $Group                               = $::proftpd::params::Group,
  $GroupOwner                          = $::proftpd::params::GroupOwner,
  $HideFiles                           = $::proftpd::params::HideFiles,
  $HideGroup                           = $::proftpd::params::HideGroup,
  $HideNoAccess                        = $::proftpd::params::HideNoAccess,
  $HideUser                            = $::proftpd::params::HideUser,
  $IgnoreHidden                        = $::proftpd::params::IgnoreHidden,
  $Include                             = $::proftpd::params::Include,
  $MasqueradeAddress                   = $::proftpd::params::MasqueradeAddress,
  $MaxCommandRate                      = $::proftpd::params::MaxCommandRate,
  $MaxConnectionRate                   = $::proftpd::params::MaxConnectionRate,
  $MaxInstances                        = $::proftpd::params::MaxInstances,
  $MultilineRFC2228                    = $::proftpd::params::MultilineRFC2228,
  $Order                               = $::proftpd::params::Order,
  $PassivePorts                        = $::proftpd::params::PassivePorts,
  $PathAllowFilter                     = $::proftpd::params::PathAllowFilter,
  $PathDenyFilter                      = $::proftpd::params::PathDenyFilter,
  $PidFile                             = $::proftpd::params::PidFile,
  $Port                                = $::proftpd::params::Port,
  $ProcessTitles                       = $::proftpd::params::ProcessTitles,
  $Protocols                           = $::proftpd::params::Protocols,
  $RegexOptions                        = $::proftpd::params::RegexOptions,
  $Satisfy                             = $::proftpd::params::Satisfy,
  $ScoreboardFile                      = $::proftpd::params::ScoreboardFile,
  $ScoreboardMutex                     = $::proftpd::params::ScoreboardMutex,
  $ScoreboardScrub                     = $::proftpd::params::ScoreboardScrub,
  $ServerAdmin                         = $::proftpd::params::ServerAdmin,
  $ServerAlias                         = $::proftpd::params::ServerAlias,
  $ServerIdent                         = $::proftpd::params::ServerIdent,
  $ServerName                          = $::proftpd::params::ServerName,
  $ServerType                          = $::proftpd::params::ServerType,
  $SetEnv                              = $::proftpd::params::SetEnv,
  $SocketBindTight                     = $::proftpd::params::SocketBindTight,
  $SocketOptions                       = $::proftpd::params::SocketOptions,
  $SyslogFacility                      = $::proftpd::params::SyslogFacility,
  $SyslogLevel                         = $::proftpd::params::SyslogLevel,
  $TimeoutIdle                         = $::proftpd::params::TimeoutIdle,
  $TimeoutLinger                       = $::proftpd::params::TimeoutLinger,
  $TimesGMT                            = $::proftpd::params::TimesGMT,
  $Trace                               = $::proftpd::params::Trace,
  $TraceLog                            = $::proftpd::params::TraceLog,
  $TraceOptions                        = $::proftpd::params::TraceOptions,
  $TransferLog                         = $::proftpd::params::TransferLog,
  $Umask                               = $::proftpd::params::Umask,
  $UnsetEnv                            = $::proftpd::params::UnsetEnv,
  $UseIPv6                             = $::proftpd::params::UseIPv6,
  $UseReverseDNS                       = $::proftpd::params::UseReverseDNS,
  $User                                = $::proftpd::params::User,
  $UserOwner                           = $::proftpd::params::UserOwner,
  $WtmpLog                             = $::proftpd::params::WtmpLog,
  $tcpBackLog                          = $::proftpd::params::tcpBackLog,
  $tcpNoDelay                          = $::proftpd::params::tcpNoDelay,
  # mod_ctrls.c
  $ControlsACLs                        = $::proftpd::params::ControlsACLs,
  $ControlsAuthFreshness               = $::proftpd::params::ControlsAuthFreshness,
  $ControlsEngine                      = $::proftpd::params::ControlsEngine,
  $ControlsInterval                    = $::proftpd::params::ControlsInterval,
  $ControlsLog                         = $::proftpd::params::ControlsLog,
  $ControlsMaxClients                  = $::proftpd::params::ControlsMaxClients,
  $ControlsSocket                      = $::proftpd::params::ControlsSocket,
  $ControlsSocketACL                   = $::proftpd::params::ControlsSocketACL,
  $ControlsSocketOwner                 = $::proftpd::params::ControlsSocketOwner,
  # mod_delay.c
  $DelayControlsACLs                   = $::proftpd::params::DelayControlsACLs,
  $DelayEngine                         = $::proftpd::params::DelayEngine,
  $DelayOnEvent                        = $::proftpd::params::DelayOnEvent,
  $DelayTable                          = $::proftpd::params::DelayTable,
  # mod_dso.c
  $LoadFile                            = $::proftpd::params::LoadFile,
  $LoadModule                          = $::proftpd::params::LoadModule,
  $ModuleControlsACLs                  = $::proftpd::params::ModuleControlsACLs,
  $ModuleOrder                         = $::proftpd::params::ModuleOrder,
  $ModulePath                          = $::proftpd::params::ModulePath,
  # mod_facl.c
  $FACLEngine                          = $::proftpd::params::FACLEngine,
  # mod_facts.c
  $FactsAdvertise                      = $::proftpd::params::FactsAdvertise,
  $FactsOptions                        = $::proftpd::params::FactsOptions,
  # mod_ident.c
  $IdentLookups                        = $::proftpd::params::IdentLookups,
  # mod_lang.c
  $LangDefault                         = $::proftpd::params::LangDefault,
  $LangEngine                          = $::proftpd::params::LangEngine,
  $LangPath                            = $::proftpd::params::LangPath,
  $UseEncoding                         = $::proftpd::params::UseEncoding,
  # mod_log.c
  $AllowLogSymlinks                    = $::proftpd::params::AllowLogSymlinks,
  $ExtendedLog                         = $::proftpd::params::ExtendedLog,
  $LogFormat                           = $::proftpd::params::LogFormat,
  $ServerLog                           = $::proftpd::params::ServerLog,
  $SystemLog                           = $::proftpd::params::SystemLog,
  # mod_ls.c
  $DirFakeUser                         = $::proftpd::params::DirFakeUser,
  $DirFakeGroup                        = $::proftpd::params::DirFakeGroup,
  $DirFakeMode                         = $::proftpd::params::DirFakeMode,
  $ListOptions                         = $::proftpd::params::ListOptions,
  $ShowSymlinks                        = $::proftpd::params::ShowSymlinks,
  $UseGlobbing                         = $::proftpd::params::UseGlobbing,
  # mod_memcache.c
  $MemcacheConnectFailures             = $::proftpd::params::MemcacheConnectFailures,
  $MemcacheEngine                      = $::proftpd::params::MemcacheEngine,
  $MemcacheLog                         = $::proftpd::params::MemcacheLog,
  $MemcacheOptions                     = $::proftpd::params::MemcacheOptions,
  $MemcacheReplicas                    = $::proftpd::params::MemcacheReplicas,
  $MemcacheServers                     = $::proftpd::params::MemcacheServers,
  $MemcacheTimeouts                    = $::proftpd::params::MemcacheTimeouts,
  # mod_rlimit.c
  $RLimitChroot                        = $::proftpd::params::RLimitChroot,
  $RLimitCPU                           = $::proftpd::params::RLimitCPU,
  $RLimitMemory                        = $::proftpd::params::RLimitMemory,
  $RLimitOpenFiles                     = $::proftpd::params::RLimitOpenFiles,
  # mod_site.c
  # none...
  # mod_xfer.c
  $AllowOverwrite                      = $::proftpd::params::AllowOverwrite,
  $AllowRetrieveRestart                = $::proftpd::params::AllowRetrieveRestart,
  $AllowStoreRestart                   = $::proftpd::params::AllowStoreRestart,
  $DeleteAbortedStores                 = $::proftpd::params::DeleteAbortedStores,
  $DisplayFileTransfer                 = $::proftpd::params::DisplayFileTransfer,
  $HiddenStores                        = $::proftpd::params::HiddenStores,
  $MaxRetrieveFileSize                 = $::proftpd::params::MaxRetrieveFileSize,
  $MaxStoreFileSize                    = $::proftpd::params::MaxStoreFileSize,
  $MaxTransfersPerHost                 = $::proftpd::params::MaxTransfersPerHost,
  $MaxTransfersPerUser                 = $::proftpd::params::MaxTransfersPerUser,
  $StoreUniquePrefix                   = $::proftpd::params::StoreUniquePrefix,
  $TimeoutNoTransfer                   = $::proftpd::params::TimeoutNoTransfer,
  $TimeoutStalled                      = $::proftpd::params::TimeoutStalled,
  $TransferPriority                    = $::proftpd::params::TransferPriority,
  $TransferRate                        = $::proftpd::params::TransferRate,
  $UseSendfile                         = $::proftpd::params::UseSendfile,
  ##########################
  # ProFTPD Contrib Module #
  ##########################
  # mod_ban.c
  $BanCache                            = $::proftpd::params::BanCache,
  $BanCacheOptions                     = $::proftpd::params::BanCacheOptions,
  $BanControlsACLs                     = $::proftpd::params::BanControlsACLs,
  $BanEngine                           = $::proftpd::params::BanEngine,
  $BanLog                              = $::proftpd::params::BanLog,
  $BanMessage                          = $::proftpd::params::BanMessage,
  $BanOnEvent                          = $::proftpd::params::BanOnEvent,
  $BanTable                            = $::proftpd::params::BanTable,
  # mod_copy.c
  # none...
  # mod_ctrls_admin.c
  $AdminControlsACLs                   = $::proftpd::params::AdminControlsACLs,
  $AdminControlsEngine                 = $::proftpd::params::AdminControlsEngine,
  # mod_deflate.c
  $DeflateEngine                       = $::proftpd::params::DeflateEngine,
  $DeflateLog                          = $::proftpd::params::DeflateLog,
  # mod_dnsbl.c
  $DNSBLDomain                         = $::proftpd::params::DNSBLDomain,
  $DNSBLEngine                         = $::proftpd::params::DNSBLEngine,
  $DNSBLLog                            = $::proftpd::params::DNSBLLog,
  $DNSBLPolicy                         = $::proftpd::params::DNSBLPolicy,
  # mod_dynmasq.c
  $DynMasqControlsACLs                 = $::proftpd::params::DynMasqControlsACLs,
  $DynMasqRefresh                      = $::proftpd::params::DynMasqRefresh,
  # mod_exec.c
  $ExecBeforeCommand                   = $::proftpd::params::ExecBeforeCommand,
  $ExecEnable                          = $::proftpd::params::ExecEnable,
  $ExecEngine                          = $::proftpd::params::ExecEngine,
  $ExecEnviron                         = $::proftpd::params::ExecEnviron,
  $ExecLog                             = $::proftpd::params::ExecLog,
  $ExecOnCommand                       = $::proftpd::params::ExecOnCommand,
  $ExecOnConnect                       = $::proftpd::params::ExecOnConnect,
  $ExecOnError                         = $::proftpd::params::ExecOnError,
  $ExecOnEvent                         = $::proftpd::params::ExecOnEvent,
  $ExecOnExit                          = $::proftpd::params::ExecOnExit,
  $ExecOnRestart                       = $::proftpd::params::ExecOnRestart,
  $ExecOptions                         = $::proftpd::params::ExecOptions,
  $ExecTimeout                         = $::proftpd::params::ExecTimeout,
  # mod_geoip.c
  $GeoIPAllowFilter                    = $::proftpd::params::GeoIPAllowFilter,
  $GeoIPDenyFilter                     = $::proftpd::params::GeoIPDenyFilter,
  $GeoIPEngine                         = $::proftpd::params::GeoIPEngine,
  $GeoIPLog                            = $::proftpd::params::GeoIPLog,
  $GeoIPPolicy                         = $::proftpd::params::GeoIPPolicy,
  $GeoIPTable                          = $::proftpd::params::GeoIPTable,
  # mod_ifsession.c
  $IfAuthenticated                     = $::proftpd::params::IfAuthenticated,
  $IfClass                             = $::proftpd::params::IfClass,
  $IfGroup                             = $::proftpd::params::IfGroup,
  $IfUser                              = $::proftpd::params::IfUser,
  # mod_ifversion.c
  $IfVersion                           = $::proftpd::params::IfVersion,
  # mod_ldap.c
  $LDAPAliasDereference                = $::proftpd::params::LDAPAliasDereference,
  $LDAPAttr                            = $::proftpd::params::LDAPAttr,
  $LDAPAuthBinds                       = $::proftpd::params::LDAPAuthBinds,
  $LDAPBindDN                          = $::proftpd::params::LDAPBindDN,
  $LDAPDefaultAuthScheme               = $::proftpd::params::LDAPDefaultAuthScheme,
  $LDAPDefaultGID                      = $::proftpd::params::LDAPDefaultGID,
  $LDAPDefaultQuota                    = $::proftpd::params::LDAPDefaultQuota,
  $LDAPDefaultUID                      = $::proftpd::params::LDAPDefaultUID,
  $LDAPForceDefaultGID                 = $::proftpd::params::LDAPForceDefaultGID,
  $LDAPForceDefaultUID                 = $::proftpd::params::LDAPForceDefaultUID,
  $LDAPForceGeneratedHomedir           = $::proftpd::params::LDAPForceGeneratedHomedir,
  $LDAPGenerateHomedir                 = $::proftpd::params::LDAPGenerateHomedir,
  $LDAPGenerateHomedirPrefix           = $::proftpd::params::LDAPGenerateHomedirPrefix,
  $LDAPGenerateHomedirPrefixNoUsername = $::proftpd::params::LDAPGenerateHomedirPrefixNoUsername,
  $LDAPGroups                          = $::proftpd::params::LDAPGroups,
  $LDAPLog                             = $::proftpd::params::LDAPLog,
  $LDAPProtocolVersion                 = $::proftpd::params::LDAPProtocolVersion,
  $LDAPQueryTimeout                    = $::proftpd::params::LDAPQueryTimeout,
  $LDAPSearchScope                     = $::proftpd::params::LDAPSearchScope,
  $LDAPServer                          = $::proftpd::params::LDAPServer,
  $LDAPUsers                           = $::proftpd::params::LDAPUsers,
  $LDAPUseTLS                          = $::proftpd::params::LDAPUseTLS,
  # mod_load.c
  $MaxLoad                             = $::proftpd::params::MaxLoad,
  # mod_log_forensic.c
  $ForensicLogBufferSize               = $::proftpd::params::ForensicLogBufferSize,
  $ForensicLogCapture                  = $::proftpd::params::ForensicLogCapture,
  $ForensicLogCriteria                 = $::proftpd::params::ForensicLogCriteria,
  $ForensicLogEngine                   = $::proftpd::params::ForensicLogEngine,
  $ForensicLogFile                     = $::proftpd::params::ForensicLogFile,
  # mod_qos.c
  $QoSOptions                          = $::proftpd::params::QoSOptions,
  # mod_quotatab.c
  $QuotaDefault                        = $::proftpd::params::QuotaDefault,
  $QuotaDirectoryTally                 = $::proftpd::params::QuotaDirectoryTally,
  $QuotaDisplayUnits                   = $::proftpd::params::QuotaDisplayUnits,
  $QuotaEngine                         = $::proftpd::params::QuotaEngine,
  $QuotaExcludeFilter                  = $::proftpd::params::QuotaExcludeFilter,
  $QuotaLimitTable                     = $::proftpd::params::QuotaLimitTable,
  $QuotaLock                           = $::proftpd::params::QuotaLock,
  $QuotaLog                            = $::proftpd::params::QuotaLog,
  $QuotaOptions                        = $::proftpd::params::QuotaOptions,
  $QuotaShowQuotas                     = $::proftpd::params::QuotaShowQuotas,
  $QuotaTallyTable                     = $::proftpd::params::QuotaTallyTable,
  # mod_quotatab_file.c
  # none...
  # mod_quotatab_ldap.c
  # none...
  # mod_quotatab_radius.c
  # none...
  # mod_quotatab_sql.c
  # none...
  # mod_radius.c
  $RadiusAcctServer                    = $::proftpd::params::RadiusAcctServer,
  $RadiusAuthServer                    = $::proftpd::params::RadiusAuthServer,
  $RadiusEngine                        = $::proftpd::params::RadiusEngine,
  $RadiusGroupInfo                     = $::proftpd::params::RadiusGroupInfo,
  $RadiusLog                           = $::proftpd::params::RadiusLog,
  $RadiusNASIdentifier                 = $::proftpd::params::RadiusNASIdentifier,
  $RadiusQuotaInfo                     = $::proftpd::params::RadiusQuotaInfo,
  $RadiusRealm                         = $::proftpd::params::RadiusRealm,
  $RadiusUserInfo                      = $::proftpd::params::RadiusUserInfo,
  $RadiusVendor                        = $::proftpd::params::RadiusVendor,
  # mod_ratio.c
  $UserRatio                           = $::proftpd::params::UserRatio,
  $GroupRatio                          = $::proftpd::params::GroupRatio,
  $AnonRatio                           = $::proftpd::params::AnonRatio,
  $HostRatio                           = $::proftpd::params::HostRatio,
  $Ratios                              = $::proftpd::params::Ratios,
  $FileRatioErrMsg                     = $::proftpd::params::FileRatioErrMsg,
  $ByteRatioErrMsg                     = $::proftpd::params::ByteRatioErrMsg,
  $LeechRatioMsg                       = $::proftpd::params::LeechRatioMsg,
  $CwdRatioMsg                         = $::proftpd::params::CwdRatioMsg,
  $SaveRatios                          = $::proftpd::params::SaveRatios,
  $RatioFile                           = $::proftpd::params::RatioFile,
  $RatioTempFile                       = $::proftpd::params::RatioTempFile,
  # mod_readme.c
  $DisplayReadme                       = $::proftpd::params::DisplayReadme,
  # mod_rewrite.c
  $RewriteCondition                    = $::proftpd::params::RewriteCondition,
  $RewriteEngine                       = $::proftpd::params::RewriteEngine,
  $RewriteLock                         = $::proftpd::params::RewriteLock,
  $RewriteMaxReplace                   = $::proftpd::params::RewriteMaxReplace,
  $RewriteLog                          = $::proftpd::params::RewriteLog,
  $RewriteMap                          = $::proftpd::params::RewriteMap,
  $RewriteRule                         = $::proftpd::params::RewriteRule,
  # mod_sftp.c
  $SFTPAcceptEnv                       = $::proftpd::params::SFTPAcceptEnv,
  $SFTPAuthMethods                     = $::proftpd::params::SFTPAuthMethods,
  $SFTPAuthorizedHostKeys              = $::proftpd::params::SFTPAuthorizedHostKeys,
  $SFTPAuthorizedUserKeys              = $::proftpd::params::SFTPAuthorizedUserKeys,
  $SFTPCiphers                         = $::proftpd::params::SFTPCiphers,
  $SFTPClientAlive                     = $::proftpd::params::SFTPClientAlive,
  $SFTPClientMatch                     = $::proftpd::params::SFTPClientMatch,
  $SFTPCompression                     = $::proftpd::params::SFTPCompression,
  $SFTPCryptoDevice                    = $::proftpd::params::SFTPCryptoDevice,
  $SFTPDHParamFile                     = $::proftpd::params::SFTPDHParamFile,
  $SFTPDigests                         = $::proftpd::params::SFTPDigests,
  $SFTPDisplayBanner                   = $::proftpd::params::SFTPDisplayBanner,
  $SFTPEngine                          = $::proftpd::params::SFTPEngine,
  $SFTPExtensions                      = $::proftpd::params::SFTPExtensions,
  $SFTPHostKey                         = $::proftpd::params::SFTPHostKey,
  $SFTPKeyBlacklist                    = $::proftpd::params::SFTPKeyBlacklist,
  $SFTPKeyExchanges                    = $::proftpd::params::SFTPKeyExchanges,
  $SFTPLog                             = $::proftpd::params::SFTPLog,
  $SFTPMaxChannels                     = $::proftpd::params::SFTPMaxChannels,
  $SFTPOptions                         = $::proftpd::params::SFTPOptions,
  $SFTPPassPhraseProvider              = $::proftpd::params::SFTPPassPhraseProvider,
  $SFTPRekey                           = $::proftpd::params::SFTPRekey,
  $SFTPTrafficPolicy                   = $::proftpd::params::SFTPTrafficPolicy,
  # mod_sftp_pam.c
  $SFTPPAMEngine                       = $::proftpd::params::SFTPPAMEngine,
  $SFTPPAMOptions                      = $::proftpd::params::SFTPPAMOptions,
  $SFTPPAMServiceName                  = $::proftpd::params::SFTPPAMServiceName,
  # mod_sftp_sql.c
  # none...
  # mod_shaper.c
  $ShaperAll                           = $::proftpd::params::ShaperAll,
  $ShaperControlsACLs                  = $::proftpd::params::ShaperControlsACLs,
  $ShaperEngine                        = $::proftpd::params::ShaperEngine,
  $ShaperLog                           = $::proftpd::params::ShaperLog,
  $ShaperSession                       = $::proftpd::params::ShaperSession,
  $ShaperTable                         = $::proftpd::params::ShaperTable,
  # mod_site_misc.c
  $SiteMiscEngine                      = $::proftpd::params::SiteMiscEngine,
  # mod_snmp.c
  $SNMPAgent                           = $::proftpd::params::SNMPAgent,
  $SNMPCommunity                       = $::proftpd::params::SNMPCommunity,
  $SNMPEnable                          = $::proftpd::params::SNMPEnable,
  $SNMPEngine                          = $::proftpd::params::SNMPEngine,
  $SNMPLog                             = $::proftpd::params::SNMPLog,
  $SNMPMaxVariables                    = $::proftpd::params::SNMPMaxVariables,
  $SNMPNotify                          = $::proftpd::params::SNMPNotify,
  $SNMPOptions                         = $::proftpd::params::SNMPOptions,
  $SNMPTables                          = $::proftpd::params::SNMPTables,
  # mod_sql.c
  $SQLConnectInfo                      = $::proftpd::params::SQLConnectInfo,
  $SQLNamedConnectInfo                 = $::proftpd::params::SQLNamedConnectInfo,
  $SQLAuthenticate                     = $::proftpd::params::SQLAuthenticate,
  $SQLAuthTypes                        = $::proftpd::params::SQLAuthTypes,
  $SQLBackend                          = $::proftpd::params::SQLBackend,
  $SQLEngine                           = $::proftpd::params::SQLEngine,
  $SQLOptions                          = $::proftpd::params::SQLOptions,
  $SQLUserInfo                         = $::proftpd::params::SQLUserInfo,
  $SQLUserPrimaryKey                   = $::proftpd::params::SQLUserPrimaryKey,
  $SQLUserWhereClause                  = $::proftpd::params::SQLUserWhereClause,
  $SQLGroupInfo                        = $::proftpd::params::SQLGroupInfo,
  $SQLGroupPrimaryKey                  = $::proftpd::params::SQLGroupPrimaryKey,
  $SQLGroupWhereClause                 = $::proftpd::params::SQLGroupWhereClause,
  $SQLMinID                            = $::proftpd::params::SQLMinID,
  $SQLMinUserUID                       = $::proftpd::params::SQLMinUserUID,
  $SQLMinUserGID                       = $::proftpd::params::SQLMinUserGID,
  $SQLDefaultUID                       = $::proftpd::params::SQLDefaultUID,
  $SQLDefaultGID                       = $::proftpd::params::SQLDefaultGID,
  $SQLNegativeCache                    = $::proftpd::params::SQLNegativeCache,
  $SQLRatios                           = $::proftpd::params::SQLRatios,
  $SQLRatioStats                       = $::proftpd::params::SQLRatioStats,
  $SQLDefaultHomedir                   = $::proftpd::params::SQLDefaultHomedir,
  $SQLLog                              = $::proftpd::params::SQLLog,
  $SQLLogFile                          = $::proftpd::params::SQLLogFile,
  $SQLLogOnEvent                       = $::proftpd::params::SQLLogOnEvent,
  $SQLNamedQuery                       = $::proftpd::params::SQLNamedQuery,
  $SQLShowInfo                         = $::proftpd::params::SQLShowInfo,
  # mod_sql_mysql.c
  # none...
  # mod_sql_odbc.c
  # none...
  # mod_sql_passwd.c
  $SQLPasswordEncoding                 = $::proftpd::params::SQLPasswordEncoding,
  $SQLPasswordEngine                   = $::proftpd::params::SQLPasswordEngine,
  $SQLPasswordOptions                  = $::proftpd::params::SQLPasswordOptions,
  $SQLPasswordPBKDF2                   = $::proftpd::params::SQLPasswordPBKDF2,
  $SQLPasswordRounds                   = $::proftpd::params::SQLPasswordRounds,
  $SQLPasswordSaltFile                 = $::proftpd::params::SQLPasswordSaltFile,
  $SQLPasswordUserSalt                 = $::proftpd::params::SQLPasswordUserSalt,
  # mod_sql_postgres.c
  # none...
  # mod_sql_sqlite.c
  # none...
  # mod_tls.c
  $TLSCACertificateFile                = $::proftpd::params::TLSCACertificateFile,
  $TLSCACertificatePath                = $::proftpd::params::TLSCACertificatePath,
  $TLSCARevocationFile                 = $::proftpd::params::TLSCARevocationFile,
  $TLSCARevocationPath                 = $::proftpd::params::TLSCARevocationPath,
  $TLSCertificateChainFile             = $::proftpd::params::TLSCertificateChainFile,
  $TLSCipherSuite                      = $::proftpd::params::TLSCipherSuite,
  $TLSControlsACLs                     = $::proftpd::params::TLSControlsACLs,
  $TLSCryptoDevice                     = $::proftpd::params::TLSCryptoDevice,
  $TLSDHParamFile                      = $::proftpd::params::TLSDHParamFile,
  $TLSDSACertificateFile               = $::proftpd::params::TLSDSACertificateFile,
  $TLSDSACertificateKeyFile            = $::proftpd::params::TLSDSACertificateKeyFile,
  $TLSECCertificateFile                = $::proftpd::params::TLSECCertificateFile,
  $TLSECCertificateKeyFile             = $::proftpd::params::TLSECCertificateKeyFile,
  $TLSEngine                           = $::proftpd::params::TLSEngine,
  $TLSLog                              = $::proftpd::params::TLSLog,
  $TLSMasqueradeAddress                = $::proftpd::params::TLSMasqueradeAddress,
  $TLSOptions                          = $::proftpd::params::TLSOptions,
  $TLSPassPhraseProvider               = $::proftpd::params::TLSPassPhraseProvider,
  $TLSPKCS12File                       = $::proftpd::params::TLSPKCS12File,
  $TLSProtocol                         = $::proftpd::params::TLSProtocol,
  $TLSRandomSeed                       = $::proftpd::params::TLSRandomSeed,
  $TLSRenegotiate                      = $::proftpd::params::TLSRenegotiate,
  $TLSRequired                         = $::proftpd::params::TLSRequired,
  $TLSRSACertificateFile               = $::proftpd::params::TLSRSACertificateFile,
  $TLSRSACertificateKeyFile            = $::proftpd::params::TLSRSACertificateKeyFile,
  $TLSServerCipherPreference           = $::proftpd::params::TLSServerCipherPreference,
  $TLSSessionCache                     = $::proftpd::params::TLSSessionCache,
  $TLSTimeoutHandshake                 = $::proftpd::params::TLSTimeoutHandshake,
  $TLSUserName                         = $::proftpd::params::TLSUserName,
  $TLSVerifyClient                     = $::proftpd::params::TLSVerifyClient,
  $TLSVerifyDepth                      = $::proftpd::params::TLSVerifyDepth,
  $TLSVerifyOrder                      = $::proftpd::params::TLSVerifyOrder,
  $TLSVerifyServer                     = $::proftpd::params::TLSVerifyServer,
  # mod_tls_memcache.c
  # none...
  # mod_tls_shmcache.c
  # none
  # mod_unique_id.c
  $UniqueIDEngine                      = $::proftpd::params::UniqueIDEngine,
  # mod_wrap.c
  $TCPAccessFiles                      = $::proftpd::params::TCPAccessFiles,
  $TCPAccessSyslogLevels               = $::proftpd::params::TCPAccessSyslogLevels,
  $TCPGroupAccessFiles                 = $::proftpd::params::TCPGroupAccessFiles,
  $TCPServiceName                      = $::proftpd::params::TCPServiceName,
  $TCPUserAccessFiles                  = $::proftpd::params::TCPUserAccessFiles,
  # mod_wrap2.c
  $WrapAllowMsg                        = $::proftpd::params::WrapAllowMsg,
  $WrapDenyMsg                         = $::proftpd::params::WrapDenyMsg,
  $WrapEngine                          = $::proftpd::params::WrapEngine,
  $WrapGroupTables                     = $::proftpd::params::WrapGroupTables,
  $WrapLog                             = $::proftpd::params::WrapLog,
  $WrapOptions                         = $::proftpd::params::WrapOptions,
  $WrapServiceName                     = $::proftpd::params::WrapServiceName,
  $WrapTables                          = $::proftpd::params::WrapTables,
  $WrapUserTables                      = $::proftpd::params::WrapUserTables,
  # mod_wrap2_file.c
  # none...
  # mod_wrap2_sql.c
  # none...
) inherits ::proftpd::params {

  include stdlib

  validate_string($config)
  validate_string($config_template)

  validate_array($package_name)
  validate_string($package_ensure)
  validate_string($service_name)
  validate_string($service_ensure)

  if $managed_users != undef {
    if $AuthGroupFile == undef {
      $AuthGroupFile = "$prefix/pw/passwd"
    }
    if $AuthUserFile == undef {
      $AuthUserFile = "$prefix/pw/group"
    }
  }

  class { '::proftpd::install': } ->
  class { '::proftpd::config': } ~>
  class { '::proftpd::service': } ->
  Class['::proftpd']
}
