require 'spec_helper'

describe 'proftpd' do
  context 'supported operating systems' do
    ['Debian', 'RedHat'].each do |osfamily|
      describe "proftpd class without any parameters on #{osfamily}" do
        let(:params) {{ }}
        let(:facts) {{
          :osfamily => osfamily,
        }}

        it { should compile.with_all_deps }

        it { should contain_class('proftpd::params') }
        it { should contain_class('proftpd::install').that_comes_before('proftpd::config') }
        it { should contain_class('proftpd::config') }
        it { should contain_class('proftpd::service').that_subscribes_to('proftpd::config') }

        it { should contain_service('proftpd') }
        it { should contain_package('proftpd').with_ensure('present') }
      end
    end
  end

  context 'unsupported operating system' do
    describe 'proftpd class without any parameters on Solaris/Nexenta' do
      let(:facts) {{
        :osfamily        => 'Solaris',
        :operatingsystem => 'Nexenta',
      }}

      it { expect { should contain_package('proftpd') }.to raise_error(Puppet::Error, /Nexenta not supported/) }
    end
  end
end
