require 'spec_helper_acceptance'

# Some tests for the standard recommended usage
describe 'standard usage tests:' do
  it 'applies twice' do
    pp = <<-EOS
      class my_fw::pre {
        Firewall {
          require => undef,
        }

        # Default firewall rules
        firewall { '000 accept all icmp':
          proto   => 'icmp',
          action  => 'accept',
        }->
        firewall { 'accept all to lo interface':
          order   => 1,
          proto   => 'all',
          iniface => 'lo',
          action  => 'accept',
        }->
        firewall { '002 accept related established rules':
          proto   => 'all',
          ctstate => ['RELATED', 'ESTABLISHED'],
          action  => 'accept',
        }
      }
      class my_fw::post {
        firewall { 'drop all':
          order   => 999,
          proto   => 'all',
          action  => 'drop',
          before  => undef,
        }
      }
      resources { "firewall":
        purge => true
      }
      Firewall {
        before  => Class['my_fw::post'],
        require => Class['my_fw::pre'],
      }
      class { ['my_fw::pre', 'my_fw::post']: }
      class { 'firewall': }
      firewall { '500 open up port 22':
        action => 'accept',
        proto => 'tcp',
        dport => 22,
      }
    EOS

    # Run it twice and test for idempotency
    apply_manifest(pp, :catch_failures => true)
    expect(apply_manifest(pp, :catch_failures => true).exit_code).to be_zero
  end
end
