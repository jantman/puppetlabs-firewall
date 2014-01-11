require 'spec_helper_acceptance'

describe "param based tests:" do
  # Takes a hash and converts it into a firewall resource
  def pp(params)
    name = params.delete('name') || 'test'
    pm = <<-EOS
firewall { '#{name}':
    EOS

    params.each do |k,v|
      pm += <<-EOS
  #{k} => #{v},
      EOS
    end

    pm += <<-EOS
}
    EOS
    pm
  end

  it 'test various params' do
    iptables_flush_all_tables

    unless (fact('operatingsystem') == 'CentOS') && \
      fact('operatingsystemrelease') =~ /^5\./ then

      ppm = pp({
        'order' => '100',
        'table' => "'raw'",
        'socket' => 'true',
        'chain' => "'PREROUTING'",
        'jump' => 'LOG',
        'log_level' => 'debug',
      })

      expect(apply_manifest(ppm, :catch_failures => true).exit_code).to eq(2)
      expect(apply_manifest(ppm, :catch_failures => true).exit_code).to be_zero
    end
  end

  it 'test log rule' do
    iptables_flush_all_tables

    ppm = pp({
      'name' => 'log all',
      'order' => '998',
      'proto' => 'all',
      'jump' => 'LOG',
      'log_level' => 'debug',
    })
    expect(apply_manifest(ppm, :catch_failures => true).exit_code).to eq(2)
    expect(apply_manifest(ppm, :catch_failures => true).exit_code).to be_zero
  end

  it 'test log rule - changing names' do
    iptables_flush_all_tables

    ppm1 = pp({
      'name' => 'log all INVALID packets',
      'order' => '004',
      'chain' => 'INPUT',
      'proto' => 'all',
      'ctstate' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => '3',
      'log_prefix' => '"IPTABLES dropped invalid: "',
    })

    ppm2 = pp({
      'name' => 'log all INVALID packets',
      'order' => '003',
      'chain' => 'INPUT',
      'proto' => 'all',
      'ctstate' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => '3',
      'log_prefix' => '"IPTABLES dropped invalid: "',
    })

    expect(apply_manifest(ppm1, :catch_failures => true).exit_code).to eq(2)

    ppm = <<-EOS + "\n" + ppm2
      resources { 'firewall':
        purge => true,
      }
    EOS
    expect(apply_manifest(ppm, :catch_failures => true).exit_code).to eq(2)
  end

  it 'test log rule - idempotent' do
    iptables_flush_all_tables

    ppm1 = pp({
      'name' => 'log all INVALID packets',
      'order' => '004',
      'chain' => 'INPUT',
      'proto' => 'all',
      'ctstate' => 'INVALID',
      'jump' => 'LOG',
      'log_level' => '3',
      'log_prefix' => '"IPTABLES dropped invalid: "',
    })

    expect(apply_manifest(ppm1, :catch_failures => true).exit_code).to eq(2)
    expect(apply_manifest(ppm1, :catch_failures => true).exit_code).to be_zero
  end

  it 'test src_range rule' do
    iptables_flush_all_tables

    ppm = pp({
      'name'      => 'block src ip range',
      'order'     => '997',
      'chain'     => 'INPUT',
      'proto'     => 'all',
      'action'    => 'drop',
      'src_range' => '"10.0.0.1-10.0.0.10"',
    })
    expect(apply_manifest(ppm, :catch_failures => true).exit_code).to eq(2)
    expect(apply_manifest(ppm, :catch_failures => true).exit_code).to be_zero
  end

  it 'test dst_range rule' do
    iptables_flush_all_tables

    ppm = pp({
      'name'      => 'block dst ip range',
      'order'     => '998',
      'chain'     => 'INPUT',
      'proto'     => 'all',
      'action'    => 'drop',
      'dst_range' => '"10.0.0.2-10.0.0.20"',
    })
    expect(apply_manifest(ppm, :catch_failures => true).exit_code).to eq(2)
    expect(apply_manifest(ppm, :catch_failures => true).exit_code).to be_zero
  end

end
