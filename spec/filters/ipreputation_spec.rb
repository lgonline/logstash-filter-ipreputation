# encoding: utf-8
require 'logstash/devutils/rspec/spec_helper'
require 'logstash/filters/ipreputation'

describe LogStash::Filters::Ipreputation do

  describe 'Get all reputation' do
    let(:config) do <<-CONFIG
      filter {
        ipreputation {
          host => "10.120.24.91"
        }
      }
    CONFIG
    end

    sample('message' => '208.109.181.210, 127.0.0.1') do
      expect(subject).to include('reputation')
      expect(subject['reputation']).to eq("{\"malware\":\"10\",\"phish_host\":\"10\"}")
    end
  end

  describe 'Get all behaviour' do
    let(:config) do <<-CONFIG
      filter {
        ipreputation {
          host => "10.120.24.91"
          separate_reputation => true
        }
      }
    CONFIG
    end

    sample('message' => '208.109.181.210, 127.0.0.1') do
      expect(subject).to include('behaviour')
      expect(subject['behaviour']).to eq(['malware', 'phish_host'])
    end
  end

  describe 'If there is no behaviour, let behaviour eq to unknown' do
    let(:config) do <<-CONFIG
      filter {
        ipreputation {
          host => "10.120.24.91"
          separate_reputation => true
        }
      }
    CONFIG
    end

    sample('message' => '127.0.0.1') do
      expect(subject).to include('behaviour')
      expect(subject['behaviour']).to eq(['unknown'])
    end
  end

  describe 'Get each reputation of threat type' do
    let(:config) do <<-CONFIG
      filter {
        ipreputation {
          host => "10.120.24.91"
          separate_reputation => true
        }
      }
    CONFIG
    end

    sample('message' => '208.109.181.210, 127.0.0.1') do
      expect(subject).to include('malware')
      expect(subject).to include('phish_host')
      expect(subject['malware']).to eq(10)
      expect(subject['phish_host']).to eq(10)
    end
  end

end
