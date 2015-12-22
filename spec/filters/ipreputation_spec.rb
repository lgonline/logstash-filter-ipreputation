# encoding: utf-8
require 'logstash/devutils/rspec/spec_helper'
require 'logstash/filters/ipreputation'

describe LogStash::Filters::Ipreputation do
  describe 'Get behaviour from redis' do
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
end
