# encoding: utf-8
require 'logstash/filters/base'
require 'logstash/namespace'
require 'json/ext'

class LogStash::Filters::Ipreputation < LogStash::Filters::Base

  config_name 'ipreputation'

  config :host, :validate => :string, :default => '127.0.0.1'
  config :port, :validate => :number, :default => 6379
  config :db, :validate => :number, :default => 0
  config :password, :validate => :password
  config :timeout, :validate => :number, :default => 5
  config :reconnect_interval, :validate => :number, :default => 1
  # The name used to specify which field of event has IP value
  config :ip_field_name, :validate => :string, :default => 'message'
  # The name used to add a field into event to represent the reputation
  config :reputation_field_name, :validate => :string, :default => 'reputation'


  public
  def register
    require 'redis'
    @redis = nil
  end # def register

  public
  def filter(event)
    begin
      if event[@ip_field_name]
        @logger.info('In filter event now')
        # Multiple IP like "192.168.0.1, 192.168.0.2", will take first one
        ip = event[@ip_field_name].split(',')[0]
        @redis ||= connect
        reputation = @redis.hgetall(ip)
        event[@reputation_field_name] = reputation.to_json
        filter_matched(event)
      end
    rescue => e
      @logger.warn('Failed to get value from Redis', :event => event,
                    :exception => e,
                    :backtrace => e.backtrace)
      sleep @reconnect_interval
      @redis = nil
      retry
    end
  end # def filter

  private
  def connect
    params = {
        :host => @host,
        :port => @port,
        :db => @db,
        :password => @password.nil? ? nil : @password.value,
        :timeout => @timeout
    }
    @logger.debug(params)
    Redis.new(params)
  end # def connect

end # class LogStash::Filters::Ipreputation
