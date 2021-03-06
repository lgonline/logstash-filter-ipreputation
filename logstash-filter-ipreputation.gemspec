Gem::Specification.new do |s|
  s.name = 'logstash-filter-ipreputation'
  s.version = '1.2.0'
  s.licenses = ['Apache License (2.0)']
  s.summary = 'A Logstash plugin used to get IP reputation value from a Redis service and enrich the Logstash event.'
  s.description = 'This gem is a logstash plugin required to be installed on top of the Logstash core pipeline using $LS_HOME/bin/plugin install gemname. This gem is not a stand-alone program'
  s.authors = ['lipengyu']
  s.email = 'lipengyux@gmail.com'
  s.homepage = 'https://github.com/ttys000/logstash-filter-ipreputation'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*', 'spec/**/*', 'vendor/**/*', '*.gemspec', '*.md', 'CONTRIBUTORS', 'Gemfile', 'LICENSE', 'NOTICE.TXT']
  # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = {'logstash_plugin' => 'true', 'logstash_group' => 'filter'}

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core', '>= 2.0.0', '< 3.0.0'
  s.add_development_dependency 'logstash-devutils', '~>0'

  s.add_runtime_dependency 'redis', '>=3.0.0', '<4.0.0'
end
