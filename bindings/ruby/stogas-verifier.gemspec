Gem::Specification.new do |s|
  s.name = 'stogas-verifier'
  s.version = '0.1.0.alpha.1'
  s.summary = 'Verified confidential HTTP transport backed by the Stogas Rust verifier.'
  s.authors = ['Stogas']
  s.license = 'Apache-2.0'
  s.homepage = 'https://github.com/StogasAI/verifier'
  s.required_ruby_version = '>= 3.3'
  s.platform = Gem::Platform.local
  s.files = Dir['lib/**/*', 'README.md']
  s.require_paths = ['lib']
  s.add_runtime_dependency 'fiddle', '>= 1.1', '< 2'
end
