Pod::Spec.new do |spec|
  spec.name         = 'Gdrill'
  spec.version      = '{{.Version}}'
  spec.license      = { :type => 'GNU Lesser General Public License, Version 3.0' }
  spec.homepage     = 'https://github.com/drillum-network/go-drillum'
  spec.authors      = { {{range .Contributors}}
		'{{.Name}}' => '{{.Email}}',{{end}}
	}
  spec.summary      = 'iOS Drillum Client'
  spec.source       = { :git => 'https://github.com/drillum-network/go-drillum.git', :commit => '{{.Commit}}' }

	spec.platform = :ios
  spec.ios.deployment_target  = '9.0'
	spec.ios.vendored_frameworks = 'Frameworks/Gdrill.framework'

	spec.prepare_command = <<-CMD
    curl https://gdrillstore.blob.core.windows.net/builds/{{.Archive}}.tar.gz | tar -xvz
    mkdir Frameworks
    mv {{.Archive}}/Gdrill.framework Frameworks
    rm -rf {{.Archive}}
  CMD
end
