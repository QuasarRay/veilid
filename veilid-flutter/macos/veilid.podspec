#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint veilid.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'veilid'
  s.version          = '0.0.1'
  s.summary          = 'Veilid Network'
  s.description      = <<-DESC
Veilid Network Plugin
                       DESC
  s.homepage         = 'http://veilid.com'
  s.license          = 'LGPL-2.0-or-later OR MPL-2.0 OR (MIT AND BSD-3-Clause)'
  s.author           = { 'John Smith' => 'jsmith@example.com' }
  s.source           = { :path => '.' }
  s.source_files     = 'veilid-flutter/Sources/veilid/**/*'
  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.15.0'
  s.osx.deployment_target = '10.15.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'

  # Rust is compiled by the Dart build hook (hook/build.dart) and delivered as a
  # native-assets framework. No cargo build here.
end
