class NvdSecurityCrawler < CommonSecurity


  require './lib/versioneye/constants/nvd_mapping'


  def self.logger
    if !defined?(@@log) || @@log.nil?
      @@log = Versioneye::DynLog.new("log/nvd_security.log", 10).log
    end
    @@log
  end


  def self.crawl
    meassure_exec{ perform_crawl }
  end


  def self.perform_crawl
    year = 2002
    while year.to_i <= DateTime.now.year do
      `rm /tmp/nvdcve-2.0-#{year}.xml.zip`
      `rm /tmp/nvdcve-2.0-#{year}.xml`
      `wget -O /tmp/nvdcve-2.0-#{year}.xml.zip https://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-#{year}.xml.zip`
      `unzip /tmp/nvdcve-2.0-#{year}.xml.zip -d /tmp`

      parse_xml "/tmp/nvdcve-2.0-#{year}.xml"

      p year
      year += 1
    end
  end


  def self.parse_xml file_path
    entries = fetch_entries file_path
    self.logger.info "#{entries.count} entries for #{file_path}"

    entries.each do |entry|
      map = process_entry( entry )
      next if map[:products].nil?

      map[:products].keys.each do |vendor_product|
        next if !NvdMapping::A_MAPPING.keys.include? vendor_product.to_s

        create_or_update_svs( map, vendor_product )
      end
    end
  rescue => e
    self.logger.error "ERROR in parse_xml Message: #{e.message}"
    self.logger.error e.backtrace.join("\n")
  end


  def self.fetch_entries file_path
    content = File.read( file_path )
    contnet = content.gsub("\n", "").gsub("\t", "").gsub("  ", "")

    doc = Nokogiri.XML( content )
    doc.remove_namespaces!

    doc.xpath("//entry")
  end


  def self.process_entry entry
    entry_map = {}
    entry.children.each do |child|
      next if child.name.eql?('text')

      entry_map[:cve]       = child.text  if child.name.eql?('cve-id')
      entry_map[:summary]   = child.text  if child.name.eql?('summary')
      entry_map[:published] = child.text  if child.name.eql?('published-datetime')
      entry_map[:modified]  = child.text  if child.name.eql?('last-modified-datetime')
      entry_map[:cwe]       = child['id'] if child.name.eql?('cwe')

      parse_links entry_map, child
      parse_score entry_map, child
      parse_product entry_map, child
    end
    entry_map
  end


  def self.parse_product entry_map, child
    return nil if !child.name.eql?('vulnerable-software-list')

    entry_map[:vendors] = []
    entry_map[:products] = {}
    child.children.each do |product|
      next if product.name.eql?('text')

      sps    = product.text.split(":")
      vendor = sps[2]
      prod   = sps[3]
      vp     = "#{vendor}:#{prod}"

      entry_map[:vendors].push vendor
      entry_map[:products][vp] = [] if entry_map[:products][vp].nil?
      entry_map[:products][vp].push product.text
    end
  end


  def self.parse_links entry_map, child
    return nil if !child.name.eql?('references')

    entry_map[:links] = []
    child.children.each do |ref|
      next if ref.name.eql?('text')

      entry_map[:links].push ref['href'] if ref.name.eql?('reference')
    end
  end


  def self.parse_score entry_map, child
    return nil if !child.name.eql?('cvss')

    child.children.each do |cvss|
      next if cvss.name.eql?('text')

      if cvss.name.eql?("base_metrics")
        cvss.children.each do |metrics|
          next if cvss.name.eql?('text')

          if metrics.name.eql?('score')
            entry_map[:cvss] = metrics.text
          end
        end
      end
    end
  end


  def self.create_or_update_svs( map, vendor_product )
    msg = " --- MATCH for #{vendor_product} --- "
    p msg
    self.logger.info msg

    mapping = NvdMapping::A_MAPPING[vendor_product]
    proecess_maven_keys map, vendor_product, mapping
    proecess_nuget_keys map, vendor_product, mapping
  end


  def self.proecess_maven_keys map, vendor_product, mapping
    language = Product::A_LANGUAGE_JAVA
    prod_keys = mapping['Maven']
    prod_keys.each do |pk|
      prod_key = pk.gsub(":", "/")
      process_cpe( language, prod_key, map )
    end
  rescue => e
    self.logger.error "ERROR in proecess_maven_keys with message: #{e.message}"
    self.logger.error e.backtrace.join("\n")
  end


  def self.proecess_nuget_keys map, vendor_product, mapping
    language = Product::A_LANGUAGE_CSHARP
    prod_keys = mapping['Nuget']
    prod_keys.each do |prod_key|
      process_cpe( language, prod_key, map, vendor_product )
    end
  rescue => e
    self.logger.error "ERROR in proecess_nuget_keys with message: #{e.message}"
    self.logger.error e.backtrace.join("\n")
  end


  def self.process_cpe language, prod_key, map, vendor_product
    cve = map[:cve]
    sv = SecurityVulnerability.where(:language => language, :prod_key => prod_key, :cve => cve).first
    if sv
      self.logger.info "-- #{cve} exist already from #{sv.source} --"
      return nil
    end

    sv = SecurityVulnerability.new({:language => language, :prod_key => prod_key, :source => "NVD"})
    sv.description = map[:summary]
    sv.summary = cve
    sv.name_id = cve
    sv.cve     = cve
    sv.cves.push cve if !sv.cves.include?(cve)

    sv.cwe = map[:cwe]
    sv.cwes.push map[:cwe] if !sv.cwes.include?(map[:cwe])

    sv.cvss_v2 = map[:cvss]

    sv.publish_date = map[:published]
    sv.modified     = map[:modified]

    map[:links].each do |href|
      lkey = href.gsub(".", "::")
      sv.links[lkey] = href
    end

    product = sv.product
    map[:products][vendor_product].each do |cpe|
      sps = cpe.split(":")
      version = sps[4]
      sv.affected_versions.push version
      if product
        product.add_svid version.to_s, sv
      end
    end
    sv.affected_versions_string = sv.affected_versions.join(', ')
    saved = sv.save

    self.logger.info "#{sv.cve} for #{language} : #{prod_key} saved: #{saved}"
  rescue => e
    self.logger.error "ERROR in process_cpe with message: #{e.message}"
    self.logger.error e.backtrace.join("\n")
  end


end
