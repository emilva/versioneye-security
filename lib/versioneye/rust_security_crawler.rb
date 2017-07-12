require 'tomlrb'

class RustSecurityCrawler < CommonSecurity

  A_ADVISORY_URL = 'https://raw.githubusercontent.com/RustSec/advisory-db/master/Advisories.toml'


  def self.logger
    if !defined?(@@log) || @@log.nil?
      @@log = Versioneye::DynLog.new("log/rust_security.log", 10).log
    end
    @@log
  end


  def self.crawl
    logger.info "Going to crawl Rust security advisories"
    res = HTTParty.get A_ADVISORY_URL
    return if res.nil? or res.code != 200

    vuln_doc = Tomlrb.parse(res.body, symbolize_keys: true)
    vuln_doc[:advisory].to_a.each {|a| process_advisory(a) }

    logger.info "Done!"
  rescue => e
    logger.error "Failed to crawl Rust advisories. #{e.message}"
    logger.error e.backtrace.join('\n')
  end


  def self.process_advisory(advisory, update_existing = false)
    vuln = SecurityVulnerability.where(
      language: Product::A_LANGUAGE_RUST,
      prod_key: advisory[:package],
      name_id: advisory[:id]
    ).first

    if vuln and update_existing == false
      logger.info "Vulnerability #{advisory[:id]} already exists - going to skip"
      return
    end

    vuln = init_vulnerability(advisory) if vuln.nil?
    product = Product.where(
      language: vuln[:language],
      prod_key: vuln[:prod_key]
    ).first

    process_versions(product, vuln, advisory[:patched_versions])

    unless vuln.save
      logger.error "Failed to save a advisory: #{advisory}"
      logger.error "reason: #{vuln.errors.full_messages.to_sentence}"
      return
    end

    vuln
  end


  def self.process_versions(product, vuln, patched_versions)
    if product.nil?
      logger.error "No product for #{vuln.to_json} - skipping processing versions"
      return
    end

    patched_releases = patched_versions.to_a.join(' || ')
    vuln.affected_versions = fetch_affected_versions( product, patched_releases, vuln )
    vuln
  end


  # patched_releases - unaffected versions separated by ||
  def self.fetch_affected_versions( product, patched_releases, vuln = nil )
    versions = product.versions
    return [] if versions.nil? || versions.empty?

    safe_versions = []
    v_ranges = VersionService.from_ranges(versions.to_a, patched_releases)
    v_ranges.to_a.each do |version_db|
      next if version_db.version.to_s.empty?
      next if safe_versions.include?(version_db.version)

      safe_versions << version_db.version
    end

    # remove all unaffected versions from product version list
    vulnerable = []
    versions.to_a.each do |version|
      next if safe_versions.include? version.version

      vulnerable << version.version
    end
    mark_versions( vuln, product, vulnerable )
    vulnerable
  end


  def self.init_vulnerability(advisory)
    unaffected_txt = advisory[:patched_versions].to_a.join(' || ')

    SecurityVulnerability.new(
      language: Product::A_LANGUAGE_RUST,
      prod_key: advisory[:package],
      name_id: advisory[:id],
      summary: advisory[:title],
      description: advisory[:description],
      publish_date: advisory[:date],
      source: 'rustsec',
      patched_versions_string: unaffected_txt,
      unaffected_versions_string: unaffected_txt,
      affected_versions_string: "!( #{unaffected_txt} )",
      links: {"details" => advisory[:url] },
      approved: true # that file includes only accepted CVEs
    )
  end

end
