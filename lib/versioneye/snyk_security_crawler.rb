class SnykSecurityCrawler < NodeSecurityCrawler


  def self.logger
    if !defined?(@@log) || @@log.nil?
      @@log = Versioneye::DynLog.new("log/snyk_security.log", 10).log
    end
    @@log
  end


  def self.crawl
    meassure_exec{ perform_crawl }
  end


  def self.perform_crawl
    url = 'https://raw.githubusercontent.com/Snyk/vulndb/snapshots/master/snapshot.json'
    index = JSON.parse HttpService.fetch_response(url).body
    index["npm"].keys.each do |key|
      svs = index["npm"][key]
      parse_svs key, svs
    end
  end


  def self.parse_svs package_name, svs
    return nil if svs.to_a.empty?

    svs.each do |sec_issue|
      sv = fetch_sv_with sec_issue
      update_sv sv, sec_issue
      mark_affected_versions sv
    end
  rescue => e
    self.logger.error "ERROR in parse_package Message: #{e.message}"
    self.logger.error e.backtrace.join("\n")
  end


  def self.update_sv sv, sec_issue
    sv.source         = 'snyk'
    sv.summary        = sec_issue['title']
    sv.description    = sec_issue['description']
    sv.author         = sec_issue['credit'].to_a.join(", ")
    sv.cvss_v3        = sec_issue['CVSSv3']
    sv.severity       = sec_issue['severity']
    sv.cve            = sec_issue['identifiers']['CVE'].first
    sv.cves           = sec_issue['identifiers']['CVE']
    sv.cwes           = sec_issue['identifiers']['CWE']
    sv.nsp            = sec_issue['identifiers']['NSP']
    sv.publish_date   = sec_issue['publish_date']
    sv.affected_versions_string = sec_issue['semver']['vulnerable']
    sv.patched_versions_string  = sec_issue['semver']['unaffected']
    sv.publish_date  = sec_issue['disclosureTime']
    sv.save
  end


  def self.fetch_sv_with sec_issue, language = Product::A_LANGUAGE_NODEJS
    prod_key = sec_issue["moduleName"]
    name_id  = sec_issue["id"]
    sv = SecurityVulnerability.where(:language => language, :prod_key => prod_key, :name_id => name_id ).first
    return sv if sv

    SecurityVulnerability.new(:language => language, :prod_key => prod_key, :name_id => name_id )
  end


end
