class NodeSecurityCrawler < CommonSecurity


  def self.logger
    if !defined?(@@log) || @@log.nil?
      @@log = Versioneye::DynLog.new("log/node_security.log", 10).log
    end
    @@log
  end


  def self.crawl
    meassure_exec{ perform_crawl }
  end


  def self.perform_crawl
    url = 'https://api.nodesecurity.io/advisories'
    index = JSON.parse HttpService.fetch_response(url).body
    index["results"].each do |sec_issue|
      parse_issue sec_issue
    end
  end


  def self.parse_issue sec_issue
    sv = fetch_sv_with sec_issue
    update_sv sv, sec_issue
    mark_affected_versions sv
  rescue => e
    self.logger.error "ERROR in parse_issue Message: #{e.message}"
    self.logger.error e.backtrace.join("\n")
  end


  def self.update_sv sv, sec_issue
    nodesec_id        = sec_issue['id']
    sv.source         = 'nodesecurity'
    sv.name_id        = "nodesecurity_#{nodesec_id}"
    sv.author         = sec_issue['author']
    sv.summary        = sec_issue['title']
    sv.description    = sec_issue['overview']
    sv.recommendation = sec_issue['recommendation']
    sv.cves           = sec_issue['cves']
    sv.cve            = sv.cves.first if !sv.cves.empty?
    sv.cvss_v2        = sec_issue['cvss_score']
    sv.cvss_vector    = sec_issue['cvss_vector']
    sv.publish_date   = sec_issue['publish_date']
    sv.affected_versions_string = sec_issue['vulnerable_versions']
    sv.patched_versions_string  = sec_issue['patched_versions']
    sv.save
  end


  def self.mark_affected_versions sv
    product = sv.product
    return nil if product.nil?

    affected = []
    affected_versions = VersionService.from_ranges( product.versions, sv.affected_versions_string.gsub("||", ",") )
    patched_versions  = VersionService.from_ranges( product.versions, sv.patched_versions_string.gsub("||", ",") )

    affected_versions.each do |version|
      next if patched_versions.to_a.map(&:to_s).include?(version.to_s)

      affected << version
    end

    mark_versions( sv, product, affected )
  end


  def self.fetch_sv_with sec_issue
    language    = Product::A_LANGUAGE_NODEJS
    prod_key    = sec_issue["module_name"]
    legacy_slug = sec_issue["legacy_slug"]
    sv = SecurityVulnerability.where(:language => language, :prod_key => prod_key, :name_id => legacy_slug ).first
    return sv if sv

    node_id = sec_issue["id"]
    name_id = "nodesecurity_#{node_id}"
    fetch_sv language, prod_key, name_id
  end


end
