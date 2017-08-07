class RetirejsSecurityCrawler < CommonSecurity


  def self.logger
    if !defined?(@@log) || @@log.nil?
      @@log = Versioneye::DynLog.new("log/retirejs_security.log", 10).log
    end
    @@log
  end


  def self.crawl
    meassure_exec{ perform_crawl }
  end


  def self.perform_crawl
    url = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository.json'
    index = JSON.parse HttpService.fetch_response(url).body
    index.keys.each do |key|
      svs = index[key]
      parse_svs key, svs
    end
  end


  def self.parse_svs package_name, svs
    return nil if package_name.to_s.eql?('retire-example')
    return nil if svs.to_a.empty?
    return nil if svs['vulnerabilities'].to_a.empty?

    svs['vulnerabilities'].each do |sec_issue|
      next if sec_issue['identifiers'].nil? || sec_issue['identifiers'].empty?

      sv = fetch_sv_with package_name, sec_issue
      if sv.nil?
        self.logger.error "sv is nil for #{package_name}"
      end

      update_sv package_name, sv, sec_issue
      # mark_affected_versions sv
    end
  rescue => e
    self.logger.error "ERROR in parse_package Message: #{e.message}"
    self.logger.error e.backtrace.join("\n")
  end


  def self.get_id_for package_name, sec_issue
    cves = sec_issue['identifiers']['CVE']
    if !cves.to_a.empty?
      return cves.first
    end

    osvdbs = sec_issue['identifiers']['osvdb']
    if !osvdbs.to_a.empty?
      return osvdbs.first
    end

    issue = sec_issue['identifiers']['issue']
    if !issue.to_s.empty?
      return "issue_#{issue}_#{package_name}"
    end

    bug = sec_issue['identifiers']['bug']
    if !bug.to_s.empty?
      return "bug_#{bug}_#{package_name}"
    end

    summary = sec_issue['identifiers']['summary']
    if !summary.to_s.empty?
      return "#{package_name}-#{summary}"
        .gsub("$sanitize", package_name)
        .gsub(" ", "_")
        .gsub("/", "_")
        .gsub(".", "_")
        .gsub("(", "")
        .gsub(")", "")
    end

    nil
  end


  def self.get_affected_range_for sec_issue
    below = sec_issue['below']
    atOrAbove = sec_issue['atOrAbove']
    if !below.to_s.empty? && atOrAbove.to_s.empty?
      return "< #{below}"
    end
    if below.to_s.empty? && !atOrAbove.to_s.empty?
      return ">= #{atOrAbove}"
    end
    ">= #{atOrAbove}, < #{below}"
  end


  def self.update_sv package_name, sv, sec_issue
    sv.source         = 'Retire.js'
    sv.prod_type      = Project::A_TYPE_BOWER
    sv.language = 'JavaScript'
    sv.prod_key = package_name
    product = Product.fetch_bower package_name
    if product
      sv.language = product.language
      sv.prod_key = product.prod_key
    end
    sv.summary        = sec_issue['identifiers']['summary']
    sv.summary        = sv.name_id if sv.summary.to_s.empty?

    cves = sec_issue['identifiers']['CVE']
    if !cves.to_a.empty?
      sv.cve = cves.first
      cves.each do |cve|
        sv.cves << cve if !sv.cves.include?(cve)
      end
    end

    osvdbs = sec_issue['identifiers']['osvdb']
    if !osvdbs.to_a.empty?
      sv.osvdb = osvdbs.first
    end

    sv.severity       = sec_issue['identifiers']['severity']
    sv.cves           = sec_issue['identifiers']['CVE']
    sv.cwes           = sec_issue['identifiers']['CWE']
    sv.nsp            = sec_issue['identifiers']['NSP']
    sv.publish_date   = sec_issue['publish_date']

    affected_version_string = get_affected_range_for sec_issue
    if !sv.affected_versions_string.to_s.match(/#{affected_version_string}/i)
      if sv.affected_versions_string.to_s.empty?
        sv.affected_versions_string = affected_version_string
      else
        sv.affected_versions_string = "#{sv.affected_versions_string} || #{affected_version_string}"
      end
    end

    if !sec_issue['info'].to_a.empty?
      count = 1
      sec_issue['info'].each do |link|
        sv.links["link#{count}"] = link if !sv.links.values.include?(link)
        count += 1
      end
    end

    sv.save
  end


  def self.fetch_sv_with package_name, sec_issue
    name_id = get_id_for package_name, sec_issue
    return nil if name_id.to_s.empty?

    sv = SecurityVulnerability.where(:prod_type => Project::A_TYPE_BOWER, :package_name => package_name, :name_id => name_id ).first
    return sv if sv

    SecurityVulnerability.new( :prod_type => Project::A_TYPE_BOWER, :package_name => package_name, :name_id => name_id )
  end


end
