class CommonSecurity


  def self.mark_versions sv, product, affected_versions
    # TODO use versioneye-core for this.
    # SecurityService.mark_versions sv, product, affected_versions
    return nil if sv.nil?
    return nil if product.nil?
    return nil if affected_versions.to_a.empty?

    affected_versions.each do |version|
      next if version.to_s.match(/\Adev\-/)

      if !sv.affected_versions.include?(version.to_s)
        sv.affected_versions.push(version.to_s)
        sv.save
      end

      product.reload
      product.add_svid version.to_s, sv
    end
  end


  def self.fetch_sv language, prod_key, name_id
    return nil if prod_key.to_s.empty? || name_id.to_s.empty?

    svs = SecurityVulnerability.by_language( language ).by_prod_key( prod_key )
    svs.each do |sv|
      next if sv.nil?

      return sv if sv.name_id.to_s.eql?(name_id)
    end

    self.logger.info "Create new SecurityVulnerability for #{language}:#{prod_key} - #{name_id}"
    SecurityVulnerability.new(:language => language, :prod_key => prod_key, :name_id => name_id )
  end


  def self.all_yaml_files(dir, &block)
    Dir.glob "#{dir}/**/*.{yml,yaml}" do |filepath|
      block.call filepath
    end
  end


  def self.meassure_exec(&block)
    start_time = Time.now
    block.call
    duration = Time.now - start_time
    minutes  = duration / 60
    str_time = DateTime.now.strftime("%Y.%m.%d %H:%M")
    self.logger.info("#{str_time}: This crawl took #{duration} seconds. Or #{minutes} minutes *** ")
  end


end
