require 'tomlrb'
require 'spec_helper'

describe RustSecurityCrawler do
  let(:test_content){
    File.read 'spec/fixtures/files/rustsec.toml'
  }

  let(:product1){
    Product.new(
      prod_type: Project::A_TYPE_NUGET,
      language: Product::A_LANGUAGE_RUST,
      prod_key: 'hyper',
      name: 'hyper',
      version: '0.10.4'
    )
  }

  let(:product2){
    Product.new(
      prod_type: Project::A_TYPE_NUGET,
      language: Product::A_LANGUAGE_RUST,
      prod_key: 'sodiumoxide',
      name: 'sodiumoxide',
      version: '0.10.4'
    )
  }


  context "remove_versions_by_label" do
    before do
      product1.versions << Version.new(version: '0.6.1')
      product1.versions << Version.new(version: '0.7.2')
      product1.versions << Version.new(version: '0.8.3')
      product1.versions << Version.new(version: '0.10.4')
      product1.save
    end

    after do
      SecurityVulnerability.delete_all
    end

    it "returns correct version for >= 0.7.2" do
      affected = RustSecurityCrawler.remove_versions_by_label(
        product1.versions, '>= 0.7.2'
      )

      expect( affected.size ).to eq(1)
      expect(affected[0]).to eq('0.6.1')
    end

    it "returns correct version for > 0.6.2" do
      affected = RustSecurityCrawler.remove_versions_by_label(
        product1.versions, '> 0.6.2'
      )

      expect( affected.size ).to eq(1)
      expect(affected[0]).to eq('0.6.1')
    end

    it "returns correct versions for >= 0.7.2, < 0.10.0" do
      affected = RustSecurityCrawler.remove_versions_by_label(
        product1.versions, '>= 0.7.2, < 0.10.0'
      )

      expect( affected.size ).to eq(2)
      expect(affected[0]).to eq('0.6.1')
      expect(affected[1]).to eq('0.10.4')
    end

    it "returns correct version for combined range" do
      affected = RustSecurityCrawler.remove_versions_by_label(
        product1.versions, '> 0.7.2 || > 0.8.0 || > 0.9.0'
      )

      expect( affected.size ).to eq(1)
      expect(affected[0]).to eq('0.6.1')
    end
  end

  context "process_advisory" do
    before do
      product2.versions << Version.new(version: '0.0.5')
      product2.versions << Version.new(version: '0.0.15')
      product2.save
    end

    after do
      SecurityVulnerability.delete_all
    end

    it "saves correctly advisory from test file" do
      vuln_doc = Tomlrb.parse(test_content, symbolize_keys: true)
      expect(vuln_doc[:advisory].size).to eq(1)
      expect(SecurityVulnerability.all.size).to eq(0)

      advisory = vuln_doc[:advisory].first
      RustSecurityCrawler.process_advisory(advisory)

      expect(SecurityVulnerability.all.size).to eq(1)
      vuln_db = SecurityVulnerability.all[0]
      expect(vuln_db[:language]).to eq(product2[:language])
      expect(vuln_db[:prod_key]).to eq(product2[:prod_key])
      expect(vuln_db[:name_id]).to eq(advisory[:id])
      expect(vuln_db[:summary]).to eq(advisory[:title])
      expect(vuln_db[:publish_date]).to eq(advisory[:date])
      expect(vuln_db[:source]).to eq('rustsec')
      expect(vuln_db[:links]).to eq({"details" => advisory[:url] })

      #tricky part
      version_lbl = advisory[:patched_versions].to_a.join(' || ')
      expect(vuln_db[:unaffected_versions_string]).to eq(version_lbl)
      expect(vuln_db[:affected_versions_string]).to eq("!( #{version_lbl} )")
      expect(vuln_db[:affected_versions]).to eq(['0.0.5'])

    end
  end
end
