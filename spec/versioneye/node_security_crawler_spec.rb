require 'spec_helper'

describe NodeSecurityCrawler do

  describe 'crawl' do

    it "succeeds" do
      product = ProductFactory.create_for_npm 'jws', "1.0.0"
      expect( product.save ).to be_truthy
      product.versions.push( Version.new( { :version => "1.1.0" } ) )
      product.versions.push( Version.new( { :version => "2.0.0" } ) )
      product.versions.push( Version.new( { :version => "2.1.0" } ) )
      product.versions.push( Version.new( { :version => "3.0.0" } ) )
      product.versions.push( Version.new( { :version => "3.1.0" } ) )
      expect( product.save ).to be_truthy

      worker = Thread.new{ SecurityWorker.new.work }

      SecurityProducer.new("node_security")
      sleep 60

      worker.exit

      product = Product.fetch_product Product::A_LANGUAGE_NODEJS, 'jws'
      expect( product.version_by_number('1.1.0').sv_ids ).to_not be_empty
      expect( product.version_by_number('2.0.0').sv_ids ).to_not be_empty
      expect( product.version_by_number('2.1.0').sv_ids ).to_not be_empty
      expect( product.version_by_number('3.0.0').sv_ids ).to be_empty
      expect( product.version_by_number('3.1.0').sv_ids ).to be_empty
    end

  end

end
