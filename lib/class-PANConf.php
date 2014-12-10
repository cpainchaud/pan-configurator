<?php


/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

/**
 * Your journey will start from PANConf or PanoramaConf
 *
 * Code:
 *
 *  $pan = new PANConf();
 *
 *  $pan->load_from_file('config.txt');
 *
 *  $vsys1 = $pan->findVirtualSystem('vsys1');
 *
 *  $vsys1->display_statistics();
 *
 * And there you go !
 *
 */
class PANConf
{
	
	use PathableName;
	use centralTagStore;
	use centralAppStore;

	public $xmlroot;
	
	public $sharedroot;
	public $devicesroot;
	public $localhostlocaldomain;
	public $vsyssroot;

    /**
     * @var AddressStore
     */
    public $addressStore=null;
    /**
     * @var ServiceStore
     */
    public $serviceStore=null;

    public $version = null;

    /**
     * @var VirtualSystem[]
     */
	public $virtualSystems = Array();

    /**
     * @var PanAPIConnector|null
     */
	public $connector = null;


    /**
     * @var null|IPsecTunnelStore
     */
    public $ipsecTunnels = null;


	public function name()
	{
		return $this->name;
	}
	
	/**
	 * @param PanoramaConf|null $withPanorama
	 */
	public function PANConf($withPanorama = null, $serial = null)
	{
		if( !is_null($withPanorama) )
			$this->panorama = $withPanorama;
		if( !is_null($serial) )
			$this->serial = $serial;

		$this->tagStore = new TagStore($this);
		$this->tagStore->setName('tagStore');
		$this->tagStore->setCentralStoreRole(true);
		
		$this->zoneStore = new ZoneStore($this);
		$this->zoneStore->setName('zoneStore');
		$this->zoneStore->setCentralStoreRole(true);
		
		$this->appStore = new AppStore($this);
		$this->appStore->setName('appStore');
		$this->appStore->setCentralStoreRole(true);
		$this->appStore->load_from_predefinedfile();

        $this->ipsecTunnels = new IPsecTunnelStore('ipsecTunnels', $this);
		
		$this->serviceStore = new ServiceStore($this,true);
		$this->serviceStore->name = 'services';
		if( !is_null($withPanorama) )
			$this->serviceStore->panoramaShared = $this->panorama->serviceStore;


		$this->addressStore = new AddressStore($this,true);
		$this->addressStore->name = 'addresses';
		if( !is_null($withPanorama) )
			$this->addressStore->panoramaShared = $this->panorama->addressStore;

		
	}

	public function load_from_xml(&$xml)
	{
		$xmlobj = new XmlArray();
		$xmlarr = $xmlobj->load_string($xml);

		return $this->load_from_xmlarr($xmlarr);
	}

	public function load_from_xmlstring(&$xml)
	{
		$xmlDoc = new DOMDocument();

        if( PH::$UseDomXML )
        {
            if ($xmlDoc->loadXML($xml, LIBXML_PARSEHUGE) !== TRUE)
                derr('Invalid XML file found');

            $this->load_from_domxml($xmlDoc);
        }
        else
            derr('unsupported');
	}

	public function load_from_domxml(DOMDocument $xml)
	{

		$this->xmldoc = $xml;


        $this->configroot = DH::findFirstElementOrDie('config', $this->xmldoc);
        $this->xmlroot = $this->configroot;


        $versionAttr = DH::findAttribute('version', $this->configroot);
        if( $versionAttr !== false )
        {
            $this->version = PH::versionFromString($versionAttr);
        }
        else
        {
            if( isset($this->connector) && $this->connector !== null )
                $version = $this->connector->getSoftwareVersion();
            else
                derr('cannot find PANOS version used for make this config');

            $this->version = $version['version'];
        }


		$this->sharedroot = DH::findFirstElementOrDie('shared', $this->configroot);

		$this->devicesroot = DH::findFirstElementOrDie('devices', $this->configroot);

		$this->localhostroot = DH::findFirstElementByNameAttrOrDie('entry', 'localhost.localdomain',$this->devicesroot);

		$this->vsyssroot = DH::findFirstElementOrDie('vsys', $this->localhostroot);

        $this->networkroot = DH::findFirstElementOrCreate('network', $this->localhostroot );


        //
        // Extract ipsec tunnels
        //
        $tmp = DH::findFirstElementOrCreate('tunnel', $this->networkroot);
        $tmp = DH::findFirstElementOrCreate('ipsec', $tmp);
        $this->ipsecTunnels->load_from_domxml($tmp);
        // End of ipsec tunnels



        //
        // Extract Tag objects
        //
        if( $this->version >= 60 )
        {
            $tmp = DH::findFirstElementOrCreate('tag', $this->sharedroot);
            $this->tagStore->load_from_domxml($tmp);
        }
        // End of Tag objects extraction


		//
		// Shared address objects extraction
		//
		$tmp = DH::findFirstElementOrCreate('address', $this->sharedroot);
		$this->addressStore->load_addresses_from_domxml($tmp);
		// end of address extraction

		//
		// Extract address groups 
		//
		$tmp = DH::findFirstElementOrCreate('address-group', $this->sharedroot);
		$this->addressStore->load_addressgroups_from_domxml($tmp);
		// End of address groups extraction

		//
		// Extract services
		//
		$tmp = DH::findFirstElementOrCreate('service', $this->sharedroot);
		$this->serviceStore->load_services_from_domxml($tmp);
		// End of address groups extraction

		//
		// Extract service groups 
		//
		$tmp = DH::findFirstElementOrCreate('service-group', $this->sharedroot);
		$this->serviceStore->load_servicegroups_from_domxml($tmp);
		// End of address groups extraction

		
		
		// Now listing and extracting all VirtualSystem configurations
		foreach( $this->vsyssroot->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;
			//print "DOM type: ".$node->nodeType."\n";
			$lvsys = new VirtualSystem($this);

			$lvname = DH::findAttribute('name', $node);

			if( $lvname === FALSE )
				derr('cannot finc VirtualSystem name');

			if( isset($this->panorama) )
			{
				$dg = $this->panorama->findApplicableDGForVsys($this->serial , $lvname);
				if( $dg !== FALSE )
				{
					$lvsys->addressStore->panoramaDG = $dg->addressStore;
					$lvsys->serviceStore->panoramaDG = $dg->serviceStore;
				}
			}

			$lvsys->load_from_domxml($node);
			$this->virtualSystems[] = $lvsys;
		}


	}

	public function load_from_xmlarr(&$xmlArray)
	{		
		$this->xmlroot = &$xmlArray;

		
		if( $xmlArray['name'] != 'config' )
			derr("Error: <config ...> not found\n");

        if( isset( $xmlArray['attributes']['version']) )
        {
            $this->version = PH::versionFromString($xmlArray['attributes']['version']);
        }
        else
        {
            if( isset($this->connector) && $this->connector !== null )
                $version = $this->connector->getSoftwareVersion();
            else
                derr('cannot find PANOS version used for make this config');

            $this->version = $version['version'];
        }

        //print "PANOS version is ".$this->version."\n";
		
		$this->sharedroot = &searchForName('name', 'shared', $xmlArray['children']);
		
		if( is_null($this->sharedroot) )
			derr("Error: <shared ...> not found\n");
		
		$this->devicesroot = &searchForName('name', 'devices', $xmlArray['children']);
		
		if( is_null($this->devicesroot) )
			derr("Error: <devices ...> not found\n");
		
		// Now look for entry name="localhost.localdomain"
		$this->localhostlocaldomain = &searchForNameAndAttribute('name', 'entry', 'name', 'localhost.localdomain', $this->devicesroot['children']);
				
		if( is_null($this->localhostlocaldomain) )
			derr("Error: <entry name=\"localhost.localdomain\" ...> not found\n");
		
		
		// Look for <VSYS> 
		$this->vsyssroot = &searchForName('name', 'vsys', $this->localhostlocaldomain['children']);
		
		if( is_null($this->vsyssroot ) )
			derr("Error: <vsys> not found\n");


        //
        // Extract Tags objects
        //
        if( $this->version >= 60 )
        {
            $tagRoot = &searchForName('name', 'tag', $this->sharedroot['children']);
            if (is_null($tagRoot))
            {
                // no object section, lets create one
                $tagRoot = Array('name' => 'tag');
                $this->sharedroot['children'][] = &$tagRoot;
            }
            if (!isset($tagRoot['children']))
            {
                $tagRoot['children'] = Array();
            }
            $this->tagStore->load_from_xml($tagRoot);
        }
        // end of Tags extraction
		
		//
		// Shared address objects extraction
		//
		$this->addressroot = &searchForName('name', 'address', $this->sharedroot['children'] );
		if( is_null($this->addressroot) )
		{
			$this->addressroot = Array( 'name' => 'address' );
			$this->sharedroot['children'][] = &$this->addressroot ;
		}
		if( !isset($this->addressroot['children']) )
		{
			$this->addressroot['children'] = Array();
		}
		$this->addressStore->load_addresses_from_xml($this->addressroot);
		// end of address extraction
		
		
		
		//
		// Extract address groups 
		//
		$this->addressGsroot = &searchForName('name', 'address-group', $this->sharedroot['children'] );
		if( is_null($this->addressGsroot) )
		{
			// no object group section, lets create one
			$this->addressGsroot = Array( 'name' => 'address-group' );
			$this->sharedroot['children'][] = &$this->addressGsroot ;
		}
		if( !isset($this->addressGsroot['children']) )
		{
			$this->addressGsroot['children'] = Array();
		}
		$this->addressStore->load_addressgroups_from_xml($this->addressGsroot);
		// End of address groups extraction
		
		
		// Now listing and extracting all VSYS configurations
        // TODO replace with foreach()
		$cur = &$this->vsyssroot['children'];
		$c = count($cur);
		$k = array_keys($cur);
		
		for( $i=0; $i<$c; $i++ )
		{
			$lvname = $cur[$i]['attributes']['name'];
			//print "VSYS '$lvname' found\n";
			
			$lvsys = new VirtualSystem($this);
			if( isset($this->panorama) )
			{
				$dg = $this->panorama->findApplicableDGForVsys($this->serial , $lvname);
				if( $dg !== FALSE )
				{
					$lvsys->addressStore->panoramaDG = $dg->addressStore;
					$lvsys->serviceStore->panoramaDG = $dg->serviceStore;
				}
			}


			$lvsys->load_from_xml($cur[$k[$i]]);
			$this->virtualSystems[] = $lvsys;
		}
		
		
				
	}

    /**
     * !!OBSOLETE!!
     *
     * @param string $name
     * @return VirtualSystem|null
     */
	public function findVSYS_by_Name($name)
	{
        mwarning('use of obsolete function, please use findVirtualSystem() instead!');
		return $this->findVirtualSystem($name);
	}

    /**
     * @param string $name
     * @return VirtualSystem|null
     */
    public function findVirtualSystem($name)
    {
        foreach( $this->virtualSystems as $vsys )
        {
            if( $vsys->name() == $name )
            {
                return $vsys;
            }
        }

        return null;
    }
	
	public function save_to_file($filename)
	{
		print "Now saving PANConf to file '$filename'...";
		if( PH::$UseDomXML === TRUE )
		{
			$xml = &DH::dom_to_xml($this->xmlroot);
			file_put_contents ( $filename , $xml);	
		}
		else
		{
			$xml = &array_to_xml($this->xmlroot);
			file_put_contents ( $filename , $xml);	
		}
		print "     done!\n\n";
	}
	
	public function load_from_file($filename)
	{
		$filecontents = file_get_contents($filename);

		if( PH::$UseDomXML === TRUE )
			$this->load_from_xmlstring($filecontents);
		else
			$this->load_from_xml($filecontents);
	}

	public function API_load_from_running( PanAPIConnector $conn )
	{
		$this->connector = $conn;


        if( PH::$UseDomXML === TRUE )
        {
            $xmlDoc = $this->connector->getRunningConfig();
            $this->load_from_domxml($xmlDoc);
        }
        else
        {
            $xmlarr = $this->connector->getRunningConfig();
            $this->load_from_xmlarr($xmlarr);
        }
	}

	public function API_load_from_candidate( PanAPIConnector $conn )
	{
		$this->connector = $conn;

        if( PH::$UseDomXML === TRUE )
        {
            $xmlDoc = $this->connector->getCandidateConfig();
            $this->load_from_domxml($xmlDoc);
        }
        else
        {
            $xmlArray = $this->connector->getCandidateConfig();
            $this->load_from_xmlarr($xmlArray);
        }
	}

	/**
	* send current config to the firewall and save under name $config_name
	*
	*/
	public function API_uploadConfig( $config_name = 'panconfigurator-default.xml' )
	{

		print "Uploadig config to device....";

		$url = "&type=import&category=configuration&category=configuration";

        if( PH::$UseDomXML )
            $answer = &$this->connector->sendRequest($url, false, DH::dom_to_xml($this->xmlroot), $config_name );
        else
		    $answer = &$this->connector->sendRequest($url, false, array_to_xml($this->xmlroot), $config_name );

		print "OK!\n";

	}

    /**
     * @return VirtualSystem[]
     */
    public function getVirtualSystems()
    {
        return $this->virtualSystems;
    }
}

