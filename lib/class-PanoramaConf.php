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
 *  $pan = new PanoramaConf();
 *
 *  $pan->load_from_file('config.txt');
 *
 *  $pan->display_statistics();
 *
 * And there you go !
 *
 */
class PanoramaConf
{
	use PathableName;
	use centralTagStore;
	use centralZoneStore;
	use centralAppStore;
	use PanSubHelperTrait;


    /**
     * @var string[]|DomNode
     */
	public $xmlroot;

    /**
     * @var string[]|DomNode
     */
	public $sharedroot;
	public $devicesroot;
	public $localhostlocaldomain;
    /**
     * @var string[]|DomNode
     */
	public $devicegrouproot;


    public $version = null;

	protected $managedFirewallsSerials = Array();

    /**
     * @var DeviceGroup[]
     */
	public $deviceGroups = Array();

    /**
     * @var RuleStore
     */
	public $securityRules;

    /**
     * @var RuleStore
     */
	public $natRules;

    /**
     * @var RuleStore
     */
    public $decryptionRules=null;

    /**
     * @var AddressStore
     */
    public $addressStore=null;
    /**
     * @var ServiceStore
     */
    public $serviceStore=null;


    /**
     * @var PanAPIConnector|null
     */
	public $connector = null;
	
	public $name = '';

	public function name()
	{
		return $this->name;
	}
	
	public function PanoramaConf()
	{
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
		
		$this->serviceStore = new ServiceStore($this,true);
		$this->serviceStore->setCentralStoreRole(true);
		$this->serviceStore->name = 'services';
		
		$this->addressStore = new AddressStore($this,true);
		$this->addressStore->name = 'addresses';


		$this->securityRules = new RuleStore($this, 'SecurityRule', true);
		$this->natRules = new RuleStore($this, 'NatRule', true);
		$this->decryptionRules = new RuleStore($this, 'DecryptionRule', true);

		
	}


	public function load_from_xmlstring(&$xml)
	{
		$this->xmldoc = new DOMDocument();

		if( $this->xmldoc->loadXML($xml) !== TRUE )
			derr('Invalid XML file found');

		$this->load_from_domxml($this->xmldoc);
	}

	public function load_from_domxml($xml)
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


		$tmp = DH::findFirstElementOrCreate('mgt-config', $this->configroot);

		$tmp = DH::findFirstElementOrCreate('devices', $tmp);

		foreach( $tmp->childNodes as $serial )
		{
			if( $serial->nodeType != 1 )
				continue;
			$s = DH::findAttribute('name', $serial);
			if( $s === FALSE )
				derr('no serial found');

			$this->managedFirewallsSerials[] = $s;
		}

		$this->sharedroot = DH::findFirstElementOrDie('shared', $this->configroot);

		$this->devicesroot = DH::findFirstElementOrDie('devices', $this->configroot);

		$this->localhostroot = DH::findFirstElementByNameAttrOrDie('entry', 'localhost.localdomain',$this->devicesroot);

		$this->devicegrouproot = DH::findFirstElementOrDie('device-group', $this->localhostroot);

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

		$prerulebase = DH::findFirstElementOrCreate('pre-rulebase', $this->sharedroot);
		$postrulebase = DH::findFirstElementOrCreate('post-rulebase', $this->sharedroot);

		$tmp = DH::findFirstElementOrCreate('security', $prerulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->preSecurityRules->load_from_domxml($tmp);

		$tmp = DH::findFirstElementOrCreate('security', $postrulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->postSecurityRules->load_from_domxml($tmp);

		$tmp = DH::findFirstElementOrCreate('nat', $prerulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->preNatRules->load_from_domxml($tmp);

		$tmp = DH::findFirstElementOrCreate('nat', $postrulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->postNatRules->load_from_domxml($tmp);


        $tmp = DH::findFirstElementOrCreate('decryption', $prerulebase);
        $tmp = DH::findFirstElementOrCreate('rules', $tmp);
        $this->preDecryptionRules->load_from_domxml($tmp);

        $tmp = DH::findFirstElementOrCreate('nat', $postrulebase);
        $tmp = DH::findFirstElementOrCreate('rules', $tmp);
        $this->postDecryptionRules->load_from_domxml($tmp);


		// Now listing and extracting all DV configurations
		foreach( $this->devicegrouproot->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;
			$lvname = $node->nodeName;
			//print "Device Group '$lvname' found\n";
			
			$ldv = new DeviceGroup($this);
			$ldv->load_from_domxml($node);
			$this->deviceGroups[] = $ldv;
		}

	}


    /**
     * @param string $name
     * @return DeviceGroup|null
     */
	public function findDeviceGroup($name)
	{
		foreach($this->deviceGroups as $dg )
        {
			if( $dg->name() == $name )
				return $dg;
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

		$this->load_from_xmlstring($filecontents);

	}
	
	
	public function display_statistics()
	{

		$gpreSecRules = $this->preSecurityRules->count();
		$gpreNatRules = $this->preNatRules->count();
        $gpreDecryptRules = $this->preDecryptionRules->count();

		$gpostSecRules = $this->postSecurityRules->count();
		$gpostNatRules = $this->postNatRules->count();
        $gpostDecryptRules = $this->postDecryptionRules->count();

		$gnservices = $this->serviceStore->countServices();
		$gnservicesUnused = $this->serviceStore->countUnusedServices();
		$gnserviceGs = $this->serviceStore->countServiceGroups();
		$gnserviceGsUnused = $this->serviceStore->countUnusedServiceGroups();
		$gnTmpServices = $this->serviceStore->countTmpServices();

		$gnaddresss = $this->addressStore->countAddresses();
		$gnaddresssUnused = $this->addressStore->countUnusedAddresses();
		$gnaddressGs = $this->addressStore->countAddressGroups();
		$gnaddressGsUnused = $this->addressStore->countUnusedAddressGroups();
		$gnTmpAddresses = $this->addressStore->countTmpAddresses();

		foreach( $this->deviceGroups as $cur)
		{
			$gpreSecRules += $cur->preSecurityRules->count();
			$gpreNatRules += $cur->preNatRules->count();
            $gpreDecryptRules += $cur->preDecryptionRules->count();

			$gpostSecRules += $cur->postSecurityRules->count();
			$gpostNatRules += $cur->postNatRules->count();
            $gpostDecryptRules += $cur->postDecryptionRules->count();

			$gnservices += $vsys->serviceStore->countServices();
			$gnservicesUnused += $vsys->serviceStore->countUnusedServices();
			$gnserviceGs += $vsys->serviceStore->countServiceGroups();
			$gnserviceGsUnused += $vsys->serviceStore->countUnusedServiceGroups();
			$gnTmpServices += $vsys->serviceStore->countTmpServices();

			$gnaddresss += $vsys->addressStore->countAddresses();
			$gnaddresssUnused += $vsys->addressStore->countUnusedAddresses();
			$gnaddressGs += $vsys->addressStore->countAddressGroups();
			$gnaddressGsUnused += $vsys->addressStore->countUnusedAddressGroups();
			$gnTmpAddresses += $vsys->addressStore->countTmpAddresses();
		}
		
		print "Statistics for PanoramaConf '".$this->name."'\n";
		print "- ".$this->preSecurityRules->count()." (".$gpreSecRules.") pre-SecRules\n";
		print "- ".$this->postSecurityRules->count()." (".$gpostSecRules.") post-SecRules\n";

		print "- ".$this->preNatRules->count()." (".$gpreNatRules.") pre-NatRules\n";
		print "- ".$this->postNatRules->count()." (".$gpostNatRules.") post-NatRules\n";

        print "- ".$this->preDecryptionRules->count()." (".$gpreDecryptRules.") pre-NatRules\n";
        print "- ".$this->postDecryptionRules->count()." (".$gpostDecryptRules.") post-NatRules\n";

		print "- ".$this->addressStore->countAddresses()." (".$gnaddresss.") address objects. {$gnaddresssUnused} unused\n";

		print "- ".$this->addressStore->countAddressGroups()." (".$gnaddressGs.") address groups. {$gnaddressGsUnused} unused\n";

		print "- ".$this->serviceStore->countServices()." (".$gnservices.") service objects. {$gnservicesUnused} unused\n";

		print "- ".$this->serviceStore->countServiceGroups()." (".$gnserviceGs.") service groups. {$gnserviceGsUnused} unused\n";

		print "- ".$this->addressStore->countTmpAddresses()." (".$gnTmpAddresses.") temporary address objects\n";

		print "- ".$this->serviceStore->countTmpServices()." (".$gnTmpServices.") temporary service objects\n";
		
		print "- ".$this->zoneStore()->count()." zones\n";
		print "- ".$this->tagStore()->count()." tags\n";
	}

    public function API_load_from_running( PanAPIConnector $conn )
    {
        $this->connector = $conn;

		$xmlDoc = $this->connector->getRunningConfig();
		$this->load_from_domxml($xmlDoc);
    }

    public function API_load_from_candidate( PanAPIConnector $conn )
    {
        $this->connector = $conn;

		$xmlDoc = $this->connector->getCandidateConfig();
		$this->load_from_domxml($xmlDoc);
    }

	/**
	* send current config to the firewall and save under name $config_name
	*
	*/
	public function API_uploadConfig( $config_name = 'panconfigurator-default.xml' )
	{
		print "Uploadig config to device....";

		$url = "&type=import&category=configuration&category=configuration";

		$answer = &$this->connector->sendRequest($url, false, DH::dom_to_xml($this->xmlroot), $config_name );


		print "OK!\n";
	}

	/**
	*	load all managed firewalls configs from API from running config if $fromRunning = TRUE
	*/
	public function API_loadManagedFirewallConfigs($fromRunning)
	{
		$this->managedFirewalls = Array();

		derr('not implemented yet');
	}

	/**
	*	load all managed firewalls configs from a directory
	*/
	public function loadManagedFirewallsConfigs($fromDirectory = './')
	{
		$this->managedFirewalls = Array();

		$files = scandir($fromDirectory);

		foreach( $this->managedFirewallsSerials as &$serial )
		{
			$fw = FALSE;
			foreach( $files as &$file )
			{
				$pos = strpos($file, $serial);
				if( $pos !== FALSE )
				{
					//$fc = file_get_contents($file);
					//if( $fc === FALSE )
					//	derr("could not open file '$file'");

					print "Loading FW '$serial' from file '$file'.\n";

					$fw = new PANConf($this, $serial);
					$fw->load_from_file($fromDirectory.'/'.$file);
					$this->managedFirewalls[] = $fw;
					break;
				}

			}
			if( $fw === FALSE )
			{
				derr("couldn't find a suitable file to load for FW '$serial'");
			}
		}

		//derr('not implemented yet');
	}


    /**
     * @param string $deviceSerial
     * @param string $vsysName
     * @return DeviceGroup|bool
     */
	public function findApplicableDGForVsys($deviceSerial , $vsysName)
	{
		if( is_null($deviceSerial) || strlen($deviceSerial) < 1 )
			derr('invalid serial provided!');
		if( is_null($vsysName) || strlen($vsysName) < 1 )
			derr('invalid serial provided!');

		//print "looking for serial $deviceSerial  and vsys $vsysName\n";

		foreach( $this->deviceGroups as $dv )
		{
			$ds = $dv->getDevicesInGroup();
			foreach($ds as &$d)
			{
				if( $d['serial'] == $deviceSerial )
				{
					//print "serial found\n";
					if( array_search($vsysName, $d['vsyslist'])!== FALSE )
					{
						//print "match!\n";
						return $dv;
					}
				}
			}
		}

		return false;
	}

	/**
	* Create a blank device group. Return that DV object.
	**/
	public function createDeviceGroup($newDV_Name)
	{
		$newDG = new DeviceGroup($this);
		$newDG->load_from_templateXml();

		$newDG->setName($newDV_Name);

		return $newDG;

	}

    /**
     * @return DeviceGroup[]
     */
    public function getDeviceGroups()
    {
        return $this->deviceGroups;
    }

	public function isPanorama()
	{
		return true;
	}

}



