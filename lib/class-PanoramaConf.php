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
	public $postSecurityRules;
    /**
     * @var RuleStore
     */
	public $preSecurityRules;

    /**
     * @var RuleStore
     */
	public $postNatRules;
    /**
     * @var RuleStore
     */
	public $preNatRules;
    /**
     * @var RuleStore
     */
    public $preDecryptionRules=null;
    /**
     * @var RuleStore
     */
    public $postDecryptionRules=null;

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
		
		
		$this->preNatRules = new RuleStore($this);
		$this->preNatRules->setStoreRole(true,"NatRule", true);
		
		$this->postNatRules = new RuleStore($this);
		$this->postNatRules->setStoreRole(true,"NatRule", false);
		
		$this->preSecurityRules = new RuleStore($this);
		$this->preSecurityRules->setStoreRole(true,"SecurityRule", true);
		
		$this->postSecurityRules = new RuleStore($this);
		$this->postSecurityRules->setStoreRole(true,"SecurityRule", false);

        $this->preDecryptionRules = new RuleStore($this);
        $this->preDecryptionRules->setStoreRole(true,"DecryptionRule", true);

        $this->postDecryptionRules= new RuleStore($this);
        $this->postDecryptionRules->setStoreRole(true,"DecryptionRule", false);
		
	}

	public function load_from_xml(&$xml)
	{
		$xmlobj = new XmlArray();
		$xmlarr = $xmlobj->load_string($xml);

		return $this->load_from_xmlarr($xmlarr);
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
		

		$tmp = &searchForName('name', 'mgt-config', $xmlArray['children']);
		if( is_null($tmp) )
			derr("Error: <mgt-config> not found\n");

		$tmp = &searchForName('name', 'devices', $tmp['children']);
		if( is_null($tmp) )
			derr("Error: <devices> not found\n");

        if( isset($tmp['children']) )
        {
            foreach ($tmp['children'] as &$serial)
                $this->managedFirewallsSerials[] = $serial['attributes']['name'];
        }


		$this->sharedroot = &searchForName('name', 'shared', $xmlArray['children']);
		
		if( is_null($this->sharedroot) )
			derr("Error: <shared ...> not found\n");


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

		
		$this->devicesroot = &searchForName('name', 'devices', $xmlArray['children']);
		
		if( is_null($this->devicesroot) )
			derr("Error: <devices ...> not found\n");
		
		// Now look for entry name="localhost.localdomain"
		$this->localhostlocaldomain = &searchForNameAndAttribute('name', 'entry', 'name', 'localhost.localdomain', $this->devicesroot['children']);
				
		if( is_null($this->localhostlocaldomain) )
			derr("Error: <entry name=\"localhost.localdomain\" ...> not found\n");
		
		
		// Look for <device-group> 
		$this->devicegrouproot = &searchForName('name', 'device-group', $this->localhostlocaldomain['children']);
		
		if( is_null($this->devicegrouproot ) )
			derr("Error: <device-group> not found\n");
		
		
		
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
			$this->addressGsroot = Array( 'name' => 'address-group', 'children' => Array() );
			$this->sharedroot['children'][] = &$this->addressGsroot ;
		}
		if( !isset($this->addressGsroot['children']) )
		{
			$this->addressGsroot['children'] = Array();
		}
		$this->addressStore->load_addressgroups_from_xml($this->addressGsroot);
		// End of address groups extraction
		
		
		
		//							//
		// Extract service objects 				//
		//							//
		$this->servicesroot = &searchForName('name', 'service', $this->sharedroot['children']);
		if( is_null($this->servicesroot) )
		{
			$this->servicesroot = Array( 'name' => 'service' );
			$this->sharedroot['children'][] = &$this->servicesroot;
			
		}
		if( !isset($this->servicesroot['children']) )
		{
			$this->servicesroot['children'] = Array();
		}
		$this->serviceStore->load_services_from_xml($this->servicesroot);
		//print "found ".count($this->services)." service objects\n";
		// End of <service> extraction
		
		
		
		//							//
		// Extract service groups 				//
		//							//
		$this->serviceGsroot = &searchForName('name', 'service-group', $this->sharedroot['children']);
		if( is_null($this->serviceGsroot) )
		{
			$this->serviceGsroot = Array( 'name' => 'service-group' );
			$this->sharedroot['children'][] = &$this->serviceGsroot;
		}
		if( !isset($this->serviceGsroot['children']) )
		{
				$this->serviceGsroot['children'] = Array();
		}
		
		$this->serviceStore->load_servicegroups_from_xml($this->serviceGsroot);
		//print "found ".count($this->serviceGs)." service groups\n";
		// End of <service-group> extraction
		
		
		
		$preRulebase = &searchForName('name', 'pre-rulebase', $this->sharedroot['children']);
		if( is_null($preRulebase) )
		{
			$preRulebase = Array('name'=>'pre-rulebase', 'children'=>Array());
			$this->sharedroot['children'][] = &$preRulebase;
		}
		
		$postRulebase = &searchForName('name', 'post-rulebase', $this->sharedroot['children']);
		if( is_null($postRulebase) )
		{
			$postRulebase =  Array( 'name' => 'post-rulebase', 'children' => Array());
			$this->sharedroot['children'][] = &$postRulebase;
		}

        if( !isset($preRulebase['children']) ) $preRulebase['children'] = Array();
        if( !isset($postRulebase['children']) ) $postRulebase['children'] = Array();


        //							//
        // Extract preNAT rules objects in this 		//
        //							//
        $nat = &searchForName('name', 'nat', $preRulebase['children']);
        if( is_null($nat) )
        {
            $nat = Array('name'=>'nat' , 'children'=>Array());
            $preRulebase['children'][] = &$nat;
        }

        $this->prenatrulesroot = &searchForName('name', 'rules', $nat['children']);
        if( is_null($this->prenatrulesroot) )
        {
            $this->prenatrulesroot = Array('name'=>'rules');
            $nat['children'][] = &$this->prenatrulesroot;
        }
        if( !isset($this->prenatrulesroot['children']) )
        {
            $this->prenatrulesroot['children'] = Array();
        }

        $c = count($this->prenatrulesroot['children']);

        //print "found $c pre-nat rules\n";
        $this->preNatRules->load_from_xml($this->prenatrulesroot);
        //
        // End of preNAT Rules extractions
        //



        //					                        		//
        // Extract preDecrypt rules objects in this 		//
        //			                        				//
        $decrypt = &searchForName('name', 'decryption', $preRulebase['children']);
        if( is_null($decrypt) )
        {
            $decrypt = Array('name'=>'decryption' , 'children'=>Array());
            $preRulebase['children'][] = &$decrypt;
        }

        $decryptRulesRoot = &searchForName('name', 'rules', $decrypt['children']);
        if( is_null($decryptRulesRoot) )
        {
            $decryptRulesRoot = Array('name'=>'rules');
            $decrypt['children'][] = &$decryptRulesRoot;
        }
        if( !isset($decryptRulesRoot['children']) )
        {
            $decryptRulesRoot['children'] = Array();
        }

        $this->preDecryptionRules->load_from_xml($decryptRulesRoot);
        //
        // End of preDecrypt Rules extractions
        //



        //							//
        // Extract pre security rules objects in this VSYS		//
        //							//
        $security = &searchForName('name', 'security', $preRulebase['children']);
        if( is_null($security) )
        {
            $security = Array('name'=>'security' , 'children'=>Array());
            $preRulebase['children'][] = &$security;
        }


        $this->presecrulesroot = &searchForName('name', 'rules', $security['children']);
        if( is_null($this->presecrulesroot) )
        {
            $this->presecrulesroot = Array('name'=>'rules');
            $security['children'][] = &$this->presecrulesroot;
        }
        if( !isset($this->presecrulesroot['children']) )
        {
            $this->presecrulesroot['children'] = Array();
        }

        //$c = count($this->presecrulesroot['children']);

        //print "found $c pre-security rules\n";
        $this->preSecurityRules->load_from_xml($this->presecrulesroot);
        //extractSecRulesFromXML($this->preSecurityRules, $this->presecrulesroot['children'], $this);
        // End of pre Security Rules extractions




        //							//
        // Extract postNAT rules objects in this VSYS		//
        //							//
        $nat = &searchForName('name', 'nat', $postRulebase['children']);
        if( is_null($nat) )
        {
            $nat = Array('name'=>'nat' , 'children'=>Array());
            $postRulebase['children'][] = &$nat;
        }

        $this->postnatrulesroot = &searchForName('name', 'rules', $nat['children']);
        if( is_null($this->postnatrulesroot) )
        {
            $this->postnatrulesroot = Array('name'=>'rules');
            $nat['children'][] = &$this->postnatrulesroot;
        }
        if( !isset($this->postnatrulesroot['children']) )
        {
            $this->postnatrulesroot['children'] = Array();
        }

        $c = count($this->postnatrulesroot['children']);

        //print "found $c post-nat rules\n";

        $this->postNatRules->load_from_xml($this->postnatrulesroot);
        //print "found post nat rules = ".$this->postNatRules->count()."\n";
        // End of post NAT Rules extractions




        //					                        		//
        // Extract postDecrypt rules objects in this 		//
        //			                        				//
        $decrypt = &searchForName('name', 'decryption', $postRulebase['children']);
        if( is_null($decrypt) )
        {
            $decrypt = Array('name'=>'decryption' , 'children'=>Array());
            $postRulebase['children'][] = &$decrypt;
        }

        $decryptRulesRoot = &searchForName('name', 'rules', $decrypt['children']);
        if( is_null($decryptRulesRoot) )
        {
            $decryptRulesRoot = Array('name'=>'rules');
            $decrypt['children'][] = &$decryptRulesRoot;
        }
        if( !isset($decryptRulesRoot['children']) )
        {
            $decryptRulesRoot['children'] = Array();
        }

        $this->postDecryptionRules->load_from_xml($decryptRulesRoot);
        //
        // End of postDecrypt Rules extractions
        //



        //							//
        // Extract pre security rules objects in this VSYS		//
        //							//
        $security = &searchForName('name', 'security', $postRulebase['children']);
        if( is_null($security) )
        {
            $security = Array('name'=>'security' , 'children'=>Array());
            $postRulebase['children'][] = &$security;
        }


        $postSecRulesRoot = &searchForName('name', 'rules', $security['children']);
        if( is_null($postSecRulesRoot) )
        {
            $postSecRulesRoot = Array('name'=>'rules');
            $security['children'][] = &$postSecRulesRoot;
        }
        if( !isset($postSecRulesRoot['children']) )
        {
            $postSecRulesRoot['children'] = Array();
        }
        $this->postSecurityRules->load_from_xml($postSecRulesRoot);
        // End of pre Security Rules extractions





		
		// Now listing and extracting all DeviceGroup configurations
        // TODO replace with foreach()
		$cur = &$this->devicegrouproot['children'];
		$c = count($cur);
		$k = array_keys($cur);
		
		for( $i=0; $i<$c; $i++ )
		{
			$lvname = $cur[$k[$i]]['attributes']['name'];
			//print "Device Group '$lvname' found\n";
			
			$ldv = new DeviceGroup($this);
			$ldv->load_from_xml($cur[$k[$i]],$this);
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

		if( PH::$UseDomXML === TRUE )
			$this->load_from_xmlstring($filecontents);
		else
			$this->load_from_xml($filecontents);
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
		$gnserviceGs = $this->serviceStore->countServiceGroups();
		$gnTmpServices = $this->serviceStore->countTmpServices();
		
		$gnaddresss = $this->addressStore->countAddresses();
		$gnaddressGs = $this->addressStore->countAddressGroups();
		$gnTmpAddresses = $this->addressStore->countTmpAddresses();

		foreach( $this->deviceGroups as $cur)
		{
			$gpreSecRules += $cur->preSecurityRules->count();
			$gpreNatRules += $cur->preNatRules->count();
            $gpreDecryptRules += $cur->preDecryptionRules->count();

			$gpostSecRules += $cur->postSecurityRules->count();
			$gpostNatRules += $cur->postNatRules->count();
            $gpostDecryptRules += $cur->postDecryptionRules->count();

			$gnservices += $cur->serviceStore->countServices();
			$gnserviceGs += $cur->serviceStore->countServiceGroups();
			$gnTmpServices += $cur->serviceStore->countTmpServices();
			
			$gnaddresss += $cur->addressStore->countAddresses();
			$gnaddressGs += $cur->addressStore->countAddressGroups();
			$gnTmpAddresses += $cur->addressStore->countTmpAddresses();
		}
		
		print "Statistics for PanoramaConf '".$this->name."'\n";
		print "- ".$this->preSecurityRules->count()." (".$gpreSecRules.") pre-SecRules\n";
		print "- ".$this->postSecurityRules->count()." (".$gpostSecRules.") post-SecRules\n";

		print "- ".$this->preNatRules->count()." (".$gpreNatRules.") pre-NatRules\n";
		print "- ".$this->postNatRules->count()." (".$gpostNatRules.") post-NatRules\n";

        print "- ".$this->preDecryptionRules->count()." (".$gpreDecryptRules.") pre-NatRules\n";
        print "- ".$this->postDecryptionRules->count()." (".$gpostDecryptRules.") post-NatRules\n";
		
		print "- ".$this->addressStore->countAddresses()." (".$gnaddresss.") address objects\n";
		
		print "- ".$this->addressStore->countAddressGroups()." (".$gnaddressGs.") address groups\n";
		
		print "- ".$this->serviceStore->countServices()." (".$gnservices.") service objects\n";
		
		print "- ".$this->serviceStore->countServiceGroups()." (".$gnserviceGs.") service groups\n";
		
		print "- ".$this->addressStore->countTmpAddresses()." (".$gnTmpAddresses.") temporary address objects\n";
		
		print "- ".$this->serviceStore->countTmpServices()." (".$gnTmpServices.") temporary service objects\n";
		
		print "- ".$this->zoneStore()->count()." zones\n";
		print "- ".$this->tagStore()->count()." tags\n";
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
            $xmlarr = $this->connector->getCandidateConfig();
            $this->load_from_xmlarr($xmlarr);
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

}



