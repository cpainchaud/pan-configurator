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


class DeviceGroup 
{
	
	use PathableName;
	use PanSubHelperTrait;

    /**
     * @var PanoramaConf
     */
	public $owner = null;

	/**
	 * @var DOMElement
	 */
	public $xmlroot;
	
	//public $addressroot;
	//public $addressGsroot;
	//public $servicesroot = null;
	//public $serviceGsroot = null;

	
	//public $prenatrulesroot=null;
	//public $presecrulesroot=null;
	//public $postnatrulesroot=null;
	//public $postsecrulesroot=null;

    /**
     * @var AddressStore
     */
    public $addressStore=null;
    /**
     * @var ServiceStore
     */
    public $serviceStore=null;

	public static $templatexml = '<entry name="**Need a Name**"><address></address><post-rulebase><security><rules></rules></security><nat><rules></rules></nat></post-rulebase>
									<pre-rulebase><security><rules></rules></security><nat><rules></rules></nat></pre-rulebase>
									</entry>';

	
	/**
	* @var TagStore
	*/
	public $tagStore=null;
	/**
	* @var ZoneStore
	*/
	public $zoneStore=null;
	/**
	* @var RuleStore
	*/
	public $preSecurityRules=null;
	/**
	* @var RuleStore
	*/
	public $postSecurityRules=null;
	/**
	* @var RuleStore
	*/
	public $preNatRules=null;
	/**
	* @var RuleStore
	*/
	public $postNatRules=null;
    /**
     * @var RuleStore
     */
    public $preDecryptionRules=null;
    /**
     * @var RuleStore
     */
    public $postDecryptionRules=null;


	/**
	* @var Array
	*/
	private $devices = Array();

	
	
	public function DeviceGroup($owner)
	{
		$this->owner = $owner;
        $this->version = &$owner->version;

		$this->device = Array();
		
		$this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';
        $this->tagStore->setCentralStoreRole(true);

		$this->zoneStore = $owner->zoneStore;
		$this->appStore = $owner->appStore;
		
		$this->serviceStore = new ServiceStore($this,true);
		$this->serviceStore->name = 'services';
		
		$this->addressStore = new AddressStore($this,true);
		$this->addressStore->name = 'addresss';
		
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

	public function load_from_templateXml()
	{
		if( $this->owner === null )
			derr('cannot be used if owner === null');

		$fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

		if( ! $fragment->appendXML(self::$templatexml) )
			derr('error occured while loading device group template xml');

		$element = $this->owner->devicegrouproot->appendChild($fragment);

		$this->load_from_domxml($element);
	}
	
	
	/**
	* !! Should not be used outside of a PanoramaConf constructor. !!
	*
	*/
	public function load_from_xml( array &$xml)
	{
		$this->xmlroot = &$xml;


        if( !isset($this->version) )
        {
            if( !isset($this->owner->version) || $this->owner->version === null  )
                derr('cannot find PANOS version from parent object');

            $this->version = $this->owner->version;
        }
		
		// this DV has a name ?
		$this->name = $xml['attributes']['name'];
		if( is_null($this->name) )
			derr("Error: DV name not found\n");
		
		//print "Device Group'".$this->name."' found\n";

        //
        // Extract Tags objects
        //
        if( $this->owner->version >= 60 )
        {
            $tagRoot = &searchForName('name', 'tag', $xml['children']);
            if (is_null($tagRoot))
            {
                // no object section, lets create one
                $tagRoot = Array('name' => 'tag');
                $xml['children'][] = &$tagRoot;
            }
            if (!isset($tagRoot['children']))
            {
                $tagRoot['children'] = Array();
            }
            $this->tagStore->load_from_xml($tagRoot);
        }
        // end of Tags extraction
		
		
		//
		// Extract address objects 
		//
		$this->addressroot = &searchForName('name', 'address', $xml['children']);
		if( is_null($this->addressroot) )
		{
			// no object section, lets create one
			$this->addressroot = Array( 'name' => 'address' );
			$xml['children'][] = &$this->addressroot ;
		}
		if( !isset($this->addressroot['children']) ) 
		{
			$this->addressroot['children'] = Array();
		}
		
		$this->addressStore->load_addresses_from_xml($this->addressroot);
		// End of address objects extraction
		
		
		
		//
		// Extract address groups in this DV
		//
		$this->addressGsroot = &searchForName('name', 'address-group', $xml['children']);
		if( is_null($this->addressGsroot) )
		{
			// no object group section, lets create one
			$this->addressGsroot = Array( 'name' => 'address-group' );
			$xml['children'][] = &$this->addressGsroot ;
		}
		if( !isset($this->addressGsroot['children']) )
		{
			$this->addressGsroot['children'] = Array();
		}
		
		$this->addressStore->load_addressgroups_from_xml($this->addressGsroot);
		//print_r($this->addressGsroot);
		// End of address groups extraction
		
		
		
		//							//
		// Extract service objects 				//
		//							//
		$this->servicesroot = &searchForName('name', 'service', $xml['children']);
		if( is_null($this->servicesroot) )
		{
			$this->servicesroot = Array( 'name' => 'service' );
			$xml['children'][] = &$this->servicesroot;
			
		}
		if( !isset($this->servicesroot['children']) )
		{
			$this->servicesroot['children'] = Array();
		}

		$this->serviceStore->load_services_from_xml($this->servicesroot);
		//print "found ".count($this->services)." service objects\n";
		// End of <service> extraction
		
		
		
		//							//
		// Extract service groups	 			//
		//							//
		$this->serviceGsroot = &searchForName('name', 'service-group', $xml['children']);
		if( is_null($this->serviceGsroot) )
		{
			$this->serviceGsroot = Array( 'name' => 'service-group' );
			$this->xmlroot['children'][] = &$this->serviceGsroot;
		}
		if( !isset($this->serviceGsroot['children']) )
		{
			$this->serviceGsroot['children'] = Array();
		}
	
		$this->serviceStore->load_servicegroups_from_xml($this->serviceGsroot);
		//print "found ".count($this->serviceGs)." service groups\n";
		// End of <service-group> extraction
		
		
		
		$preRulebase = &searchForName('name', 'pre-rulebase', $xml['children']);
		if( is_null($preRulebase) )
		{
			$preRulebase = Array('name'=>'pre-rulebase', 'children'=>Array());
			$xml['children'][] = &$preRulebase;
		}
		
		$postRulebase = &searchForName('name', 'post-rulebase', $xml['children']);
		if( is_null($postRulebase) )
		{
			$postRulebase = Array('name'=>'post-rulebase', 'children'=>Array());
			$xml['children'][] = &$postRulebase;
		}
		
		
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
		// Extract pre security rules objects in this VirtualSystem		//
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
		// Extract postNAT rules objects in this VirtualSystem		//
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
		// Extract pre security rules objects in this VirtualSystem		//
		//							//
		$security = &searchForName('name', 'security', $postRulebase['children']);
		if( is_null($security) )
		{
			$security = Array('name'=>'security' , 'children'=>Array());
			$postRulebase['children'][] = &$security;
		}
		
		
		$this->postsecrulesroot = &searchForName('name', 'rules', $security['children']);
		if( is_null($this->postsecrulesroot) )
		{
			$this->postsecrulesroot = Array('name'=>'rules');
			$security['children'][] = &$this->postsecrulesroot;
		}
		if( !isset($this->postsecrulesroot['children']) )
		{
			$this->postsecrulesroot['children'] = Array();
		}
		
		$c = count($this->postsecrulesroot['children']);
		
		//print "found $c post-security rules\n";
		
		$this->postSecurityRules->load_from_xml($this->postsecrulesroot);
		// End of pre Security Rules extractions


		// Devices extraction
		$this->devicesRoot = &searchForName('name', 'devices', $this->xmlroot['children']);
		if( is_null($this->devicesRoot) )
		{
			//print "no devices found in DV".$this->name."\n";
			$this->devicesRoot = Array('name'=>'devices');
			$this->xmlroot['children'][] = &$this->devicesRoot;
		}
		if( !isset($this->devicesRoot['children']) )
		{
			$this->devicesRoot['children'] = Array();
		}

		foreach( $this->devicesRoot['children'] as &$device )
		{
			//print "Device in DV ".$this->name.": ".$device['attributes']['name']."\n";
			$devname = $device['attributes']['name'];
			$vsyslist = Array();

			if( isset($device['children']) && count($device['children']) > 0 )
			{
				foreach( $device['children'][0]['children'] as &$vsysentry)
				{
					$vname = &$vsysentry['attributes']['name'];
					//print "found vsys '$vname'\n";
					$vsyslist[] = $vname;
				}
			}
			else
			{
				//print "No vsys for device '$devname'\n";
				$vsyslist[] = 'vsys1';
			}

			$this->devices[] = Array('serial' => $devname, 'vsyslist' => $vsyslist );
		}
		//print_r($this->device);
		//end of devices extraction
		
		
		
	}



	/**
	* !! Should not be used outside of a PanoramaConf constructor. !!
	*
	*/
	public function load_from_domxml( $xml)
	{
		$this->xmlroot = $xml;
		
		// this VirtualSystem has a name ?
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("VirtualSystem name not found\n");

        //
        // Extract Tag objects
        //
        if( $this->owner->version >= 60 )
        {
            $tmp = DH::findFirstElementOrCreate('tag', $xml);
            $this->tagStore->load_from_domxml($tmp);
        }
        // End of Tag objects extraction


		//
		// Extract address objects 
		//
		$tmp = DH::findFirstElementOrCreate('address', $xml);
		$this->addressStore->load_addresses_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' address objectsloaded\n" ;
		// End of address objects extraction
		
		
		//
		// Extract address groups in this DV
		//
		$tmp = DH::findFirstElementOrCreate('address-group', $xml);
		$this->addressStore->load_addressgroups_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' address groups loaded\n" ;
		// End of address groups extraction
		
		
		
		//												//
		// Extract service objects in this VirtualSystem			//
		//												//
		$tmp = DH::findFirstElementOrCreate('service', $xml);
		$this->serviceStore->load_services_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' service objects\n" ;
		// End of <service> extraction
		
		
		
		//												//
		// Extract service groups in this VirtualSystem			//
		//												//
		$tmp = DH::findFirstElementOrCreate('service-group', $xml);
		$this->serviceStore->load_servicegroups_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' service groups loaded\n" ;
		// End of <service-group> extraction
		
		
		
		$prerulebase = DH::findFirstElementOrCreate('pre-rulebase', $xml);
		$postrulebase = DH::findFirstElementOrCreate('post-rulebase', $xml);

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


		// Devices extraction
		$this->devicesRoot = DH::findFirstElementOrCreate('devices', $xml);

		foreach( $this->devicesRoot->childNodes as $device )
		{
			if( $device->nodeType != 1 ) continue;
			$devname = DH::findAttribute('name', $device);
			$vsyslist = Array();

			$vsysChild = DH::firstChildElement($device);

			if( $vsysChild !== FALSE )
			{
				foreach( $vsysChild->childNodes as $vsysentry)
				{
					if( $vsysentry->nodeType != 1) continue;
					$vname = DH::findAttribute('name', $vsysentry);
					$vsyslist[] = $vname;
				}
			}
			else
			{
				//print "No vsys for device '$devname'\n";
				$vsyslist[] = 'vsys1';
			}

			$this->devices[] = Array('serial' => $devname, 'vsyslist' => $vsyslist );
		}
	}

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$this->name."']";

        return $str;
    }



	public function getDevicesInGroup()
	{
		return $this->devices;
	}
	
	public function name()
	{
		return $this->name;
	}

	public function setName($newName)
	{
		if( PH::$UseDomXML )
			$this->xmlroot->setAttribute('name', $newName);
		else
			$this->xmlroot['attributes']['name'] = $newName;

		$this->name = $newName;
	}

	public function isDeviceGroup()
	{
		return true;
	}
	
	
	
}


